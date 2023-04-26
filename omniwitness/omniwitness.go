// Copyright 2022 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package omniwitness provides a single Main file that runs the omniwitness.
// Some components are left pluggable so this can be deployed on different
// runtimes.
package omniwitness

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/internal/config"
	ihttp "github.com/transparency-dev/witness/internal/http"
	"github.com/transparency-dev/witness/internal/persistence"
	"github.com/transparency-dev/witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	dist_gh "github.com/transparency-dev/witness/internal/distribute/github"
	"github.com/transparency-dev/witness/internal/feeder"
	"github.com/transparency-dev/witness/internal/feeder/pixelbt"
	"github.com/transparency-dev/witness/internal/feeder/rekor"
	"github.com/transparency-dev/witness/internal/feeder/serverless"
	"github.com/transparency-dev/witness/internal/feeder/sumdb"
	"github.com/transparency-dev/witness/internal/github"
	i_note "github.com/transparency-dev/witness/internal/note"
)

// LogStatePersistence describes functionality the omniwitness requires
// in order to persist its view of log state.
type LogStatePersistence = persistence.LogStatePersistence

// LogStateReadOps provides read-only operations on the stored state for
// a given log.
type LogStateReadOps = persistence.LogStateReadOps

// LogStateWriteOps provides write operations on the stored state for
// a given log.
type LogStateWriteOps = persistence.LogStateWriteOps

const (
	// Interval between attempts to feed checkpoints
	// TODO(mhutchinson): Make this configurable
	feedInterval       = 5 * time.Minute
	distributeInterval = 5 * time.Minute
)

// OperatorConfig allows the bare minimum operator-specific configuration.
// This should only contain configuration details that are custom per-operator.
type OperatorConfig struct {
	WitnessSigner   note.Signer
	WitnessVerifier note.Verifier

	GithubUser  string
	GithubEmail string
	GithubToken string
}

// logFeeder is the de-facto interface that feeders implement.
type logFeeder func(context.Context, config.Log, feeder.Witness, *http.Client, time.Duration) error

// Main runs the omniwitness, with the witness listening using the listener, and all
// outbound HTTP calls using the client provided.
func Main(ctx context.Context, operatorConfig OperatorConfig, p LogStatePersistence, httpListener net.Listener, httpClient *http.Client) error {
	// This error group will be used to run all top level processes.
	// If any process dies, then all of them will be stopped via context cancellation.
	g, ctx := errgroup.WithContext(ctx)

	feeders := make(map[config.Log]logFeeder)

	logCfg := LogConfig{}
	if err := yaml.Unmarshal(ConfigLogs, &logCfg); err != nil {
		return fmt.Errorf("failed to unmarshal witness config: %v", err)
	}

	for _, l := range logCfg.Logs {
		// TODO(mhutchinson): deprecate config.Log as it's a subset of LogInfo.
		lc := config.Log{
			ID:            log.ID(l.Origin, []byte(l.PublicKey)),
			Origin:        l.Origin,
			URL:           l.URL,
			PublicKey:     l.PublicKey,
			PublicKeyType: l.PublicKeyType,
		}
		feeders[lc] = l.Feeder.FeedFunc()
	}

	knownLogs, err := logCfg.AsLogMap()
	if err != nil {
		return fmt.Errorf("failed to convert witness config to map: %v", err)
	}
	witness, err := witness.New(witness.Opts{
		Persistence: p,
		Signer:      operatorConfig.WitnessSigner,
		KnownLogs:   knownLogs,
	})
	if err != nil {
		return fmt.Errorf("failed to create witness: %v", err)
	}

	bw := witnessAdapter{
		w: witness,
	}
	for c, f := range feeders {
		c, f := c, f
		// Continually feed this log in its own goroutine, hooked up to the global waitgroup.
		g.Go(func() error {
			glog.Infof("Feeder %q goroutine started", c.Origin)
			defer glog.Infof("Feeder %q goroutine done", c.Origin)
			return f(ctx, c, bw, httpClient, feedInterval)
		})
	}

	if operatorConfig.GithubUser != "" {
		var distLogs = []dist_gh.Log{}
		for config := range feeders {
			// TODO(mhutchinson): This verifier could be created inside the distributor.
			logSigV, err := i_note.NewVerifier(config.PublicKeyType, config.PublicKey)
			if err != nil {
				return err
			}
			distLogs = append(distLogs, dist_gh.Log{
				Config: config,
				SigV:   logSigV,
			})
		}

		runDistributors(ctx, httpClient, g, distLogs, bw, operatorConfig)
	} else {
		glog.Info("No GitHub user specified; skipping deployment of distributors")
	}

	r := mux.NewRouter()
	s := ihttp.NewServer(witness)
	s.RegisterHandlers(r)
	srv := http.Server{
		Handler: r,
	}
	g.Go(func() error {
		glog.Info("HTTP server goroutine started")
		defer glog.Info("HTTP server goroutine done")
		return srv.Serve(httpListener)
	})
	g.Go(func() error {
		// This goroutine brings down the HTTP server when ctx is done.
		glog.Info("HTTP server-shutdown goroutine started")
		defer glog.Info("HTTP server-shutdown goroutine done")
		<-ctx.Done()
		return srv.Shutdown(ctx)
	})

	return g.Wait()
}

func runDistributors(ctx context.Context, c *http.Client, g *errgroup.Group, logs []dist_gh.Log, witness dist_gh.Witness, operatorConfig OperatorConfig) {
	distribute := func(opts *dist_gh.DistributeOptions) error {
		if err := dist_gh.DistributeOnce(ctx, opts); err != nil {
			glog.Errorf("DistributeOnce: %v", err)
		}
		for {
			select {
			case <-time.After(distributeInterval):
			case <-ctx.Done():
				return ctx.Err()
			}
			if err := dist_gh.DistributeOnce(ctx, opts); err != nil {
				glog.Errorf("DistributeOnce: %v", err)
			}
		}
	}

	createOpts := func(upstreamOwner, repoName, mainBranch, distributorPath string) (*dist_gh.DistributeOptions, error) {
		dr := github.RepoID{
			Owner:    upstreamOwner,
			RepoName: repoName,
		}
		fork := github.RepoID{
			Owner:    operatorConfig.GithubUser,
			RepoName: repoName,
		}
		repo, err := github.NewRepository(ctx, c, dr, mainBranch, fork, operatorConfig.GithubUser, operatorConfig.GithubEmail, operatorConfig.GithubToken)
		if err != nil {
			return nil, fmt.Errorf("NewRepository: %v", err)
		}
		return &dist_gh.DistributeOptions{
			Repo:            repo,
			DistributorPath: distributorPath,
			Logs:            logs,
			WitSigV:         operatorConfig.WitnessVerifier,
			Witness:         witness,
		}, nil
	}

	g.Go(func() error {
		opts, err := createOpts("mhutchinson", "mhutchinson-distributor", "main", "distributor")
		if err != nil {
			return fmt.Errorf("createOpts(mhutchinson): %v", err)
		}
		glog.Infof("Distributor %q goroutine started", opts.Repo)
		defer glog.Infof("Distributor %q goroutine done", opts.Repo)
		return distribute(opts)
	})

	g.Go(func() error {
		opts, err := createOpts("WolseyBankWitness", "rediffusion", "main", ".")
		if err != nil {
			return fmt.Errorf("createOpts(WolseyBankWitness): %v", err)
		}
		glog.Infof("Distributor %q goroutine started", opts.Repo)
		defer glog.Infof("Distributor %q goroutine done", opts.Repo)
		return distribute(opts)
	})
}

// Feeder is an enum of the known feeder types.
type Feeder uint8

const (
	Serverless Feeder = iota + 1
	SumDB
	Pixel
	Rekor
)

var (
	feederByName = map[string]Feeder{
		"serverless": Serverless,
		"sumdb":      SumDB,
		"pixel":      Pixel,
		"rekor":      Rekor,
	}
)

// UnmarshalYAML populates the log from yaml using the unmarshal func provided.
func (f *Feeder) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	if *f, err = ParseFeeder(raw); err != nil {
		return err
	}
	return nil
}

func (f Feeder) FeedFunc() logFeeder {
	switch f {
	case Serverless:
		return serverless.FeedLog
	case SumDB:
		return sumdb.FeedLog
	case Pixel:
		return pixelbt.FeedLog
	case Rekor:
		return rekor.FeedLog
	}
	panic(fmt.Sprintf("unknown feeder enum: %q", f))
}

// ParseFeeder takes a string and returns a valid enum or an error.
func ParseFeeder(f string) (Feeder, error) {
	f = strings.TrimSpace(strings.ToLower(f))
	value, ok := feederByName[f]
	if !ok {
		return Feeder(0), fmt.Errorf("uknown feeder type %q", f)
	}
	return value, nil
}

// witnessAdapter binds the internal witness implementation to the feeder interface.
// TODO(mhutchinson): Can we fix the difference between the API on the client and impl
// so they both have the same contract?
type witnessAdapter struct {
	w *witness.Witness
}

func (w witnessAdapter) GetLatestCheckpoint(ctx context.Context, logID string) ([]byte, error) {
	cp, err := w.w.GetCheckpoint(logID)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, os.ErrNotExist
		}
	}
	return cp, err
}

func (w witnessAdapter) Update(ctx context.Context, logID string, newCP []byte, proof [][]byte) ([]byte, error) {
	return w.w.Update(ctx, logID, newCP, proof)
}
