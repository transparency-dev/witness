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
	"crypto/ed25519"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/transparency-dev/witness/internal/config"
	ihttp "github.com/transparency-dev/witness/internal/http"
	"github.com/transparency-dev/witness/internal/persistence"
	"github.com/transparency-dev/witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"

	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/internal/distribute/rest"
	"github.com/transparency-dev/witness/internal/feeder"
	"github.com/transparency-dev/witness/internal/feeder/bastion"
	"github.com/transparency-dev/witness/internal/feeder/pixelbt"
	"github.com/transparency-dev/witness/internal/feeder/rekor"
	"github.com/transparency-dev/witness/internal/feeder/serverless"
	"github.com/transparency-dev/witness/internal/feeder/sumdb"
	"github.com/transparency-dev/witness/internal/feeder/tiles"
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
	defaultDistributeInterval = 1 * time.Minute
)

// OperatorConfig allows the bare minimum operator-specific configuration.
// This should only contain configuration details that are custom per-operator.
type OperatorConfig struct {
	WitnessKey string

	// BastionAddr is the host:port of the bastion host to connect to, if any.
	BastionAddr string
	// BastionKey is the key used to authenticate the witness to the bastion host, if
	// a BastionAddr is configured.
	BastionKey ed25519.PrivateKey
	// BastionRateLimit is the maximum number of bastion requests to serve per second.
	BastionRateLimit float64

	// RestDistributorBaseURL is optional, and if provided gives the base URL
	// to a distributor that takes witnessed checkpoints via a PUT request.
	// TODO(mhutchinson): This should be baked into the code when there is a public distributor.
	RestDistributorBaseURL string

	FeedInterval       time.Duration
	DistributeInterval time.Duration
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

	logs := []config.Log{}
	for _, l := range logCfg.Logs {
		lc, err := config.NewLog(l.Origin, l.PublicKey, l.URL)
		if err != nil {
			return fmt.Errorf("invalid log configuration: %v", err)
		}
		if l.Feeder != None {
			feeders[lc] = l.Feeder.FeedFunc()
		}
		logs = append(logs, lc)
		klog.Infof("Added log %q: %s", lc.Origin, lc.ID)
	}

	signerLegacy, err := note.NewSigner(operatorConfig.WitnessKey)
	if err != nil {
		return fmt.Errorf("failed to init signer v0: %v", err)
	}
	signerCosigV1, err := f_note.NewSignerForCosignatureV1(operatorConfig.WitnessKey)
	if err != nil {
		return fmt.Errorf("failed to init signer v1: %v", err)
	}

	knownLogs, err := logCfg.AsLogMap()
	if err != nil {
		return fmt.Errorf("failed to convert witness config to map: %v", err)
	}
	witness, err := witness.New(witness.Opts{
		Persistence: p,
		Signers:     []note.Signer{signerLegacy, signerCosigV1},
		KnownLogs:   knownLogs,
	})
	if err != nil {
		return fmt.Errorf("failed to create witness: %v", err)
	}

	if operatorConfig.DistributeInterval == 0 {
		operatorConfig.DistributeInterval = defaultDistributeInterval
	}

	bw := witnessAdapter{
		w: witness,
	}

	if operatorConfig.FeedInterval > 0 {
		for c, f := range feeders {
			c, f := c, f
			// Continually feed this log in its own goroutine, hooked up to the global waitgroup.
			g.Go(func() error {
				klog.Infof("Feeder %q goroutine started", c.Origin)
				defer klog.Infof("Feeder %q goroutine done", c.Origin)
				return f(ctx, c, bw, httpClient, operatorConfig.FeedInterval)
			})
		}
	}

	if operatorConfig.BastionAddr != "" && operatorConfig.BastionKey != nil {
		bc := bastion.Config{
			Addr:            operatorConfig.BastionAddr,
			Logs:            logs,
			BastionKey:      operatorConfig.BastionKey,
			WitnessVerifier: signerCosigV1.Verifier(),
			Limits: bastion.RequestLimits{
				TotalPerSecond: rate.Limit(operatorConfig.BastionRateLimit),
			}}
		g.Go(func() error {
			klog.Infof("Bastion feeder %q goroutine started", bc.Addr)
			defer klog.Infof("Bastion feeder %q goroutine done", bc.Addr)
			return bastion.FeedBastion(ctx, bc, bw)
		})
	}

	if operatorConfig.RestDistributorBaseURL != "" {
		klog.Infof("Starting RESTful distributor for %q", operatorConfig.RestDistributorBaseURL)
		runRestDistributors(ctx, g, httpClient, operatorConfig.DistributeInterval, logs, operatorConfig.RestDistributorBaseURL, bw, signerCosigV1.Verifier())
	}

	r := mux.NewRouter()
	s := ihttp.NewServer(witness)
	s.RegisterHandlers(r)
	srv := http.Server{
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  5 * time.Minute,
	}
	g.Go(func() error {
		klog.Info("HTTP server goroutine started")
		defer klog.Info("HTTP server goroutine done")
		return srv.Serve(httpListener)
	})
	g.Go(func() error {
		// This goroutine brings down the HTTP server when ctx is done.
		klog.Info("HTTP server-shutdown goroutine started")
		defer klog.Info("HTTP server-shutdown goroutine done")
		<-ctx.Done()
		return srv.Shutdown(ctx)
	})

	return g.Wait()
}

func runRestDistributors(ctx context.Context, g *errgroup.Group, httpClient *http.Client, interval time.Duration, logs []config.Log, distributorBaseURL string, bw witnessAdapter, witnessV note.Verifier) {
	g.Go(func() error {
		d, err := rest.NewDistributor(distributorBaseURL, httpClient, logs, witnessV, bw)
		if err != nil {
			return fmt.Errorf("NewDistributor: %v", err)
		}
		if err := d.DistributeOnce(ctx); err != nil {
			klog.Errorf("DistributeOnce: %v", err)
		}
		for {
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				return ctx.Err()
			}
			if err := d.DistributeOnce(ctx); err != nil {
				klog.Errorf("DistributeOnce: %v", err)
			}
		}
	})
}

// Feeder is an enum of the known feeder types.
type Feeder uint8

const (
	Serverless Feeder = iota + 1
	SumDB
	Pixel
	Rekor
	Tiles
	None
)

var (
	feederByName = map[string]Feeder{
		"serverless": Serverless,
		"sumdb":      SumDB,
		"pixel":      Pixel,
		"rekor":      Rekor,
		"tiles":      Tiles,
		"none":       None,
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
	case Tiles:
		return tiles.FeedLog
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
