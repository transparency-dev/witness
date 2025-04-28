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
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/internal/feeder"
	"github.com/transparency-dev/witness/internal/persistence"
	"github.com/transparency-dev/witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"

	"github.com/transparency-dev/witness/internal/bastion"
	"github.com/transparency-dev/witness/internal/distribute/rest"
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
	WitnessKeys []note.Signer
	// This must verify one of the sigs from the previous checkpoint. If the same
	// signing keys are always used for this witness, then this will be a verifier
	// for one of the signers above.
	WitnessVerifier note.Verifier

	// BastionAddr is the host:port of the bastion host to connect to, if any.
	BastionAddr string
	// BastionKey is the key used to authenticate the witness to the bastion host, if
	// a BastionAddr is configured.
	BastionKey ed25519.PrivateKey

	// RateLimit is the maximum number of update requests to serve per second.
	RateLimit float64

	// RestDistributorBaseURL is optional, and if provided gives the base URL
	// to a distributor that takes witnessed checkpoints via a PUT request.
	// TODO(mhutchinson): This should be baked into the code when there is a public distributor.
	RestDistributorBaseURL string

	FeedInterval       time.Duration
	DistributeInterval time.Duration
}

// logFeeder is the de-facto interface that feeders implement.
type logFeeder func(context.Context, config.Log, feeder.UpdateFn, *http.Client, time.Duration) error

// Main runs the omniwitness, with the witness listening using the listener, and all
// outbound HTTP calls using the client provided.
func Main(ctx context.Context, operatorConfig OperatorConfig, p LogStatePersistence, httpListener net.Listener, httpClient *http.Client) error {
	initMetrics()
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

	knownLogs, err := logCfg.AsLogMap()
	if err != nil {
		return fmt.Errorf("failed to convert witness config to map: %v", err)
	}
	witness, err := witness.New(witness.Opts{
		Persistence: p,
		Signers:     operatorConfig.WitnessKeys,
		KnownLogs:   knownLogs,
	})
	if err != nil {
		return fmt.Errorf("failed to create witness: %v", err)
	}

	logsByID := make(map[string]config.Log)
	for _, l := range logs {
		logsByID[l.ID] = l
	}

	handler := &httpHandler{
		update:      witness.Update,
		logs:        logsByID,
		witVerifier: operatorConfig.WitnessVerifier,
		limiter:     rate.NewLimiter(rate.Limit(operatorConfig.RateLimit), int(operatorConfig.RateLimit)),
	}

	if operatorConfig.DistributeInterval == 0 {
		operatorConfig.DistributeInterval = defaultDistributeInterval
	}

	if operatorConfig.FeedInterval > 0 {
		for c, f := range feeders {
			c, f := c, f
			// Continually feed this log in its own goroutine, hooked up to the global waitgroup.
			g.Go(func() error {
				spreadDelay := time.Duration(rand.Int64N(int64(operatorConfig.FeedInterval)))
				klog.Infof("Feeder %q goroutine will start after spread delay of %s", c.Origin, spreadDelay)
				defer klog.Infof("Feeder %q goroutine done", c.Origin)

				time.Sleep(spreadDelay)
				klog.Infof("Feeder %q running", c.Origin)
				return f(ctx, c, witness.Update, httpClient, operatorConfig.FeedInterval)
			})
		}
	}

	if operatorConfig.BastionAddr != "" && operatorConfig.BastionKey != nil {
		klog.Infof("My bastion backend ID: %064x", sha256.Sum256(operatorConfig.BastionKey.Public().(ed25519.PublicKey)))
		bc := bastion.Config{
			Addr:            operatorConfig.BastionAddr,
			Logs:            logs,
			BastionKey:      operatorConfig.BastionKey,
			WitnessVerifier: operatorConfig.WitnessVerifier,
		}
		g.Go(func() error {
			klog.Infof("Bastion feeder %q goroutine started", bc.Addr)
			defer klog.Infof("Bastion feeder %q goroutine done", bc.Addr)
			return bastion.Register(ctx, bc, handler)
		})
	}

	if operatorConfig.RestDistributorBaseURL != "" {
		klog.Infof("Starting RESTful distributor for %q", operatorConfig.RestDistributorBaseURL)
		runRestDistributors(ctx, g, httpClient, operatorConfig.DistributeInterval, logs, operatorConfig.RestDistributorBaseURL, witness.GetCheckpoint, operatorConfig.WitnessVerifier)
	}

	srv := http.Server{
		Handler:      handler,
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

func runRestDistributors(ctx context.Context, g *errgroup.Group, httpClient *http.Client, interval time.Duration, logs []config.Log, distributorBaseURL string, getLatest rest.GetLatestCheckpointFn, witnessV note.Verifier) {
	g.Go(func() error {
		d, err := rest.NewDistributor(distributorBaseURL, httpClient, logs, witnessV, getLatest)
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
