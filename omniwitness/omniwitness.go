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
	"iter"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/transparency-dev/witness/api"
	"github.com/transparency-dev/witness/internal/feeder"
	"github.com/transparency-dev/witness/internal/persistence"
	"github.com/transparency-dev/witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"

	"github.com/transparency-dev/witness/internal/bastion"
	"github.com/transparency-dev/witness/internal/distribute/rest"
	"github.com/transparency-dev/witness/internal/feeder/pixelbt"
	"github.com/transparency-dev/witness/internal/feeder/rekor_v1"
	"github.com/transparency-dev/witness/internal/feeder/serverless"
	"github.com/transparency-dev/witness/internal/feeder/sumdb"
	"github.com/transparency-dev/witness/internal/feeder/tiles"
)

// LogStatePersistence describes functionality the omniwitness requires
// in order to persist its view of log state and log configs
type Persistence interface {
	persistence.LogStatePersistence
	LogConfig
}

const (
	defaultDistributeInterval = 1 * time.Minute
	defaultProvisionInterval  = 10 * time.Minute
)

// Log describes a verifiable log.
type Log struct {
	// VKey is the serialised note-compliant vkey for the log.
	VKey string
	// Verifier is a signature verifier for log checkpoints.
	Verifier note.Verifier
	// Origin is the expected first line of checkpoints from the log.
	Origin string
	// QPD is the expected number of witness requests per day from the log.
	QPD float64
	// Contact is an arbitrary string with contact information for the log operator.
	Contact string
	// URL is the URL of the root of the log.
	URL string
}

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
	// DistributeRateLimit is the maximum number of calls per second to the configured distributor.
	DistributeRateLimit float64

	ServeMux *http.ServeMux

	// Logs provides the witness with the log configuration.
	// If unset, uses the embedded default config.
	Logs LogConfig

	// Feeders provides the witness with the config for self-feeding from logs.
	Feeders func(context.Context) iter.Seq2[FeederConfig, error]

	// WitnessNetworkConfigURLs is optional, and may be set to one or more URLs pointing to resources
	// in the public witness network config format.
	// These resources will be periodically retrieved and incorporated into the LogConfig provided above.
	WitnessNetworkConfigURLs []string

	// WitnessNetworkConfigInterval is the time between attempts to fetch and merge configs from the
	// URLs provided above.
	WitnessNetworkConfigInterval time.Duration
}

// LogConfig is the contract of something which knows how to provide log configuration info for the witness.
type LogConfig interface {
	// Logs returns an iterator of all known logs.
	Logs(ctx context.Context) iter.Seq2[Log, error]
	// Log returns the configuration info of the log with the specified log ID, if it exists.
	Log(ctx context.Context, id string) (Log, bool, error)
	// AddLogs should attempt to merge the provided logs into the current config.
	// The merge must be additive only with respect to the logs.
	AddLogs(ctx context.Context, cfg []Log) error
}

type FeederConfig struct {
	Log    Log
	Feeder Feeder
}

// Main runs the omniwitness, with the witness listening using the listener, and all
// outbound HTTP calls using the client provided.
func Main(ctx context.Context, operatorConfig OperatorConfig, p Persistence, httpListener net.Listener, httpClient *http.Client) error {
	initHTTPMetrics()
	initFeederMetrics()

	// This error group will be used to run all top level processes.
	// If any process dies, then all of them will be stopped via context cancellation.
	g, ctx := errgroup.WithContext(ctx)

	// If no ServeMux is provided, make a new private one.
	if operatorConfig.ServeMux == nil {
		operatorConfig.ServeMux = &http.ServeMux{}
	}

	if operatorConfig.Logs == nil {
		l, err := NewStaticLogConfig(DefaultConfigLogs)
		if err != nil {
			return fmt.Errorf("failed to instantiate default logs config: %v", err)
		}
		operatorConfig.Logs = l
	}

	witness, err := witness.New(ctx, witness.Opts{
		Persistence:  p,
		Signers:      operatorConfig.WitnessKeys,
		ConfigForLog: operatorConfig.Logs.Log,
	})
	if err != nil {
		return fmt.Errorf("failed to create witness: %v", err)
	}

	var limiter *rate.Limiter
	if operatorConfig.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(operatorConfig.RateLimit), int(operatorConfig.RateLimit))
	}
	handler := &httpHandler{
		update:      witness.Update,
		logs:        operatorConfig.Logs,
		witVerifier: operatorConfig.WitnessVerifier,
		limiter:     limiter,
	}

	if operatorConfig.DistributeInterval == 0 {
		operatorConfig.DistributeInterval = defaultDistributeInterval
	}
	if operatorConfig.WitnessNetworkConfigInterval == 0 && len(operatorConfig.WitnessNetworkConfigURLs) > 0 {
		operatorConfig.WitnessNetworkConfigInterval = defaultProvisionInterval
	}
	if operatorConfig.FeedInterval > 0 && operatorConfig.Feeders != nil {
		rOpts := RunFeedOpts{
			Witnesses:     []Witness{{Name: operatorConfig.WitnessVerifier.Name(), Update: witness.Update}},
			HTTPClient:    httpClient,
			MaxWitnessQPS: float64(time.Second) / float64(operatorConfig.FeedInterval),
			FeederConfigs: operatorConfig.Feeders,
		}
		g.Go(func() error { return RunFeeders(ctx, rOpts) })

	}
	operatorConfig.ServeMux.Handle(api.HTTPAddCheckpoint, http.MaxBytesHandler(handler, 16*1024))

	if operatorConfig.BastionAddr != "" && operatorConfig.BastionKey != nil {
		klog.Infof("My bastion backend ID: %064x", sha256.Sum256(operatorConfig.BastionKey.Public().(ed25519.PublicKey)))
		bc := bastion.Config{
			Addr:            operatorConfig.BastionAddr,
			BastionKey:      operatorConfig.BastionKey,
			WitnessVerifier: operatorConfig.WitnessVerifier,
		}
		g.Go(func() error {
			klog.Infof("Bastion feeder %q goroutine started", bc.Addr)
			defer klog.Infof("Bastion feeder %q goroutine done", bc.Addr)
			return bastion.Register(ctx, bc, operatorConfig.ServeMux)
		})
	}

	if operatorConfig.RestDistributorBaseURL != "" {
		klog.Infof("Starting RESTful distributor for %q", operatorConfig.RestDistributorBaseURL)
		runRestDistributors(ctx, g, httpClient, operatorConfig.DistributeInterval, operatorConfig.Logs, operatorConfig.RestDistributorBaseURL, witness.GetCheckpoint, operatorConfig.WitnessVerifier, operatorConfig.DistributeRateLimit)
	}
	if len(operatorConfig.WitnessNetworkConfigURLs) > 0 {
		g.Go(func() error {
			return provisionFromPublicConfig(ctx, httpClient, operatorConfig.WitnessNetworkConfigURLs, operatorConfig.Logs, operatorConfig.WitnessNetworkConfigInterval)
		})
	}

	srv := http.Server{
		Handler:      operatorConfig.ServeMux,
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

func runRestDistributors(ctx context.Context, g *errgroup.Group, httpClient *http.Client, interval time.Duration, logs LogConfig, distributorBaseURL string, getLatest rest.GetLatestCheckpointFn, witnessV note.Verifier, rateLimit float64) {
	g.Go(func() error {
		d, err := rest.NewDistributor(distributorBaseURL, httpClient, logs, witnessV, getLatest, rateLimit)
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
	feederNameByID = func() map[Feeder]string {
		r := make(map[Feeder]string)
		for k, v := range feederByName {
			r[v] = k
		}
		return r
	}()
)

// UnmarshalYAML populates the log from yaml using the unmarshal func provided.
func (f *Feeder) UnmarshalYAML(unmarshal func(any) error) (err error) {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	if *f, err = ParseFeeder(raw); err != nil {
		return err
	}
	return nil
}

func (f Feeder) NewSourceFunc() func(Log, *http.Client) (feeder.Source, error) {
	switch f {
	case Serverless:
		return serverless.NewFeedSource
	case SumDB:
		return sumdb.NewFeedSource
	case Pixel:
		return pixelbt.NewFeedSource
	case Rekor:
		return rekor_v1.NewFeedSource
	case Tiles:
		return tiles.NewFeedSource
	}
	panic(fmt.Sprintf("unknown feeder enum: %q", f))
}

func (f Feeder) String() string {
	return feederNameByID[f]
}

// ParseFeeder takes a string and returns a valid enum or an error.
func ParseFeeder(f string) (Feeder, error) {
	f = strings.TrimSpace(strings.ToLower(f))
	value, ok := feederByName[f]
	if !ok {
		return Feeder(0), fmt.Errorf("unknown feeder type %q", f)
	}
	return value, nil
}
