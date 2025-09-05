// Copyright 2025 Google LLC. All Rights Reserved.
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

package omniwitness

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/transparency-dev/witness/internal/feeder"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

// RunFeedOpts is the configuration to use for RunFeeders.
type RunFeedOpts struct {
	// MaxWitnessQPS is the maximum number of requests to make per second to any given witness.
	// If unset, a default of 1 QPS will be assumed.
	MaxWitnessQPS float64
	// HTTPClient is the HTTPClient to use, if nil uses http.DefaultClient.
	HTTPClient *http.Client
	// MatchLogs is an optional regex to select a submet of logs to feed.
	MatchLogs string
	// LogConfig provides access to log config. Required.
	LogConfig LogConfig
	// Witnesses is the set of witnesses to feed to. Required.
	Witnesses []feeder.UpdateFn
}

type wJob struct {
	logID string
	f     func(sizeHint uint64, f feeder.UpdateFn) (uint64, error)
}

// RunFeeders continually feeds checkpoints from logs to witnesses according to the provided config.
//
// This is a long-running function which will only return when the context is done.
func RunFeeders(ctx context.Context, opts RunFeedOpts) error {
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}
	if opts.MaxWitnessQPS == 0 {
		opts.MaxWitnessQPS = 1
	}

	eg := &errgroup.Group{}
	// TODO: consider making this configuable if needed.
	const maxPendingJobs = 1

	// We'll have a goroutine per witness, each fed by its own work channel
	klog.Infof("Starting %d feeder worker(s)", len(opts.Witnesses))
	wChans := make([]chan wJob, 0, len(opts.Witnesses))
	for _, wi := range opts.Witnesses {
		wChan := make(chan wJob, maxPendingJobs)
		wChans = append(wChans, wChan)
		eg.Go(func() error {
			// cache of size hints for logs we've submitted to.
			// local to this goroutine only, so no need to lock.
			//
			// TODO(al): this can be limited in size or disabled if the number of logs we need to
			// witness is too large for available RAM, we'll just degrade to going through the
			// "stale view" path with the witnesses.
			logSizes := make(map[string]uint64)
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case job := <-wChan:
					var err error
					sizeHint := logSizes[job.logID]
					if sizeHint, err = job.f(sizeHint, wi); err != nil {
						// Log this, but don't return the error as we want to continue
						// executing feeder jobs until the context is done.
						klog.Infof("[FeederWorker] Feed job failed: %v", err)
					} else {
						logSizes[job.logID] = sizeHint
					}
				}
			}
		})
	}

	r := regexp.MustCompile(opts.MatchLogs)

	// Send feeder work to workers
	eg.Go(func() error {
		klog.Infof("Starting feeder job creator")
		rl := rate.NewLimiter(rate.Limit(opts.MaxWitnessQPS), 1)
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			for c, err := range opts.LogConfig.Feeders(ctx) {
				if err != nil {
					klog.Warningf("Failed to enumerate feeders: %v", err)
					break
				}
				// Skip unfeedable or unwanted logs
				if c.Feeder == None || !r.MatchString(c.Log.Origin) {
					continue
				}
				if err := rl.Wait(ctx); err != nil {
					return fmt.Errorf("rate limit failed: %v", err)
				}
				// Now send jobs to the witnesses.
				for _, wc := range wChans {
					select {
					case wc <- wJob{
						logID: c.Log.ID,
						f: func(sizeHint uint64, w feeder.UpdateFn) (uint64, error) {
							return c.Feeder.FeedFunc()(ctx, c.Log, sizeHint, w, opts.HTTPClient)
						},
					}:
						klog.V(1).Infof("Request to feed %s", c.Log.Origin)
					default:
						klog.V(1).Infof("Skipping feed of %s, witness worker busy", c.Log.Origin)
					}
				}
			}
		}
	})

	return eg.Wait()
}
