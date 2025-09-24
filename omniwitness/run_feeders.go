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

// TODO(al): We should remove the concept of feeding from Omniwitness now that we're moving to a
// tlog-witness world, and all the stuff in here can then be moved over to `cmd/feedwitness`.

package omniwitness

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/cenkalti/backoff/v5"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/internal/feeder"
	"github.com/transparency-dev/witness/internal/witness"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

// UpdateFn is the signature of a function which knows how to update a witness.
type UpdateFn func(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error)

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
	Witnesses []UpdateFn
}

type wJob struct {
	logID string
	f     func(sizeHint uint64, f UpdateFn) (uint64, error)
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
	// TODO: consider making this configurable if needed.
	const maxPendingJobs = 1

	// We'll have a goroutine per witness, each fed by its own work channel.
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

	// Send feeder work to workers.
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
				// Skip unfeedable or unwanted logs.
				if c.Feeder == None || !r.MatchString(c.Log.Origin) {
					continue
				}
				if err := rl.Wait(ctx); err != nil {
					return fmt.Errorf("rate limit failed: %v", err)
				}

				// Create a source for this log to be used in the feeding operation.
				src, err := c.Feeder.NewSourceFunc()(c.Log, opts.HTTPClient)
				if err != nil {
					klog.Warningf("Failed to create feeder opts for %s: %v", c.Feeder.String(), err)
					continue
				}
				// First, fetch a checkpoint from the log, we're going to send this exact checkpoint to all the witnesses below.
				// Note that we can't also pre-create a proof here because we don't know what state each of the target witnesses
				// are in (e.g. previous updates could have failed on a subset).
				cp, err := src.FetchCheckpoint(ctx)
				if err != nil {
					klog.Warningf("Failed to fetch checkpoint: %v", err)
					continue
				}

				// Now send jobs to the witness channels to update to the checkpoint above.
				for _, wc := range wChans {
					select {
					case wc <- wJob{
						logID: c.Log.ID,
						f: func(sizeHint uint64, w UpdateFn) (uint64, error) {
							return feedOnce(ctx, sizeHint, w, cp, src)
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

// FeedOnce completes one feeding operation for the log and witness in the provided configuration.
// The provided sizeHint is size of the log that the caller believes is current on the target witness.
//
// Returns a new hint on what the current size of the log on the target witness.
func feedOnce(ctx context.Context, sizeHint uint64, update UpdateFn, cp []byte, src feeder.Source) (uint64, error) {
	klog.V(2).Infof("CP to feed:\n%s", string(cp))

	cpSubmit, _, _, err := log.ParseCheckpoint(cp, src.LogOrigin, src.LogSigVerifier)
	if err != nil {
		return sizeHint, fmt.Errorf("failed to parse checkpoint: %v", err)
	}

	newSize, err := submitToWitness(ctx, sizeHint, cp, *cpSubmit, src.FetchProof, update)
	if err != nil {
		return newSize, fmt.Errorf("witness submission failed: %w", err)
	}
	return newSize, nil
}

// submitToWitness will submit the checkpoint to the witness, retrying up to 3 times if the local checkpoint is stale.
func submitToWitness(ctx context.Context, sizeHint uint64, cpRaw []byte, cpSubmit log.Checkpoint, fetchProof feeder.FetchProofFn, update UpdateFn) (uint64, error) {
	// Since this func will be executed by the backoff mechanism below, we'll
	// log any error messages directly in here before returning the error, as
	// the backoff util doesn't seem to log them itself.
	submitOp := func() (uint64, error) {
		var err error
		var conP [][]byte
		if sizeHint > cpSubmit.Size {
			return sizeHint, backoff.Permanent(fmt.Errorf("witness checkpoint size (%d) > submit checkpoint size (%d)", sizeHint, cpSubmit.Size))
		}

		// The witness may be configured to expect a compact-range type proof, so we need to always
		// try to build one, even if the witness doesn't have a "latest" checkpoint for this log.
		conP, err = fetchProof(ctx, sizeHint, cpSubmit)
		if err != nil {
			e := fmt.Errorf("failed to fetch consistency proof: %w", err)
			return sizeHint, backoff.Permanent(e)
		}
		klog.V(2).Infof("%q: Fetched proof %d -> %d: %x", cpSubmit.Origin, sizeHint, cpSubmit.Size, conP)

		_, actualSize, err := update(ctx, sizeHint, cpRaw, conP)
		switch {
		case errors.Is(err, witness.ErrCheckpointStale):
			klog.V(2).Infof("%q: %d is stale, bumping to %d: %x", cpSubmit.Origin, sizeHint, cpSubmit.Size, conP)
			sizeHint = actualSize
			return sizeHint, backoff.RetryAfter(1)
		case err != nil:
			e := fmt.Errorf("%q: failed to submit checkpoint to witness: %w", cpSubmit.Origin, err)
			return sizeHint, backoff.Permanent(e)
		default:
			if sizeHint == cpSubmit.Size {
				klog.V(1).Infof("%q: Refreshed witness - @%d: %x", cpSubmit.Origin, cpSubmit.Size, cpSubmit.Hash)

			} else {
				klog.V(1).Infof("%q: Updated witness - @%d → @%d: %x", cpSubmit.Origin, sizeHint, cpSubmit.Size, cpSubmit.Hash)
			}
			sizeHint = cpSubmit.Size
		}
		return sizeHint, nil
	}

	return backoff.Retry(ctx, submitOp, backoff.WithBackOff(backoff.NewExponentialBackOff()), backoff.WithMaxTries(3))
}
