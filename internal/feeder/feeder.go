// Copyright 2021 Google LLC. All Rights Reserved.
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

// Package feeder provides support for building witness feeder implementations.
package feeder

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

// ErrNoSignaturesAdded is returned when the witness has already signed the presented checkpoint.
var ErrNoSignaturesAdded = errors.New("no additional signatures added")

// UpdateFn is the signature of a function which knows how to update a witness.
type UpdateFn func(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error)

// FeedOpts holds parameters when calling the Feed function.
type FeedOpts struct {
	// LogID is the ID for the log whose checkpoint is being fed.
	//
	// TODO(al/mhutchinson): should this be an impl detail of Witness
	// rather than present here just to be passed back in to Witness calls?
	LogID string

	// FetchCheckpoint should return a recent checkpoint from the source log.
	FetchCheckpoint func(ctx context.Context) ([]byte, error)

	// FetchProof should return a consistency proof from the source log.
	//
	// Note that if the witness knows the log but has no previous checkpoint stored, this
	// function will be called with a default `from` value - this allows compact-range
	// type proofs to be supported.  Implementations for non-compact-range type proofs
	// should return an empty proof and no error.
	FetchProof func(ctx context.Context, from uint64, to log.Checkpoint) ([][]byte, error)

	// LogSigVerifier a verifier for log checkpoint signatures.
	LogSigVerifier note.Verifier
	// LogOrigin is the expected first line of checkpoints from the source log.
	LogOrigin string

	// Update knows how to update a witness
	Update UpdateFn
}

// FeedOnce sends the provided checkpoint to the configured witness.
// This method will block until a witness signature is obtained,
// or the context becomes done.
func FeedOnce(ctx context.Context, opts FeedOpts) ([]byte, error) {
	f := feeder{
		opts: opts,
	}
	return f.feedOnce(ctx)
}

// Run periodically initiates a feed cycle, fetching a checkpoint from the source log and
// submitting it to the witness.
// Calling this function will block until the context is done.
func Run(ctx context.Context, interval time.Duration, opts FeedOpts) error {
	f := feeder{
		opts: opts,
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		// Create a scope with a bounded context so we don't get wedged if something goes wrong.
		func() {
			ctx, cancel := context.WithTimeout(ctx, interval)
			defer cancel()

			if _, err := f.feedOnce(ctx); err != nil {
				klog.Errorf("Feeding log %q failed: %v", opts.LogSigVerifier.Name(), err)
			}
		}()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

type feeder struct {
	opts    FeedOpts
	oldSize uint64
}

func (f *feeder) feedOnce(ctx context.Context) ([]byte, error) {
	cp, err := f.opts.FetchCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read input checkpoint: %v", err)
	}

	klog.V(2).Infof("CP to feed:\n%s", string(cp))

	cpSubmit, _, _, err := log.ParseCheckpoint(cp, f.opts.LogOrigin, f.opts.LogSigVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint: %v", err)
	}

	wCP, err := f.submitToWitness(ctx, cp, *cpSubmit, f.opts)
	if err != nil {
		return nil, fmt.Errorf("witness submission failed: %w", err)
	}
	return wCP, nil
}

// submitToWitness will submit the checkpoint to the witness, retrying up to 3 times if the local checkpoint is stale.
func (f *feeder) submitToWitness(ctx context.Context, cpRaw []byte, cpSubmit log.Checkpoint, opts FeedOpts) ([]byte, error) {

	// Since this func will be executed by the backoff mechanism below, we'll
	// log any error messages directly in here before returning the error, as
	// the backoff util doesn't seem to log them itself.
	submitOp := func() ([]byte, error) {
		var err error
		var conP [][]byte
		if f.oldSize > cpSubmit.Size {
			return nil, backoff.Permanent(fmt.Errorf("witness checkpoint size (%d) > submit checkpoint size (%d)", f.oldSize, cpSubmit.Size))
		}

		// The witness may be configured to expect a compact-range type proof, so we need to always
		// try to build one, even if the witness doesn't have a "latest" checkpoint for this log.
		conP, err = opts.FetchProof(ctx, f.oldSize, cpSubmit)
		if err != nil {
			e := fmt.Errorf("failed to fetch consistency proof: %w", err)
			return nil, backoff.Permanent(e)
		}
		klog.V(2).Infof("%q: Fetched proof %d -> %d: %x", cpSubmit.Origin, f.oldSize, cpSubmit.Size, conP)

		witnessCp, actualSize, err := opts.Update(ctx, f.oldSize, cpRaw, conP)
		switch {
		case errors.Is(err, witness.ErrCheckpointStale):
			klog.V(2).Infof("%q: %d is stale, bumping to %d: %x", cpSubmit.Origin, f.oldSize, cpSubmit.Size, conP)
			f.oldSize = actualSize
			return nil, backoff.RetryAfter(1)
		case err != nil:
			e := fmt.Errorf("%q: failed to submit checkpoint to witness: %w", cpSubmit.Origin, err)
			return nil, backoff.Permanent(e)
		default:
			if f.oldSize == cpSubmit.Size {
				klog.V(1).Infof("%q: Refreshed witness - @%d: %x", cpSubmit.Origin, cpSubmit.Size, cpSubmit.Hash)

			} else {
				klog.V(1).Infof("%q: Updated witness - @%d → @%d: %x", cpSubmit.Origin, f.oldSize, cpSubmit.Size, cpSubmit.Hash)
			}
			f.oldSize = cpSubmit.Size
		}
		return witnessCp, nil
	}

	return backoff.Retry(ctx, submitOp, backoff.WithBackOff(backoff.NewExponentialBackOff()), backoff.WithMaxTries(3))
}
