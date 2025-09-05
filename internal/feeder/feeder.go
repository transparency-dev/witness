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

func FeedOnce(ctx context.Context, sizeHint uint64, opts FeedOpts) (uint64, error) {
	cp, err := opts.FetchCheckpoint(ctx)
	if err != nil {
		return sizeHint, fmt.Errorf("failed to read input checkpoint: %v", err)
	}

	klog.V(2).Infof("CP to feed:\n%s", string(cp))

	cpSubmit, _, _, err := log.ParseCheckpoint(cp, opts.LogOrigin, opts.LogSigVerifier)
	if err != nil {
		return sizeHint, fmt.Errorf("failed to parse checkpoint: %v", err)
	}

	newSize, err := submitToWitness(ctx, sizeHint, cp, *cpSubmit, opts)
	if err != nil {
		return newSize, fmt.Errorf("witness submission failed: %w", err)
	}
	return newSize, nil
}

// submitToWitness will submit the checkpoint to the witness, retrying up to 3 times if the local checkpoint is stale.
func submitToWitness(ctx context.Context, sizeHint uint64, cpRaw []byte, cpSubmit log.Checkpoint, opts FeedOpts) (uint64, error) {
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
		conP, err = opts.FetchProof(ctx, sizeHint, cpSubmit)
		if err != nil {
			e := fmt.Errorf("failed to fetch consistency proof: %w", err)
			return sizeHint, backoff.Permanent(e)
		}
		klog.V(2).Infof("%q: Fetched proof %d -> %d: %x", cpSubmit.Origin, sizeHint, cpSubmit.Size, conP)

		_, actualSize, err := opts.Update(ctx, sizeHint, cpRaw, conP)
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
