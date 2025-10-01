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

	"github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

// ErrNoSignaturesAdded is returned when the witness has already signed the presented checkpoint.
var ErrNoSignaturesAdded = errors.New("no additional signatures added")

// FetchProofFn is the signature of a function which knows how to fetch a consistency proof.
type FetchProofFn func(ctx context.Context, from uint64, to log.Checkpoint) ([][]byte, error)

// Source holds parameters when calling the Feed function.
type Source struct {
	// FetchCheckpoint should return a recent checkpoint from the source log.
	FetchCheckpoint func(ctx context.Context) ([]byte, error)

	// FetchProof should return a consistency proof from the source log.
	//
	// Note that if the witness knows the log but has no previous checkpoint stored, this
	// function will be called with a default `from` value - this allows compact-range
	// type proofs to be supported.  Implementations for non-compact-range type proofs
	// should return an empty proof and no error.
	FetchProof FetchProofFn

	// LogSigVerifier a verifier for log checkpoint signatures.
	LogSigVerifier note.Verifier
	// LogOrigin is the expected first line of checkpoints from the source log.
	LogOrigin string
}
