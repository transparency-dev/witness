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

// Package witness is designed to make sure the checkpoints of verifiable logs
// are consistent and store/serve/sign them if so.  It is expected that a separate
// feeder component would be responsible for the actual interaction with logs.
package witness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/witness/internal/persistence"
	"github.com/transparency-dev/witness/monitoring"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	doOnce                         sync.Once
	counterUpdateAttempt           monitoring.Counter
	counterUpdateSuccess           monitoring.Counter
	counterInvalidConsistency      monitoring.Counter
	counterInconsistentCheckpoints monitoring.Counter
)

var (
	// ErrNoValidSignature is returned by calls to Update if the provided checkpoint has no valid signature by the expected key.
	ErrNoValidSignature = errors.New("no valid signatures")
	// ErrUnknownLog is returned by calls to Update if the provided checkpoint carries an Origin which is unknown to the
	// witness.
	ErrUnknownLog = errors.New("unknown log")
	// ErrOldSizeInvalid is returned by calls to Update if the provided oldSize parameter is larger than the size of the
	// submitted checkpoint.
	ErrOldSizeInvalid = errors.New("old size > current")
	// ErrCheckpointStale is returned by calls to Update if the oldSize parameter does not match the size of the currently
	// stored checkpoint for the same log.
	ErrCheckpointStale = errors.New("old size != current")
	// ErrInvalidProof is returned by calls to Update if the provided consistency proof is invalid.
	ErrInvalidProof = errors.New("consistency proof invalid")
	// ErrRootMismatch is returned by calls to Update if the provided checkpoint is for the same size tree as the currently
	// stored one, but their root hashes differ.
	ErrRootMismatch = errors.New("roots do not match")
)

func initMetrics() {
	doOnce.Do(func() {
		mf := monitoring.GetMetricFactory()
		const logIDLabel = "logid"
		counterUpdateAttempt = mf.NewCounter("witness_update_request", "Number of attempted requests made to update checkpoints for the log ID", logIDLabel)
		counterUpdateSuccess = mf.NewCounter("witness_update_success", "Number of successful requests made to update checkpoints for the log ID", logIDLabel)
		counterInvalidConsistency = mf.NewCounter("witness_update_invalid_consistency", "Number of times the witness received a bad consistency proof for the log ID", logIDLabel)
		counterInconsistentCheckpoints = mf.NewCounter("witness_update_inconsistent_checkpoints", "Number of times the witness received inconsistent checkpoints for the log ID", logIDLabel)
	})
}

// Opts is the options passed to a witness.
type Opts struct {
	Persistence persistence.LogStatePersistence
	Signers     []note.Signer
	KnownLogs   map[string]LogInfo
}

// LogInfo contains the information needed to verify log checkpoints.
type LogInfo struct {
	// The verifier for signatures from the log.
	SigV note.Verifier
	// The expected Origin string in the checkpoints.
	Origin string
	// The hash strategy that should be used in verifying consistency.
	Hasher merkle.LogHasher
}

// Witness consists of a database for storing checkpoints, a signer, and a list
// of logs for which it stores and verifies checkpoints.
type Witness struct {
	lsp     persistence.LogStatePersistence
	Signers []note.Signer
	// At some point we might want to store this information in a table in
	// the database too but as I imagine it being populated from a static
	// config file it doesn't seem very urgent to do that.
	Logs map[string]LogInfo
}

// New creates a new witness, which initially has no logs to follow.
func New(wo Opts) (*Witness, error) {
	initMetrics()

	// Create the chkpts table if needed.
	if err := wo.Persistence.Init(); err != nil {
		return nil, fmt.Errorf("Persistence.Init(): %v", err)
	}
	return &Witness{
		lsp:     wo.Persistence,
		Signers: wo.Signers,
		Logs:    wo.KnownLogs,
	}, nil
}

// parse verifies the checkpoint under the appropriate keys for logID and returns
// the parsed checkpoint and the note itself.
func (w *Witness) parse(chkptRaw []byte, logID string) (*log.Checkpoint, *note.Note, error) {
	logInfo, ok := w.Logs[logID]
	if !ok {
		return nil, nil, ErrUnknownLog
	}
	cp, _, n, err := log.ParseCheckpoint(chkptRaw, logInfo.Origin, logInfo.SigV)
	return cp, n, err
}

// GetLogs returns a list of all logs the witness is aware of.
func (w *Witness) GetLogs() ([]string, error) {
	return w.lsp.Logs()
}

// GetCheckpoint gets a checkpoint for a given log, which is consistent with all
// other checkpoints for the same log signed by this witness.
func (w *Witness) GetCheckpoint(logID string) ([]byte, error) {
	chkpt, err := w.lsp.Latest(logID)
	if err != nil {
		return nil, err
	}
	return chkpt, nil
}

// Update updates the latest checkpoint if nextRaw is consistent with the current
// latest one for this log.
//
// It returns the latest cosigned checkpoint held by the witness (which may be the provided checkpoint
// if it's accepted).
func (w *Witness) Update(ctx context.Context, logID string, oldSize uint64, nextRaw []byte, cProof [][]byte) ([]byte, error) {
	// If we don't witness this log then no point in going further.
	logInfo, ok := w.Logs[logID]
	if !ok {
		return nil, ErrUnknownLog
	}
	counterUpdateAttempt.Inc(logID)
	// Check the signatures on the raw checkpoint and parse it
	// into the log.Checkpoint format.
	//
	// SPEC: The witness MUST verify the checkpoint signature against the public key(s) it trusts for the
	//       checkpoint origin, and it MUST ignore signatures from unknown keys.
	next, nextNote, err := w.parse(nextRaw, logID)
	if err != nil {
		// TODO(al): Technically this could also be that the checkpoint body is invalid.
		return nil, ErrNoValidSignature
	}

	var retCP []byte

	err = w.lsp.Update(logID, func(prevRaw []byte) ([]byte, error) {
		// If there was nothing stored already then treat this new
		// checkpoint as trust-on-first-use (TOFU).
		if prevRaw == nil {
			// Store a witness cosigned version of the checkpoint.
			signed, err := w.signChkpt(nextNote)
			if err != nil {
				return nil, fmt.Errorf("couldn't sign input checkpoint: %v", err)
			}
			counterUpdateSuccess.Inc(logID)

			retCP = signed
			return signed, nil
		}

		prev, _, err := w.parse(prevRaw, logID)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse stored checkpoint: %v", err)
		}

		// SPEC: The old size MUST be equal to or lower than the (submitted) checkpoint size.
		if oldSize > next.Size {
			return nil, ErrOldSizeInvalid
		}
		// SPEC: The witness MUST check that the old size matches the size of the latest checkpoint it cosigned
		//       for the checkpoint's origin (or zero if it never cosigned a checkpoint for that origin)
		if oldSize != prev.Size {
			return nil, ErrCheckpointStale
		}
		// SPEC: The old size MUST be equal to or lower than the checkpoint size.
		if next.Size < prev.Size {
			return nil, ErrOldSizeInvalid
		}
		// SPEC:  If the old size matches the checkpoint size, the witness MUST check that the root hashes are
		//        also identical.
		if next.Size == prev.Size {
			if !bytes.Equal(next.Hash, prev.Hash) {
				klog.Errorf("%s: INCONSISTENT CHECKPOINTS!:\n%v\n%v", logID, prev, next)
				counterInconsistentCheckpoints.Inc(logID)

				return nil, ErrRootMismatch
			}
			// This used to short-circuit here to save work.
			// However, having the most recently witnessed timestamp available is beneficial to demonstrate freshness.
		}
		// Checkpoints of size 0 are really placeholders and consistency proofs can't be performed.
		// If we initialized on a tree size of 0, then we simply ratchet forward and effectively TOFU the new checkpoint.
		if prev.Size == 0 {
			// SPEC:  The proof MUST be empty if the old size is zero.
			if len(cProof) > 0 {
				return nil, ErrInvalidProof
			}
			signed, err := w.signChkpt(nextNote)
			if err != nil {
				return nil, fmt.Errorf("couldn't sign input checkpoint: %v", err)
			}
			counterUpdateSuccess.Inc(logID)
			return signed, nil
		}

		// The only remaining option is next.Size > prev.Size. This might be
		// valid so we verify the consistency proofs.
		if err := proof.VerifyConsistency(logInfo.Hasher, prev.Size, next.Size, cProof, prev.Hash, next.Hash); err != nil {
			// Complain if the checkpoints aren't consistent.
			counterInvalidConsistency.Inc(logID)
			return nil, ErrInvalidProof
		}
		// If the consistency proof is good we store the witness cosigned nextRaw.
		signed, err := w.signChkpt(nextNote)
		if err != nil {
			return nil, fmt.Errorf("couldn't sign input checkpoint: %v", err)
		}
		counterUpdateSuccess.Inc(logID)
		retCP = signed
		return signed, nil
	})
	if err == nil {
		counterUpdateSuccess.Inc(logID)
	}

	return retCP, err
}

// signChkpt adds the witness' signature to a checkpoint.
func (w *Witness) signChkpt(n *note.Note) ([]byte, error) {
	cosigned, err := note.Sign(n, w.Signers...)
	if err != nil {
		return nil, fmt.Errorf("couldn't sign checkpoint: %v", err)
	}
	return cosigned, nil
}
