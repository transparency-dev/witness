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
	"fmt"
	"sync"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/witness/internal/persistence"
	"github.com/transparency-dev/witness/monitoring"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"
)

var (
	doOnce                         sync.Once
	counterUpdateAttempt           monitoring.Counter
	counterUpdateSuccess           monitoring.Counter
	counterInvalidConsistency      monitoring.Counter
	counterInconsistentCheckpoints monitoring.Counter
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
	// An indicator of whether the log should be verified using consistency
	// proofs or compact ranges.
	UseCompact bool
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
		return nil, nil, fmt.Errorf("log %q not found", logID)
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
	read, err := w.lsp.ReadOps(logID)
	if err != nil {
		return nil, fmt.Errorf("ReadOps(): %v", err)
	}
	chkpt, _, err := read.GetLatest()
	if err != nil {
		return nil, err
	}
	return chkpt, nil
}

// Update updates the latest checkpoint if nextRaw is consistent with the current
// latest one for this log.
//
// It returns the latest cosigned checkpoint held by the witness, which is a signed
// version of nextRaw if the update was applied.
//
// If an error occurs, this method will generally return an error with a status code:
// - codes.NotFound if the log is unknown
// - codes.InvalidArgument for general bad requests
// - codes.AlreadyExists if the checkpoint is smaller than the one the witness knows
// - codes.FailedPrecondition if the checkpoint is inconsistent with the one the witness knows
func (w *Witness) Update(ctx context.Context, logID string, nextRaw []byte, cProof [][]byte) ([]byte, error) {
	// If we don't witness this log then no point in going further.
	logInfo, ok := w.Logs[logID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "log %q not found", logID)
	}
	counterUpdateAttempt.Inc(logID)
	// Check the signatures on the raw checkpoint and parse it
	// into the log.Checkpoint format.
	next, nextNote, err := w.parse(nextRaw, logID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "couldn't parse input checkpoint: %v", err)
	}
	// Get the latest one for the log because we don't want consistency proofs
	// with respect to older checkpoints.  Bind this all in a transaction to
	// avoid race conditions when updating the database.
	write, err := w.lsp.WriteOps(logID)
	if err != nil {
		return nil, fmt.Errorf("WriteOps(%v): %v", logID, err)
	}
	// The WriteOps contract is that Close must always be called.
	defer write.Close()

	// Get the latest checkpoint (if one exists) and compact range.
	prevRaw, rangeRaw, err := write.GetLatest()
	if err != nil {
		// If there was nothing stored already then treat this new
		// checkpoint as trust-on-first-use (TOFU).
		if status.Code(err) == codes.NotFound {
			// Store a witness cosigned version of the checkpoint.
			signed, err := w.signChkpt(nextNote)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "couldn't sign input checkpoint: %v", err)
			}

			if err := setInitChkptData(write, logInfo, next, signed, cProof); err != nil {
				return nil, status.Errorf(codes.Internal, "couldn't set TOFU checkpoint: %v", err)
			}
			counterUpdateSuccess.Inc(logID)
			return signed, nil
		}
		return nil, status.Errorf(codes.Internal, "couldn't retrieve latest checkpoint: %v", err)
	}
	// Parse the raw retrieved checkpoint into the log.Checkpoint format.
	prev, _, err := w.parse(prevRaw, logID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "couldn't parse stored checkpoint: %v", err)
	}
	// Parse the compact range if we're using one.
	var prevRange Proof
	if logInfo.UseCompact {
		if err := prevRange.Unmarshal(rangeRaw); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "couldn't unmarshal proof: %v", err)
		}
	}
	if next.Size < prev.Size {
		// Complain if prev is bigger than next.
		return prevRaw, status.Errorf(codes.AlreadyExists, "cannot prove consistency backwards (%d < %d)", next.Size, prev.Size)
	}
	if next.Size == prev.Size {
		if !bytes.Equal(next.Hash, prev.Hash) {
			// Code analysis complains about the next line, but it's fine; we've already bailed out
			// further up the method if the log ID was not found.
			klog.Errorf("%s: INCONSISTENT CHECKPOINTS!:\n%v\n%v", logID, prev, next) // lgtm [go/log-injection]
			counterInconsistentCheckpoints.Inc(logID)
			return prevRaw, status.Errorf(codes.FailedPrecondition, "checkpoint for same size log with differing hash (got %x, have %x)", next.Hash, prev.Hash)
		}
		// This used to short-circuit here to save work.
		// However, having the most recently witnessed timestamp available is beneficial to demonstrate freshness.
	}
	if prev.Size == 0 {
		// Checkpoints of size 0 are really placeholders and consistency proofs can't be performed.
		// If we initialized on a tree size of 0, then we simply ratchet forward and effectively TOFU the new checkpoint.
		signed, err := w.signChkpt(nextNote)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "couldn't sign input checkpoint: %v", err)
		}
		if err := setInitChkptData(write, logInfo, next, signed, cProof); err != nil {
			return nil, status.Errorf(codes.Internal, "couldn't set first non-zero checkpoint: %v", err)
		}
		counterUpdateSuccess.Inc(logID)
		return signed, nil
	}
	if next.Size != prev.Size && len(cProof) == 0 {
		// We require a proof, but we were given an empty one - the submitter likely thinks we've not seen a checkpoint for this log
		// before and is trying to get us to TOFU.
		// This is a special case of "prev > next" above, so return the same code so higher layers can handle similarly (e.g. by telling
		// the submitter our view of prev.size).
		return prevRaw, status.Errorf(codes.AlreadyExists, "we already have a non-zero checkpoint")
	}

	// The only remaining option is next.Size > prev.Size. This might be
	// valid so we use either plain consistency proofs or compact ranges to
	// verify, depending on the log.
	if logInfo.UseCompact {
		nextRange, err := verifyRange(next, prev, logInfo.Hasher, prevRange, cProof)
		if err != nil {
			counterInvalidConsistency.Inc(logID)
			return prevRaw, status.Errorf(codes.FailedPrecondition, "failed to verify compact range: %v", err)
		}
		// If the proof is good store nextRaw and the new range.
		r := []byte(Proof(nextRange).Marshal())
		signed, err := w.signChkpt(nextNote)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "couldn't sign input checkpoint: %v", err)
		}
		if err := write.Set(signed, r); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to store new checkpoint: %v", err)
		}
		counterUpdateSuccess.Inc(logID)
		return signed, nil
	}
	// If we're not using compact ranges then use consistency proofs.
	if err := proof.VerifyConsistency(logInfo.Hasher, prev.Size, next.Size, cProof, prev.Hash, next.Hash); err != nil {
		// Complain if the checkpoints aren't consistent.
		counterInvalidConsistency.Inc(logID)
		return prevRaw, status.Errorf(codes.FailedPrecondition, "failed to verify consistency proof: %v", err)
	}
	// If the consistency proof is good we store the witness cosigned nextRaw.
	signed, err := w.signChkpt(nextNote)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "couldn't sign input checkpoint: %v", err)
	}
	if err := write.Set(signed, nil); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store new checkpoint: %v", err)
	}
	counterUpdateSuccess.Inc(logID)
	return signed, nil
}

// signChkpt adds the witness' signature to a checkpoint.
func (w *Witness) signChkpt(n *note.Note) ([]byte, error) {
	cosigned, err := note.Sign(n, w.Signers...)
	if err != nil {
		return nil, fmt.Errorf("couldn't sign checkpoint: %v", err)
	}
	return cosigned, nil
}

// verifyRange verifies the new checkpoint against the stored and given compact
// range and outputs the updated compact range if verification succeeds.
func verifyRange(next *log.Checkpoint, prev *log.Checkpoint, h merkle.LogHasher, rngRaw [][]byte, deltaRaw [][]byte) ([][]byte, error) {
	rf := compact.RangeFactory{Hash: h.HashChildren}
	rng, err := rf.NewRange(0, prev.Size, rngRaw)
	if err != nil {
		return nil, fmt.Errorf("can't form current compact range: %v", err)
	}
	// As a sanity check, make sure the stored checkpoint and range are consistent.
	if err := verifyRangeHash(prev.Hash, rng); err != nil {
		return nil, fmt.Errorf("old root hash doesn't verify: %v", err)
	}
	delta, err := rf.NewRange(prev.Size, next.Size, deltaRaw)
	if err != nil {
		return nil, fmt.Errorf("can't form delta compact range: %v", err)
	}
	// Merge the delta range into the existing one and compare root hashes.
	if err := rng.AppendRange(delta, nil); err != nil {
		return nil, fmt.Errorf("failed to append range: %v", err)
	}
	if err := verifyRangeHash(next.Hash, rng); err != nil {
		return nil, fmt.Errorf("new root hash doesn't verify: %v", err)
	}
	return rng.Hashes(), nil
}

// verifyRangeHash computes the root hash of the compact range and compares it
// against the one given as input, returning an error if they aren't equal.
func verifyRangeHash(rootHash []byte, rng *compact.Range) error {
	h, err := rng.GetRootHash(nil)
	if err != nil {
		return fmt.Errorf("can't get root hash for range: %v", err)
	}
	if !bytes.Equal(rootHash, h) {
		return fmt.Errorf("hashes aren't equal (got %x, given %x)", h, rootHash)
	}
	return nil
}

// setInitChkptData stores the data for an initial checkpoint and, if using one,
// its associated compact range.
func setInitChkptData(write persistence.LogStateWriteOps, logInfo LogInfo, c *log.Checkpoint, cRaw []byte, rngRaw [][]byte) error {
	// If we're using compact ranges then store the initial range, assuming
	// it matches the initial checkpoint.
	if logInfo.UseCompact {
		rf := compact.RangeFactory{Hash: logInfo.Hasher.HashChildren}
		rng, err := rf.NewRange(0, c.Size, rngRaw)
		if err != nil {
			return fmt.Errorf("can't form compact range: %v", err)
		}
		if err := verifyRangeHash(c.Hash, rng); err != nil {
			return fmt.Errorf("input root hash doesn't verify: %v", err)
		}
		r := []byte(Proof(rngRaw).Marshal())
		return write.Set(cRaw, r)
	}
	// If we're not using compact ranges no need to store one.
	return write.Set(cRaw, nil)
}
