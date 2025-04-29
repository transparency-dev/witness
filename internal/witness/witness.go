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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle"
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

// parse verifies the checkpoint under the appropriate key for the origin and returns
// the parsed checkpoint and the note itself.
func (w *Witness) parse(chkptRaw []byte) (*log.Checkpoint, *note.Note, LogInfo, error) {
	origin, _, found := strings.Cut(string(chkptRaw), "\n")
	if !found {
		return nil, nil, LogInfo{}, errors.New("invalid checkpoint")
	}
	logID := log.ID(origin)
	logInfo, ok := w.Logs[logID]
	if !ok {
		return nil, nil, LogInfo{}, ErrUnknownLog
	}
	cp, _, n, err := log.ParseCheckpoint(chkptRaw, logInfo.Origin, logInfo.SigV)
	return cp, n, logInfo, err
}

// GetCheckpoint gets a checkpoint for a given log, which is consistent with all
// other checkpoints for the same log signed by this witness.
func (w *Witness) GetCheckpoint(_ context.Context, logID string) ([]byte, error) {
	read, err := w.lsp.ReadOps(logID)
	if err != nil {
		return nil, fmt.Errorf("ReadOps(): %v", err)
	}
	chkpt, err := read.GetLatest()
	if err != nil {
		return nil, err
	}
	return chkpt, nil
}

// Update updates the latest checkpoint if nextRaw is consistent with the current
// latest one for this log.
//
// The values returned depend on whether or not the new checkpoint is accepted, and
// if not, the reason it was rejected. This can be determined through the error:
//
// - no error: The checkpoint was accepted, and a serialised note-signature is returned.
// - ErrCheckpointStale or ErrOldSizeInvalid: the presented checkpoint is out of date, the size of the current checkpoint is returned.
// - Any other error, no supporting values are returned.
func (w *Witness) Update(ctx context.Context, oldSize uint64, nextRaw []byte, cProof [][]byte) ([]byte, uint64, error) {
	// Check the signatures on the raw checkpoint and parse it
	// into the log.Checkpoint format.
	//
	// SPEC: The witness MUST verify the checkpoint signature against the public key(s) it trusts for the
	//       checkpoint origin, and it MUST ignore signatures from unknown keys.
	next, nextNote, logInfo, err := w.parse(nextRaw)
	if err != nil {
		// TODO(al): Technically this could also be that the checkpoint body is invalid.
		return nil, 0, ErrNoValidSignature
	}
	logID := log.ID(logInfo.Origin)
	counterUpdateAttempt.Inc(logID)

	// Get the latest checkpoint for the log because we don't want consistency proofs
	// with respect to older checkpoints.  Bind this all in a transaction to
	// avoid race conditions when updating the database.
	write, err := w.lsp.WriteOps(logID)
	if err != nil {
		return nil, 0, fmt.Errorf("WriteOps(%v): %v", logID, err)
	}
	// The WriteOps contract is that Close must always be called.
	defer func() {
		if err := write.Close(); err != nil {
			klog.Errorf("Failed to close log state write ops: %v", err)
		}
	}()

	// Get the latest checkpoint.
	prevRaw, err := write.GetLatest()
	if err != nil {
		// If there was nothing stored already then treat this new
		// checkpoint as trust-on-first-use (TOFU).
		if status.Code(err) == codes.NotFound {
			// Store a witness cosigned version of the checkpoint.
			signed, sigs, err := w.signChkpt(nextNote)
			if err != nil {
				return nil, 0, fmt.Errorf("couldn't sign input checkpoint: %v", err)
			}

			if err := write.Set(signed); err != nil {
				return nil, 0, fmt.Errorf("couldn't set TOFU checkpoint: %v", err)
			}
			counterUpdateSuccess.Inc(logID)
			return sigs, 0, nil
		}
		return nil, 0, fmt.Errorf("couldn't retrieve latest checkpoint: %v", err)
	}
	prev, _, _, err := w.parse(prevRaw)
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't parse stored checkpoint: %v", err)
	}

	// SPEC: The old size MUST be equal to or lower than the (submitted) checkpoint size.
	if oldSize > next.Size {
		return prevRaw, prev.Size, ErrOldSizeInvalid
	}
	// SPEC: The witness MUST check that the old size matches the size of the latest checkpoint it cosigned
	//       for the checkpoint's origin (or zero if it never cosigned a checkpoint for that origin)
	if oldSize != prev.Size {
		return prevRaw, prev.Size, ErrCheckpointStale
	}
	// SPEC: The old size MUST be equal to or lower than the checkpoint size.
	if next.Size < prev.Size {
		return nil, prev.Size, ErrOldSizeInvalid
	}
	// SPEC:  If the old size matches the checkpoint size, the witness MUST check that the root hashes are
	//        also identical.
	if next.Size == prev.Size {
		if !bytes.Equal(next.Hash, prev.Hash) {
			klog.Errorf("%s: INCONSISTENT CHECKPOINTS!:\n%v\n%v", logID, prev, next)
			counterInconsistentCheckpoints.Inc(logID)
			return prevRaw, prev.Size, ErrRootMismatch
		}
		// This used to short-circuit here to save work.
		// However, having the most recently witnessed timestamp available is beneficial to demonstrate freshness.
	}
	// Checkpoints of size 0 are really placeholders and consistency proofs can't be performed.
	// If we initialized on a tree size of 0, then we simply ratchet forward and effectively TOFU the new checkpoint.
	if next.Size == 0 {
		// SPEC:  The proof MUST be empty if the old size is zero.
		if len(cProof) > 0 {
			return nil, 0, fmt.Errorf("oldSize=0 but non-zero proof supplied")
		}
		signed, witnessSig, err := w.signChkpt(nextNote)
		if err != nil {
			return nil, 0, fmt.Errorf("couldn't sign input checkpoint: %v", err)
		}
		if err := write.Set(signed); err != nil {
			return nil, 0, fmt.Errorf("couldn't set first non-zero checkpoint: %v", err)
		}
		counterUpdateSuccess.Inc(logID)
		return witnessSig, 0, nil
	}

	// The only remaining option is next.Size > prev.Size. This might be
	// valid so we verify the consistency proofs.
	if err := proof.VerifyConsistency(logInfo.Hasher, prev.Size, next.Size, cProof, prev.Hash, next.Hash); err != nil {
		// Complain if the checkpoints aren't consistent.
		counterInvalidConsistency.Inc(logID)
		return prevRaw, 0, ErrInvalidProof
	}
	// If the consistency proof is good we store the witness cosigned nextRaw.
	signed, witnessSig, err := w.signChkpt(nextNote)
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't sign input checkpoint: %v", err)
	}
	if err := write.Set(signed); err != nil {
		return nil, 0, fmt.Errorf("failed to store new checkpoint: %v", err)
	}
	counterUpdateSuccess.Inc(logID)
	return witnessSig, 0, nil
}

// signChkpt adds the witness' signature to a checkpoint.
//
// Returns:
// - A serialised signed note including new witness signatures.
// - A serialised representation of just the witness signature line(s).
func (w *Witness) signChkpt(n *note.Note) ([]byte, []byte, error) {
	// Code below is a lightly tweaked snippet from sumdb/note/note.go
	// https://cs.opensource.google/go/x/mod/+/refs/tags/v0.24.0:sumdb/note/note.go;l=625-649

	// Prepare signatures.
	//
	// We need to return both a full serialised signed note, as well as the just the
	// signature lines we're adding - this is because we want to _store_ the full note, but
	// the tlog-witness API requires that we only return the signature lines.
	//
	// Rather than using note.Sign, then running note.Open in order to get access to our
	// signatures, we'll instead use our note.Signer(s) directly to sign the note message
	// and then use the returned signature bytes to create both the serialised signed note
	// as well as the serialised signature lines.

	var sigs = bytes.Buffer{}
	for _, s := range w.Signers {
		name := s.Name()
		hash := s.KeyHash()
		if !isValidSignerName(name) {
			return nil, nil, errors.New("invalid signer")
		}

		sig, err := s.Sign([]byte(n.Text))
		if err != nil {
			return nil, nil, err
		}

		// Create serialised signature line and append it to our sigs buffer:
		var hbuf [4]byte
		binary.BigEndian.PutUint32(hbuf[:], hash)
		b64 := base64.StdEncoding.EncodeToString(append(hbuf[:], sig...))
		sigs.WriteString("— ")
		sigs.WriteString(name)
		sigs.WriteString(" ")
		sigs.WriteString(b64)
		sigs.WriteString("\n")

		// Also create a new note.Signature and pop it into the note's Sigs list (this will cause
		// the signature to be present in the output when we call note.Sign below.
		n.Sigs = append(n.Sigs, note.Signature{Name: name, Hash: hash, Base64: b64})
	}
	// Serialise the full signed note by calling Sign.
	// Note that we're not passing any signers here because we've already added signatures in the loop above, so
	// this call becomes just a serialisation function.
	signed, err := note.Sign(n)
	if err != nil {
		return nil, nil, err
	}

	return signed, sigs.Bytes(), nil
}

// isValiSignerdName reports whether name is valid.
// It must be non-empty and not have any Unicode spaces or pluses.
func isValidSignerName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}
