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
	"math/bits"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	counterUpdateAttempt           metric.Int64Counter
	counterUpdateSuccess           metric.Int64Counter
	counterInvalidConsistency      metric.Int64Counter
	counterInconsistentCheckpoints metric.Int64Counter
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
	// ErrPushback is returned if the witness is overloaded.
	ErrPushback = errors.New("pushback")
	// ErrNoWitnessSignature is returned by calls to SignSubtree if the provided checkpoint has no valid signature by the witness.
	ErrNoWitnessSignature = errors.New("no witness signature")
	// ErrSubtreeRangeInvalid is returned by calls to SignSubtree if the subtree range is invalid.
	ErrSubtreeRangeInvalid = errors.New("subtree range invalid")
	// ErrNotImplemented is returned if the operation is not supported by the witness's signers.
	ErrNotImplemented = errors.New("not implemented")
)

func init() {
	var err error
	counterUpdateAttempt, err = meter.Int64Counter("witness_update_request", metric.WithUnit("{call}"), metric.WithDescription("Number of attempted requests made to update checkpoints for the log origin"))
	if err != nil {
		klog.Errorf("failed to create counter: %v", err)
	}
	counterUpdateSuccess, err = meter.Int64Counter("witness_update_success", metric.WithUnit("{call}"), metric.WithDescription("Number of successful requests made to update checkpoints for the log origin"))
	if err != nil {
		klog.Errorf("failed to create counter: %v", err)
	}
	counterInvalidConsistency, err = meter.Int64Counter("witness_update_invalid_consistency", metric.WithUnit("{call}"), metric.WithDescription("Number of times the witness received a bad consistency proof for the log origin"))
	if err != nil {
		klog.Errorf("failed to create counter: %v", err)
	}
	counterInconsistentCheckpoints, err = meter.Int64Counter("witness_update_inconsistent_checkpoints", metric.WithUnit("{call}"), metric.WithDescription("Number of times the witness received inconsistent checkpoints for the log origin"))
	if err != nil {
		klog.Errorf("failed to create counter: %v", err)
	}
}

// Opts is the options passed to a witness.
type Opts struct {
	Persistence          LogStatePersistence
	Signers              []note.Signer
	VerifierForLog       func(ctx context.Context, origin string) (note.Verifier, bool, error)
	EnableSubtreeSigning bool
}

// Witness consists of a database for storing checkpoints, a signer, and a list
// of logs for which it stores and verifies checkpoints.
type Witness struct {
	lsp            LogStatePersistence
	Signers        []note.Signer
	subtreeSigners []f_note.SubtreeSigner
	VerifierForLog func(ctx context.Context, origin string) (note.Verifier, bool, error)
}

// New creates a new witness, which initially has no logs to follow.
func New(ctx context.Context, wo Opts) (*Witness, error) {
	// Create the chkpts table if needed.
	if err := wo.Persistence.Init(ctx); err != nil {
		return nil, fmt.Errorf("Persistence.Init(): %v", err)
	}

	subtreeSigners := make([]f_note.SubtreeSigner, 0, len(wo.Signers))
	// Ensure we can handle subtree signing, if it is enabled.
	if wo.EnableSubtreeSigning {
		for _, s := range wo.Signers {
			if ss, ok := s.(f_note.SubtreeSigner); ok {
				subtreeSigners = append(subtreeSigners, ss)
			}
		}
		if len(subtreeSigners) == 0 {
			return nil, errors.New("EnableSubtreeSigning is true but no subtree signer provided")
		}
	}

	return &Witness{
		lsp:            wo.Persistence,
		Signers:        wo.Signers,
		subtreeSigners: subtreeSigners,
		VerifierForLog: wo.VerifierForLog,
	}, nil
}

// GetCheckpoint gets a checkpoint for a given log, which is consistent with all
// other checkpoints for the same log signed by this witness.
//
// Returns a nil checkpoint if no checkpoint is stored for the given logID.
func (w *Witness) GetCheckpoint(ctx context.Context, origin string) ([]byte, error) {
	return w.lsp.Latest(ctx, origin)
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
	next, nextNote, origin, err := func() (*log.Checkpoint, *note.Note, string, error) {
		origin, _, found := strings.Cut(string(nextRaw), "\n")
		if !found {
			return nil, nil, "", errors.New("invalid checkpoint")
		}
		v, ok, err := w.VerifierForLog(ctx, origin)
		if err != nil {
			return nil, nil, "", err
		}
		if !ok {
			return nil, nil, "", ErrUnknownLog
		}
		cp, _, n, err := log.ParseCheckpoint(nextRaw, origin, v)
		return cp, n, origin, err
	}()
	if err != nil {
		return nil, 0, err
	}

	// SPEC: A checkpoint of size zero MUST have the root hash of the empty tree, which
	//		RFC 6962, Section 2.1 defines as the hash of the empty string. Otherwise,
	//		the witness MUST respond with a "422 Unprocessable Entity" HTTP status code.
	if next.Size == 0 && !bytes.Equal(next.Hash, rfc6962.DefaultHasher.EmptyRoot()) {
		return nil, 0, ErrRootMismatch
	}

	counterUpdateAttempt.Add(ctx, 1, metric.WithAttributes(originKey.String(origin)))

	var retSigs []byte
	var retSize uint64

	// Get the latest checkpoint for the log because we don't want consistency proofs
	// with respect to older checkpoints.  Bind this all in a transaction to
	// avoid race conditions when updating the database.
	err = w.lsp.Update(ctx, origin, func(prevRaw []byte) ([]byte, error) {
		// If there was nothing stored already then treat this new
		// checkpoint as trust-on-first-use (TOFU).
		if prevRaw == nil {
			// Store a witness cosigned version of the checkpoint.
			signed, sigs, err := w.signChkpt(nextNote)
			if err != nil {
				return nil, fmt.Errorf("couldn't sign input checkpoint: %v", err)
			}
			retSigs = sigs
			return signed, nil
		}

		// The persistence layer is within the TCB so we assume that whatever we read is a valid log checkpoint.
		// Avoiding revalidating this gives us more flexibility to support log key rotation.
		prevOrigin, prevSize, prevHash, err := checkpointUnsafe(prevRaw)
		if err != nil {
			retSize, retSigs = 0, nil
			return nil, fmt.Errorf("couldn't parse stored checkpoint: %v", err)
		}
		if prevOrigin != origin {
			retSize, retSigs = 0, nil
			return nil, fmt.Errorf("origin didn't match during update. prev=%q, next=%q", prevOrigin, origin)
		}

		// SPEC: The old size MUST be equal to or lower than the (submitted) checkpoint size.
		if oldSize > next.Size {
			retSize, retSigs = prevSize, nil
			return nil, ErrOldSizeInvalid
		}
		// SPEC: The witness MUST check that the old size matches the size of the latest checkpoint it cosigned
		//       for the checkpoint's origin (or zero if it never cosigned a checkpoint for that origin)
		if oldSize != prevSize {
			retSize, retSigs = prevSize, nil
			return nil, fmt.Errorf("%w (%d != %d)", ErrCheckpointStale, oldSize, prevSize)
		}
		// SPEC: The old size MUST be equal to or lower than the checkpoint size.
		if next.Size < prevSize {
			retSize, retSigs = prevSize, nil
			return nil, ErrOldSizeInvalid
		}
		// SPEC:  If the old size matches the checkpoint size, the witness MUST check that the root hashes are
		//        also identical.
		if next.Size == prevSize {
			if !bytes.Equal(next.Hash, prevHash) {
				klog.Errorf("%s: INCONSISTENT CHECKPOINTS!:\nPrevious:\n%s\nNext:\n%s", origin, string(prevRaw), string(nextRaw))
				counterInconsistentCheckpoints.Add(ctx, 1, metric.WithAttributes(originKey.String(origin)))

				retSize, retSigs = 0, nil
				return nil, ErrRootMismatch
			}
			// This used to short-circuit here to save work.
			// However, having the most recently witnessed timestamp available is beneficial to demonstrate freshness.
		}
		// Checkpoints of size 0 are really placeholders and consistency proofs can't be performed.
		// If we initialized on a tree size of 0, then we simply ratchet forward and effectively TOFU the new checkpoint.
		if prevSize == 0 {
			// SPEC:  The proof MUST be empty if the old size is zero.
			if len(cProof) > 0 {
				retSize, retSigs = 0, nil
				return nil, ErrInvalidProof
			}
			signed, sigs, err := w.signChkpt(nextNote)
			if err != nil {
				retSize, retSigs = 0, nil
				return nil, fmt.Errorf("couldn't sign input checkpoint: %v", err)
			}
			retSize, retSigs = 0, sigs
			return signed, nil
		}

		// The only remaining option is next.Size > prev.Size. This might be
		// valid so we verify the consistency proofs.
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, prevSize, next.Size, cProof, prevHash, next.Hash); err != nil {
			// Complain if the checkpoints aren't consistent.
			counterInvalidConsistency.Add(ctx, 1, metric.WithAttributes(originKey.String(origin)))
			return nil, ErrInvalidProof
		}
		// If the consistency proof is good we store the witness cosigned nextRaw.
		signed, sigs, err := w.signChkpt(nextNote)
		if err != nil {
			retSize, retSigs = 0, nil
			return nil, fmt.Errorf("couldn't sign input checkpoint: %v", err)
		}
		retSize, retSigs = 0, sigs
		return signed, nil
	})
	if err == nil {
		counterUpdateSuccess.Add(ctx, 1, metric.WithAttributes(originKey.String(origin)))
	}

	return retSigs, retSize, err
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

// checkpointUnsafe parses a checkpoint without performing any signature verification.
// This is intended to be as fast as possible, but sacrifices safety because it skips verifying
// the note signature.
func checkpointUnsafe(rawCp []byte) (string, uint64, []byte, error) {
	parts := bytes.SplitN(rawCp, []byte{'\n'}, 4)
	if want, got := 4, len(parts); want != got {
		return "", 0, nil, fmt.Errorf("invalid checkpoint: %q", rawCp)
	}
	origin := string(parts[0])
	sizeStr := string(parts[1])
	hashStr := string(parts[2])
	size, err := strconv.ParseUint(sizeStr, 10, 64)
	if err != nil {
		return "", 0, nil, fmt.Errorf("failed to parse checkpoint size of %q into uint64: %v", sizeStr, err)
	}
	hash, err := base64.StdEncoding.DecodeString(hashStr)
	if err != nil {
		return "", 0, nil, fmt.Errorf("failed to decode hash: %v", err)
	}
	return origin, size, hash, nil
}

// SupportsSubtreeSigning returns true if the witness is configured to sign subtrees.
func (w *Witness) SupportsSubtreeSigning() bool {
	return len(w.subtreeSigners) > 0
}

func (w *Witness) subtreeVerifiers() []note.Verifier {
	r := make([]note.Verifier, 0, len(w.subtreeSigners))
	for _, ss := range w.subtreeSigners {
		r = append(r, ss.Verifier())
	}
	return r
}

// SignSubtree validates the checkpoint was signed by the witness, verifies the subtree
// consistency proof from the subtree to the checkpoint, and returns a subtree cosignature.
func (w *Witness) SignSubtree(ctx context.Context, start, end uint64, subRoot []byte, cProof [][]byte, chkptRaw []byte) ([]byte, error) {
	// If none of our keys support subtree signing, then bail.
	if len(w.subtreeSigners) == 0 {
		return nil, ErrNotImplemented
	}

	// SPEC: The witness MUST verify that the checkpoint includes a valid cosignature from
	//       one of its own keys.
	//
	// We're a bit tighter here - we'll only proceed if the checkpoint was signed by one of our
	// *subtree-capable* signers.
	n, err := note.Open(chkptRaw, note.VerifierList(w.subtreeVerifiers()...))
	if err != nil {
		return nil, ErrNoWitnessSignature
	}

	var cp log.Checkpoint
	if _, err := cp.Unmarshal([]byte(n.Text)); err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint: %w", err)
	}

	// SPEC: If the checkpoint origin is unknown, the witness MUST respond with a "404 Not Found" HTTP status code.
	_, ok, err := w.VerifierForLog(ctx, cp.Origin)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrUnknownLog
	}

	// SPEC: The half-open interval [start, end) MUST be a valid subtree per draft-ietf-plants-merkle-tree-certs-03, Section 4.1,
	//       and end MUST be less than or equal to the checkpoint size.
	if end > cp.Size {
		return nil, fmt.Errorf("%w: end %d is greater than checkpoint size %d", ErrSubtreeRangeInvalid, end, cp.Size)
	}
	if err := isSubtreeValid(start, end); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSubtreeRangeInvalid, err)
	}

	// SPEC: The client MUST NOT send more than 63 consistency proof lines
	if len(cProof) > 63 {
		return nil, ErrInvalidProof
	}

	// SPEC: The consistency proof lines MUST encode a Subtree Consistency Proof from the subtree to the checkpoint
	//       according to draft-ietf-plants-merkle-tree-certs-03, Section 4.4.
	if err := proof.VerifySubtreeConsistency(rfc6962.DefaultHasher, start, end, cp.Size, cProof, subRoot, cp.Hash); err != nil {
		return nil, ErrInvalidProof
	}

	var sigs bytes.Buffer
	for _, s := range w.subtreeSigners {
		// SPEC: If the cosignature format supports timestamps, the timestamp MUST be zero.
		sig, err := s.SignSubtree(0, cp.Origin, start, end, subRoot)
		if err != nil {
			return nil, fmt.Errorf("couldn't sign subtree: %v", err)
		}

		name := s.Name()
		hash := s.KeyHash()

		var hbuf [4]byte
		binary.BigEndian.PutUint32(hbuf[:], hash)
		b64 := base64.StdEncoding.EncodeToString(append(hbuf[:], sig...))
		_, _ = sigs.WriteString("— ")
		_, _ = sigs.WriteString(name)
		_, _ = sigs.WriteString(" ")
		_, _ = sigs.WriteString(b64)
		_, _ = sigs.WriteString("\n")
	}
	if sigs.Len() == 0 {
		return nil, ErrNotImplemented
	}
	return sigs.Bytes(), nil
}

// isSubtreeValid returns whether a subtree covers a valid range.
// A subtree is valid if there exist a parent tree node to:
// - all the subtree nodes
// - no extra node to the left of the subtree
// - potentially extra nodes to the right of the subtree
func isSubtreeValid(start, end uint64) error {
	if start >= end {
		return fmt.Errorf("start %d must be strictly less than end %d", start, end)
	}
	if start == 0 {
		return nil
	}

	l := end - start

	// special-case large subtree to avoid panic
	if l > uint64(1)<<63 {
		return fmt.Errorf("start %d must be 0 when subtree length %d > 1<<63", start, l)
	}
	if bc := bitCeil(l); start&(bc-1) != 0 {
		return fmt.Errorf("start %d not a multiple of bit_ceil(end - start) = %d", start, bc)
	}

	return nil
}

// bitCeil returns the smallest power of 2 larger than or equal to n.
// MUST NOT be used with n larger than uint64(1)<<63.
func bitCeil(n uint64) uint64 {
	if n <= 1 {
		return 1
	}
	return uint64(1) << bits.Len64(n-1)
}
