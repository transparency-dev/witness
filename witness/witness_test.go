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

package witness

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

var (
	// https://go.dev/play/p/FVJgyhl7URt to regenerate any messages if needed.
	mPK       = "monkeys+db4d9f7e+AULaJMvTtDLHPUcUrjdDad9vDlh/PTfC2VV60JUtCfWT"
	mSK       = "PRIVATE+KEY+monkeys+db4d9f7e+ATWIAF3yVBG+Hv1rZFQoNt/BaURkLPtOFMAM2HrEeIr6"
	bPK       = "bananas+cf639f13+AaPjhFnPCQnid/Ql32KWhmh+uk72FVRfK+2DLmO3BI3M"
	bSK       = "PRIVATE+KEY+bananas+cf639f13+AdjzytHoXdvn+1vG2UXXqFR3LZ+kvnmQZFretRaKfTIu"
	wPK       = "witness+f13a86db+AdYV1Ztajd9BvyjP2HgpwrqYL6TjOwIjGMOq8Bu42xbN"
	wSK       = "PRIVATE+KEY+witness+f13a86db+AaLa/dfyBhyo/m0Z7WCi98ENVZWtrP8pxgRNrx7tIWiA"
	mInit     = []byte("monkeys\n5\n41smjBUiAU70EtKlT6lIOIYtRTYxYXsDB+XHfcvu/BE=\n\n— monkeys 202fftzGl3LVoqjXfwCFZZXs8I+5G22+Ek2K0AOyBuSJ/8/CZawNF+6fNlTKOCd622pbzJNkkJFWuw9DbicZCkEx9AY=\n")
	mNext     = []byte("monkeys\n8\nV8K9aklZ4EPB+RMOk1/8VsJUdFZR77GDtZUQq84vSbo=\n\n— monkeys 202ffoUEboiQYpHzICeaFmoy3RNviHTpAxYrq/eO4QQVQMvu9UebKBMX2MJC76NLthZaKsnKbCA8GxrjePZhvDCH7Ag=\n")
	consProof = [][]byte{
		dh("b9e1d62618f7fee8034e4c5010f727ab24d8e4705cb296c374bf2025a87a10d2", 32),
		dh("aac66cd7a79ce4012d80762fe8eec3a77f22d1ca4145c3f4cee022e7efcd599d", 32),
		dh("89d0f753f66a290c483b39cd5e9eafb12021293395fad3d4a2ad053cfbcfdc9e", 32),
		dh("29e40bb79c966f4c6fe96aff6f30acfce5f3e8d84c02215175d6e018a5dee833", 32),
	}

	_ = mSK
	_ = bSK
)

type logOpts struct {
	origin string
	PK     string
}

type cfg map[string]note.Verifier

func (c *cfg) Log(_ context.Context, origin string) (note.Verifier, bool, error) {
	id := log.ID(origin)
	v, ok := (*c)[id]
	return v, ok, nil
}

func newWitness(t *testing.T, logs []logOpts) *Witness {
	// Set up Opts for the witness.
	ns, err := f_note.NewSignerForCosignatureV1(wSK)
	if err != nil {
		t.Fatalf("couldn't create a witness signer: %v", err)
	}
	logMap := make(cfg)
	for _, l := range logs {
		logV, err := note.NewVerifier(l.PK)
		if err != nil {
			t.Fatalf("couldn't create a log verifier: %v", err)
		}
		logMap[log.ID(l.origin)] = logV
	}
	opts := Opts{
		Persistence:    newPersistence(),
		Signers:        []note.Signer{ns},
		VerifierForLog: logMap.Log,
	}
	// Create the witness
	w, err := New(t.Context(), opts)
	if err != nil {
		t.Fatalf("couldn't create witness: %v", err)
	}
	return w
}

// dh is taken from https://github.com/google/trillian/blob/master/merkle/logverifier/log_verifier_test.go.
func dh(h string, expLen int) []byte {
	r, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	if got := len(r); got != expLen {
		panic(fmt.Sprintf("decode %q: len=%d, want %d", h, got, expLen))
	}
	return r
}

func TestGetChkpt(t *testing.T) {
	for _, test := range []struct {
		desc        string
		setOrigin   string
		setPK       string
		queryOrigin string
		queryPK     string
		c           []byte
		wantThere   bool
	}{
		{
			desc:        "happy path",
			setOrigin:   "monkeys",
			setPK:       mPK,
			queryOrigin: "monkeys",
			queryPK:     mPK,
			c:           mInit,
			wantThere:   true,
		}, {
			desc:        "other log",
			setOrigin:   "monkeys",
			setPK:       mPK,
			queryOrigin: "bananas",
			queryPK:     bPK,
			c:           mInit,
			wantThere:   false,
		}, {
			desc:        "nothing there",
			setOrigin:   "monkeys",
			setPK:       mPK,
			queryOrigin: "monkeys",
			queryPK:     mPK,
			c:           nil,
			wantThere:   false,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			ctx := context.Background()
			// Set up witness.
			w := newWitness(t, []logOpts{{
				origin: test.setOrigin,
				PK:     test.setPK,
			}})
			// Set a checkpoint for the log if we want to for this test.
			if test.c != nil {
				if _, _, err := w.Update(ctx, 0, test.c, nil); err != nil {
					t.Errorf("failed to set checkpoint: %v", err)
				}
			}
			// Try to get the latest checkpoint.
			cosigned, err := w.GetCheckpoint(ctx, test.queryOrigin)
			if !test.wantThere && err == nil && cosigned != nil {
				t.Fatalf("returned a checkpoint but shouldn't have: %v", cosigned)
			}
			// If we got something then verify it under the log and
			// witness public keys.
			if test.wantThere {
				if err != nil {
					t.Errorf("failed to get latest: %v", err)
				}
				wV, err := f_note.NewVerifierForCosignatureV1(wPK)
				if err != nil {
					t.Fatalf("couldn't create a witness verifier: %v", err)
				}
				logV, err := note.NewVerifier(test.queryPK)
				if err != nil {
					t.Fatalf("couldn't create a log verifier: %v", err)
				}
				n, err := note.Open(cosigned, note.VerifierList(logV, wV))
				if err != nil {
					t.Fatalf("couldn't verify the co-signed checkpoint: %v", err)
				}
				if len(n.Sigs) != 2 {
					t.Fatalf("checkpoint doesn't verify under enough keys")
				}
			}
		})
	}
}

func mustCreateCheckpoint(t *testing.T, sk string, origin string, size uint64, rootHash []byte) []byte {
	t.Helper()
	cp := log.Checkpoint{
		Origin: origin,
		Size:   size,
		Hash:   rootHash,
	}
	signer, err := note.NewSigner(sk)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := note.Sign(&note.Note{Text: string(cp.Marshal())}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestUpdate(t *testing.T) {
	for _, test := range []struct {
		desc      string
		origin    string
		initC     []byte
		oldSize   uint64
		newC      []byte
		pf        [][]byte
		isGood    bool
		wantError error
	}{
		{
			desc:    "vanilla consistency happy path",
			origin:  "monkeys",
			initC:   mustCreateCheckpoint(t, mSK, "monkeys", 5, dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			oldSize: 5,
			newC:    mNext,
			pf:      consProof,
			isGood:  true,
		}, {
			desc:    "valid zero size hash",
			origin:  "monkeys",
			initC:   mustCreateCheckpoint(t, mSK, "monkeys", 0, rfc6962.DefaultHasher.EmptyRoot()),
			oldSize: 0,
			newC:    mustCreateCheckpoint(t, mSK, "monkeys", 0, rfc6962.DefaultHasher.EmptyRoot()),
			isGood:  true,
		}, {
			desc:      "invalid zero size hash",
			origin:    "monkeys",
			initC:     mustCreateCheckpoint(t, mSK, "monkeys", 0, rfc6962.DefaultHasher.EmptyRoot()),
			oldSize:   0,
			newC:      mustCreateCheckpoint(t, mSK, "monkeys", 0, dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			wantError: ErrRootMismatch,
		}, {
			desc:      "oldSize doesn't match current state",
			origin:    "monkeys",
			initC:     mustCreateCheckpoint(t, mSK, "monkeys", 5, dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			oldSize:   2,
			newC:      mNext,
			isGood:    false,
			wantError: ErrCheckpointStale,
		}, {
			desc:    "vanilla consistency starting from tree size 0 with proof",
			origin:  "monkeys",
			initC:   mustCreateCheckpoint(t, mSK, "monkeys", 0, rfc6962.DefaultHasher.EmptyRoot()),
			oldSize: 0,
			newC:    mustCreateCheckpoint(t, mSK, "monkeys", 5, dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			pf:      consProof,
			// Proof should be empty.
			isGood: false,
		}, {
			desc:      "vanilla consistency starting from tree size 0 without proof",
			origin:    "monkeys",
			initC:     mustCreateCheckpoint(t, mSK, "monkeys", 0, rfc6962.DefaultHasher.EmptyRoot()),
			oldSize:   0,
			newC:      mustCreateCheckpoint(t, mSK, "monkeys", 5, dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			pf:        [][]byte{{2}},
			wantError: ErrInvalidProof,
		}, {
			desc:    "vanilla resubmit known CP",
			origin:  "monkeys",
			initC:   mustCreateCheckpoint(t, mSK, "monkeys", 5, dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			oldSize: 5,
			newC:    mustCreateCheckpoint(t, mSK, "monkeys", 5, dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			isGood:  true,
		}, {
			desc:      "resubmit known CP with changed root",
			origin:    "monkeys",
			initC:     mustCreateCheckpoint(t, mSK, "monkeys", 5, dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			oldSize:   5,
			newC:      mustCreateCheckpoint(t, mSK, "monkeys", 5, dh("fffffffffffffffef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			wantError: ErrRootMismatch,
		}, {
			desc:      "missing proof",
			origin:    "monkeys",
			initC:     mustCreateCheckpoint(t, mSK, "monkeys", 4, dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			oldSize:   4,
			newC:      mustCreateCheckpoint(t, mSK, "monkeys", 5, dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)),
			pf:        [][]byte{},
			wantError: ErrInvalidProof,
		}, {
			desc:      "submit smaller checkpoint",
			initC:     mNext,
			oldSize:   8,
			newC:      mInit,
			pf:        consProof,
			wantError: ErrOldSizeInvalid,
		}, {
			desc:    "vanilla consistency garbage proof",
			initC:   mInit,
			oldSize: 5,
			newC:    mNext,
			pf: [][]byte{
				dh("aaaa", 2),
				dh("bbbb", 2),
				dh("cccc", 2),
				dh("dddd", 2),
			},
			wantError: ErrInvalidProof,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			ctx := context.Background()
			// Set up witness.
			w := newWitness(t, []logOpts{{
				origin: "monkeys",
				PK:     mPK,
			}})
			// Set an initial checkpoint for the log.
			if _, _, err := w.Update(ctx, 0, test.initC, nil); err != nil {
				t.Errorf("failed to set checkpoint: %v", err)
			}
			// Now update from this checkpoint to a newer one.
			_, _, err := w.Update(ctx, test.oldSize, test.newC, test.pf)
			if test.isGood {
				if err != nil {
					t.Fatalf("can't update to new checkpoint: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("should have gotten an error but didn't")
				}
				if test.wantError != nil {

					if !errors.Is(err, test.wantError) {
						t.Fatalf("Got error %v, want %v", err, test.wantError)
					}
				}
			}
		})
	}
}

func newPersistence() *testPersistence {
	return &testPersistence{
		checkpoints: make(map[string][]byte),
	}
}

type testPersistence struct {
	mu          sync.RWMutex
	checkpoints map[string][]byte
}

func (p *testPersistence) Init(_ context.Context) error {
	return nil
}

func (p *testPersistence) Latest(_ context.Context, origin string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	logID := log.ID(origin)
	return p.checkpoints[logID], nil
}

func (p *testPersistence) Update(_ context.Context, origin string, f func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	logID := log.ID(origin)
	u, err := f(p.checkpoints[logID])
	if err != nil {
		return err
	}

	bits := bytes.Split(u, []byte{'\n'})
	if len(bits) == 0 {
		return errors.New("invalid checkpoint")
	}
	if co := string(bits[0]); origin != co {
		return fmt.Errorf("origin mismatch, %q != %q", origin, co)
	}

	p.checkpoints[logID] = u
	return nil
}

func TestSignSubtree(t *testing.T) {
	ctx := t.Context()

	const signerPrefix = "witness-mldsa"
	ns1 := mustCreateMLDSACosigner(t, fmt.Sprintf("%s-1", signerPrefix))
	ns2 := mustCreateMLDSACosigner(t, fmt.Sprintf("%s-2", signerPrefix))

	// Setup log verifier.
	logMap := make(cfg)
	logV, err := note.NewVerifier(mPK)
	if err != nil {
		t.Fatalf("failed to create log verifier: %v", err)
	}
	logMap[log.ID("monkeys")] = logV

	w, err := New(ctx, Opts{
		Persistence:          newPersistence(),
		EnableSubtreeSigning: true,
		Signers:              []note.Signer{ns1, ns2},
		VerifierForLog:       logMap.Log,
	})
	if err != nil {
		t.Fatalf("failed to create witness: %v", err)
	}

	// Create a log checkpoint of size 2.
	d0 := make([]byte, 32)
	d0[0] = 0xaa
	d1 := make([]byte, 32)
	d1[0] = 0xbb
	root := rfc6962.DefaultHasher.HashChildren(d0, d1)

	logCp := mustCreateCheckpoint(t, mSK, "monkeys", 2, root)

	// Let the witness sign it (update to size 2).
	sigs, _, err := w.Update(ctx, 0, logCp, nil)
	if err != nil {
		t.Fatalf("failed to update witness checkpoint: %v", err)
	}
	cosignedCp := append(bytes.Clone(logCp), sigs...)

	// Prepare unknown-log checkpoint signed by witness.
	unknownLogCp := mustCreateCheckpoint(t, mSK, "unknown-log", 2, root)
	n, err := note.Open(unknownLogCp, note.VerifierList(logV))
	if err != nil {
		t.Fatal(err)
	}
	wSigned, _, err := w.signChkpt(n)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		start   uint64
		end     uint64
		subRoot []byte
		proof   [][]byte
		chkpt   []byte
		wantErr error
	}{
		{
			name:    "success",
			start:   0,
			end:     1,
			subRoot: d0,
			proof:   [][]byte{d1},
			chkpt:   cosignedCp,
			wantErr: nil,
		}, {
			name:    "success - multi subtree-signers",
			start:   0,
			end:     1,
			subRoot: d0,
			proof:   [][]byte{d1},
			chkpt:   cosignedCp,
			wantErr: nil,
		}, {
			name:    "unknown log",
			start:   0,
			end:     1,
			subRoot: d0,
			proof:   [][]byte{d1},
			chkpt:   wSigned,
			wantErr: ErrUnknownLog,
		}, {
			name:    "no witness signature",
			start:   0,
			end:     1,
			subRoot: d0,
			proof:   [][]byte{d1},
			chkpt:   logCp,
			wantErr: ErrNoWitnessSignature,
		},
		{
			name:    "invalid subtree range (start >= end)",
			start:   1,
			end:     1,
			subRoot: d0,
			proof:   [][]byte{d1},
			chkpt:   cosignedCp,
			wantErr: ErrSubtreeRangeInvalid,
		}, {
			name:    "invalid subtree range (end > cp.Size)",
			start:   0,
			end:     3,
			subRoot: d0,
			proof:   [][]byte{d1},
			chkpt:   cosignedCp,
			wantErr: ErrSubtreeRangeInvalid,
		}, {
			name:    "invalid proof",
			start:   0,
			end:     1,
			subRoot: d0,
			proof:   [][]byte{make([]byte, 32)},
			chkpt:   cosignedCp,
			wantErr: ErrInvalidProof,
		}, {
			name:    "too many proof lines",
			start:   0,
			end:     1,
			subRoot: d0,
			proof:   make([][]byte, 64),
			chkpt:   cosignedCp,
			wantErr: ErrInvalidProof,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sigs, err := w.SignSubtree(ctx, tc.start, tc.end, tc.subRoot, tc.proof, tc.chkpt)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
			if tc.wantErr != nil {
				return
			}

			// Returned signatures should be note signatures.
			lines := bytes.Split(bytes.TrimSpace(sigs), []byte("\n"))
			if len(lines) == 0 {
				t.Fatalf("expected at least one signature line and a trailing newline, got: %q", sigs)
			}

			vs := make(map[string]f_note.SubtreeVerifier)
			for _, s := range w.subtreeSigners {
				vs[s.Name()] = s.Verifier()
			}
			// Verify the returned subtree signature(s)
			for _, s := range lines {
				sigLine := string(s)
				bits := strings.Split(sigLine, " ")
				if len(bits) != 3 {
					t.Fatalf("unexpected signature line format: %q, want 3 parts", sigLine)
				}
				if bits[0] != "—" {
					t.Fatalf("unexpected signature line format: %q, want prefix %q", sigLine, "—")
				}
				signerName := bits[1]
				b64sig := bits[2]
				sigBytes, err := base64.StdEncoding.DecodeString(b64sig)
				if err != nil {
					t.Fatalf("failed to decode base64 signature: %v", err)
				}
				// The signature bytes contain keyHash (4 bytes) + sig.
				if len(sigBytes) < 4 {
					t.Fatalf("signature too short: %d bytes", len(sigBytes))
				}
				// Ignore the hash.
				actualSig := sigBytes[4:]

				// Now verify the subtree signature.
				verifier, ok := vs[signerName]
				if !ok {
					t.Fatalf("no verifier found for name %q", signerName)
				}
				// SPEC: If the cosignature format supports timestamps, the timestamp MUST be zero.
				if !verifier.VerifySubtree(0, "monkeys", tc.start, tc.end, tc.subRoot, actualSig) {
					t.Fatalf("subtree signature verification failed")
				}
			}
		})
	}
}

func mustCreateMLDSACosigner(t *testing.T, name string) f_note.SubtreeSigner {
	skey, _, err := f_note.GenerateMLDSAKey(name)
	if err != nil {
		t.Fatalf("failed to generate MLDSA key: %v", err)
	}

	// Create subtree signer.
	ns, err := f_note.NewMLDSASigner(skey)
	if err != nil {
		t.Fatalf("failed to create MLDSA signer: %v", err)
	}

	return ns
}
