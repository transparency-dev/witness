// Copyright 2024 Google LLC. All Rights Reserved.
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
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	testCPOrigin = "transparency.dev/armored-witness/firmware_transparency/ci/2"
	testCPSize   = 56
	testCPRoot   = "7azctENRYLlBCBQ5OX2qxxIKCTOeCda1KfTwjdt0wdA="
	testCPSig    = "— transparency.dev-aw-ftlog-ci-2 93xidocoWXVph2jEuzW2oovU+IjU71+FeVGKtKXQknSla2HCvr6RYHRSdJfxpo4kj5geqxkjrDXcbpiSo7lK96X4Dgc=\n"
)

var testCP = fmt.Sprintf("%s\n%d\n%s\n\n%s", testCPOrigin, testCPSize, testCPRoot, testCPSig)

func TestParseBody(t *testing.T) {
	for _, test := range []struct {
		name            string
		body            string
		wantSize        uint64
		wantConsistency [][]byte
		wantCheckpoint  []byte
		wantErr         bool
	}{
		{
			name:            "ok",
			body:            "old 10\nabc=\ndef=\n\n" + testCP,
			wantSize:        10,
			wantConsistency: [][]byte{d64(t, "abc="), d64(t, "def=")},
			wantCheckpoint:  []byte(testCP),
		}, {
			name:    "Invalid previous size",
			body:    "10 stuff\nabc=\ndef=\n\n" + testCP,
			wantErr: true,
		}, {
			name:    "Invalid proof base64",
			body:    "10\nZ043\n423ed\n" + testCP,
			wantErr: true,
		}, {
			name:    "Missing proof terminator line",
			body:    "10\nabc=\ndef=\n" + testCP,
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, c, cp, err := parseBody(bytes.NewBuffer([]byte(test.body)))
			if err != nil {
				if !test.wantErr {
					t.Fatalf("parseBody: %v, want no err", err)
				}
			}
			if got, want := s, test.wantSize; got != want {
				t.Errorf("got size %d, want %d", got, want)
			}
			if got, want := c, test.wantConsistency; !cmp.Equal(got, want) {
				t.Errorf("got proof %x, want %x", got, want)
			}
			if got, want := cp, test.wantCheckpoint; !cmp.Equal(got, want) {
				t.Errorf("got proof %s, want %s", got, want)
			}
		})
	}
}

func TestParseSubtreeBody(t *testing.T) {
	for _, test := range []struct {
		name            string
		body            string
		wantStart       uint64
		wantEnd         uint64
		wantSubRoot     []byte
		wantConsistency [][]byte
		wantCheckpoint  []byte
		wantErr         bool
	}{
		{
			name:            "ok",
			body:            "subtree 8 13\nmbsQCg+dEIMGlpqeGgk94JutQwKKS2Lo5IuDhKmDjiU=\nCD82D2LDm0phY0+xKbHyZfq3Hw21lVkuV7Zis5EFg0k=\n\n" + testCP,
			wantStart:       8,
			wantEnd:         13,
			wantSubRoot:     d64(t, "mbsQCg+dEIMGlpqeGgk94JutQwKKS2Lo5IuDhKmDjiU="),
			wantConsistency: [][]byte{d64(t, "CD82D2LDm0phY0+xKbHyZfq3Hw21lVkuV7Zis5EFg0k=")},
			wantCheckpoint:  []byte(testCP),
		}, {
			name:    "Invalid subtree range line",
			body:    "subtree 8\nmbsQCg+dEIMGlpqeGgk94JutQwKKS2Lo5IuDhKmDjiU=\n\n" + testCP,
			wantErr: true,
		}, {
			name:    "Invalid subroot base64",
			body:    "subtree 8 13\nnot-base64-!!!\n\n" + testCP,
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			start, end, subRoot, proof, cp, err := parseSubtreeBody(bytes.NewBuffer([]byte(test.body)))
			if err != nil {
				if !test.wantErr {
					t.Fatalf("parseSubtreeBody: %v, want no err", err)
				}
				return
			}
			if test.wantErr {
				t.Fatalf("parseSubtreeBody: no err, want err")
			}
			if got, want := start, test.wantStart; got != want {
				t.Errorf("got start %d, want %d", got, want)
			}
			if got, want := end, test.wantEnd; got != want {
				t.Errorf("got end %d, want %d", got, want)
			}
			if got, want := subRoot, test.wantSubRoot; !cmp.Equal(got, want) {
				t.Errorf("got subRoot %x, want %x", got, want)
			}
			if got, want := proof, test.wantConsistency; !cmp.Equal(got, want) {
				t.Errorf("got proof %x, want %x", got, want)
			}
			if got, want := cp, test.wantCheckpoint; !cmp.Equal(got, want) {
				t.Errorf("got checkpoint %s, want %s", got, want)
			}
		})
	}
}

func TestHandler(t *testing.T) {
	for _, test := range []struct {
		name string
		// fake witness control
		witness *testWitness
		// responses
		wantBody        string
		wantStatus      int
		wantContentType string
	}{
		{
			name:       "Accepted by witness",
			witness:    &testWitness{updateResponse: []byte(testCPSig)},
			wantStatus: 200,
			wantBody:   testCPSig,
		}, {
			name:            "ErrCheckpointStale",
			witness:         &testWitness{updateErr: ErrCheckpointStale, updateSize: testCPSize},
			wantStatus:      http.StatusConflict,
			wantContentType: "text/x.tlog.size",
			wantBody:        fmt.Sprintf("%d\n", testCPSize),
		}, {
			name:       "ErrNoValidSignature",
			witness:    &testWitness{updateErr: ErrNoValidSignature},
			wantStatus: http.StatusForbidden,
		}, {
			name:       "ErrUnknownLog",
			witness:    &testWitness{updateErr: ErrUnknownLog},
			wantStatus: http.StatusNotFound,
		}, {
			name:       "ErrInvalidProof",
			witness:    &testWitness{updateErr: ErrInvalidProof},
			wantStatus: http.StatusUnprocessableEntity,
		}, {
			name:       "ErrOldSizeInvalid",
			witness:    &testWitness{updateErr: ErrOldSizeInvalid},
			wantStatus: http.StatusBadRequest,
		}, {
			name:       "ErrInvalidCheckpoint",
			witness:    &testWitness{updateErr: ErrInvalidCheckpoint},
			wantStatus: http.StatusBadRequest,
		}, {
			name:       "ErrBadRequest",
			witness:    &testWitness{updateErr: ErrBadRequest},
			wantStatus: http.StatusBadRequest,
		}, {
			name:       "ErrRootMismatch",
			witness:    &testWitness{updateErr: ErrRootMismatch},
			wantStatus: http.StatusUnprocessableEntity,
		}, {
			name:       "ErrPushback",
			witness:    &testWitness{updateErr: ErrPushback},
			wantStatus: http.StatusTooManyRequests,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sc, body, ct, err := handleUpdate(context.Background(), test.witness.Update, 0, []byte(testCP), [][]byte{})
			if err != nil {
				t.Fatalf("handleUpdate: %v", err)
			}
			if got, want := sc, test.wantStatus; got != want {
				t.Errorf("handleUpdate got status %d, want %d", got, want)
			}
			if got, want := ct, test.wantContentType; got != want {
				t.Errorf("handleUpdate got content type %q, want %q", got, want)
			}
			if got, want := string(body), test.wantBody; got != want {
				t.Errorf("handleUpdate got body %q, %q", got, want)
			}
		})
	}
}

// TestHandlerAgainstRealWitness drives handleUpdate with a real Witness rather than a fake.
//
// TestHandler above injects sentinels directly, so it verifies the switch statement but cannot detect
// a sentinel that Update never actually returns. These cases pin the status codes the spec mandates
// to the errors the witness genuinely produces.
func TestHandlerAgainstRealWitness(t *testing.T) {
	testRoot := dh("e35b268c1522014ef412d2a54fa94838862d453631617b0307e5c77dcbeefc11", 32)
	goodCP := mustCreateCheckpoint(t, mSK, "monkeys", 5, testRoot)

	for _, test := range []struct {
		name       string
		cp         []byte
		wantStatus int
	}{
		{
			name:       "valid checkpoint",
			cp:         goodCP,
			wantStatus: http.StatusOK,
		}, {
			// SPEC: If none of the signatures verify against any of the trusted public keys, the
			//       witness MUST respond with a "403 Forbidden" HTTP status code.
			name:       "signature doesn't verify",
			cp:         mustCorruptSignature(t, goodCP),
			wantStatus: http.StatusForbidden,
		}, {
			name:       "signed only by an untrusted key",
			cp:         mustCreateCheckpoint(t, bSK, "monkeys", 5, testRoot),
			wantStatus: http.StatusForbidden,
		}, {
			// SPEC: If the checkpoint origin is unknown, the witness MUST respond with a "404 Not
			//       Found" HTTP status code.
			name:       "unknown origin",
			cp:         mustCreateCheckpoint(t, bSK, "bananas", 5, testRoot),
			wantStatus: http.StatusNotFound,
		}, {
			name:       "malformed checkpoint",
			cp:         []byte("monkeys\nthis is not a checkpoint\n"),
			wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := newWitness(t, []logOpts{{origin: "monkeys", PK: mPK}})

			sc, _, _, err := handleUpdate(t.Context(), w.Update, 0, test.cp, nil)
			if err != nil {
				t.Fatalf("handleUpdate: %v", err)
			}
			if got, want := sc, test.wantStatus; got != want {
				t.Errorf("handleUpdate got status %d, want %d", got, want)
			}
		})
	}
}

func TestSubtreeHandler(t *testing.T) {
	for _, test := range []struct {
		name string
		// fake witness control
		witness *testWitness
		// responses
		wantStatus      int
		wantBody        string
		wantContentType string
	}{
		{
			name:       "Accepted by witness",
			witness:    &testWitness{signSubtreeResponse: []byte(testCPSig)},
			wantStatus: 200,
			wantBody:   testCPSig,
		}, {
			name:       "ErrUnknownLog",
			witness:    &testWitness{signSubtreeErr: ErrUnknownLog},
			wantStatus: http.StatusNotFound,
		}, {
			name:       "ErrNoWitnessSignature",
			witness:    &testWitness{signSubtreeErr: ErrNoWitnessSignature},
			wantStatus: http.StatusForbidden,
		}, {
			name:       "ErrSubtreeRangeInvalid",
			witness:    &testWitness{signSubtreeErr: ErrSubtreeRangeInvalid},
			wantStatus: http.StatusBadRequest,
		}, {
			name:       "ErrInvalidCheckpoint",
			witness:    &testWitness{signSubtreeErr: ErrInvalidCheckpoint},
			wantStatus: http.StatusBadRequest,
		}, {
			name:       "ErrBadRequest",
			witness:    &testWitness{signSubtreeErr: ErrBadRequest},
			wantStatus: http.StatusBadRequest,
		}, {
			name:       "ErrInvalidProof",
			witness:    &testWitness{signSubtreeErr: ErrInvalidProof},
			wantStatus: http.StatusUnprocessableEntity,
		}, {
			name:       "ErrNotImplemented",
			witness:    &testWitness{signSubtreeErr: ErrNotImplemented},
			wantStatus: http.StatusNotImplemented,
		}, {
			name:       "ErrPushback",
			witness:    &testWitness{signSubtreeErr: ErrPushback},
			wantStatus: http.StatusTooManyRequests,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sc, body, ct, err := handleSignSubtree(context.Background(), test.witness.SignSubtree, 0, 1, []byte{}, [][]byte{}, []byte(testCP))
			if err != nil {
				t.Fatalf("handleSignSubtree: %v", err)
			}
			if got, want := sc, test.wantStatus; got != want {
				t.Errorf("handleSignSubtree got status %d, want %d", got, want)
			}
			if got, want := ct, test.wantContentType; got != want {
				t.Errorf("handleSignSubtree got content type %q, want %q", got, want)
			}
			if got, want := string(body), test.wantBody; got != want {
				t.Errorf("handleSignSubtree got body %q, %q", got, want)
			}
		})
	}
}

// TestSubtreeHandlerAgainstRealWitness drives handleSignSubtree with a real Witness rather than a fake.
//
// As with TestHandlerAgainstRealWitness, injecting sentinels only verifies the switch statement: these
// cases pin the status codes the spec mandates to the errors SignSubtree genuinely produces.
func TestSubtreeHandlerAgainstRealWitness(t *testing.T) {
	ctx := t.Context()
	w := newSubtreeWitness(t, []logOpts{{origin: "monkeys", PK: mPK}})

	// Build a size 2 log checkpoint, and have the witness cosign it.
	d0, d1 := make([]byte, 32), make([]byte, 32)
	d0[0], d1[0] = 0xaa, 0xbb
	root := rfc6962.DefaultHasher.HashChildren(d0, d1)
	logCp := mustCreateCheckpoint(t, mSK, "monkeys", 2, root)
	sigs, _, err := w.Update(ctx, 0, logCp, nil)
	if err != nil {
		t.Fatalf("failed to update witness checkpoint: %v", err)
	}
	cosignedCp := append(bytes.Clone(logCp), sigs...)

	for _, test := range []struct {
		name       string
		cp         []byte
		wantStatus int
	}{
		{
			name:       "witness cosigned checkpoint",
			cp:         cosignedCp,
			wantStatus: http.StatusOK,
		}, {
			// SPEC: The witness MUST verify that the checkpoint includes a valid cosignature from one
			//       of its own keys. If the witness can't verify the checkpoint, it MUST respond with
			//       a "403 Forbidden" HTTP status code.
			name:       "witness cosignature doesn't verify",
			cp:         mustCorruptSignature(t, cosignedCp),
			wantStatus: http.StatusForbidden,
		}, {
			name:       "signed only by the log",
			cp:         logCp,
			wantStatus: http.StatusForbidden,
		}, {
			// SPEC: If the request is invalid according to the rules above, the witness MUST respond
			//       with a "400 Bad Request" HTTP status code.
			name:       "not a note",
			cp:         []byte("monkeys\nthis is not a checkpoint\n"),
			wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sc, _, _, err := handleSignSubtree(ctx, w.SignSubtree, 0, 1, d0, [][]byte{d1}, test.cp)
			if err != nil {
				t.Fatalf("handleSignSubtree: %v", err)
			}
			if got, want := sc, test.wantStatus; got != want {
				t.Errorf("handleSignSubtree got status %d, want %d", got, want)
			}
		})
	}
}

type testWitness struct {
	latestCPErr         error
	latestCP            []byte
	updateErr           error
	updateSize          uint64
	updateResponse      []byte
	signSubtreeResponse []byte
	signSubtreeErr      error
}

func (tw *testWitness) GetLatestCheckpoint(ctx context.Context, logID string) ([]byte, error) {
	return tw.latestCP, tw.latestCPErr
}

func (tw *testWitness) Update(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error) {
	return tw.updateResponse, tw.updateSize, tw.updateErr
}

func (tw *testWitness) SignSubtree(ctx context.Context, start, end uint64, subRoot []byte, proof [][]byte, cp []byte) ([]byte, error) {
	return tw.signSubtreeResponse, tw.signSubtreeErr
}

func d64(t *testing.T, s string) []byte {
	t.Helper()
	r, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("Invalid test base64 %q: %v", s, err)
	}
	return r
}
