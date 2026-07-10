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
			a := HTTPHandler{
				witness: test.witness,
			}
			sc, body, ct, err := a.handleUpdate(context.Background(), 0, []byte(testCP), [][]byte{})
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
			a := HTTPHandler{
				witness: test.witness,
			}
			sc, body, ct, err := a.handleSignSubtree(context.Background(), 0, 1, []byte{}, [][]byte{}, []byte(testCP))
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
