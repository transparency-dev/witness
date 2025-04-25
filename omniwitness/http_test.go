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

package omniwitness

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/internal/witness"
)

const (
	testCPOrigin = "transparency.dev/armored-witness/firmware_transparency/ci/2"
	testCPSize   = 56
	testCPRoot   = "7azctENRYLlBCBQ5OX2qxxIKCTOeCda1KfTwjdt0wdA="
	testCPSig    = "— transparency.dev-aw-ftlog-ci-2 93xidocoWXVph2jEuzW2oovU+IjU71+FeVGKtKXQknSla2HCvr6RYHRSdJfxpo4kj5geqxkjrDXcbpiSo7lK96X4Dgc=\n"

	testCPVerifier = "transparency.dev-aw-ftlog-ci-2+f77c6276+AZXqiaARpwF4MoNOxx46kuiIRjrML0PDTm+c7BLaAMt6"
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

func TestHandler(t *testing.T) {
	v, err := note.NewVerifier(testCPVerifier)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	logID := "logID"
	logs := map[string]config.Log{
		logID: config.Log{Origin: testCPOrigin},
	}
	for _, test := range []struct {
		name string
		// fake witness control
		witnessResp []byte
		witnessErr  error
		// responses
		wantBody        string
		wantStatus      int
		wantContentType string
	}{
		{
			name:        "Accepted by witness",
			witnessResp: []byte(testCP),
			wantStatus:  200,
			wantBody:    testCPSig,
		}, {
			name:            "ErrCheckpointStale",
			witnessResp:     []byte(testCP),
			witnessErr:      witness.ErrCheckpointStale,
			wantStatus:      http.StatusConflict,
			wantContentType: "text/x.tlog.size",
			wantBody:        fmt.Sprintf("%d\n", testCPSize),
		}, {
			name:        "ErrNoValidSignature",
			witnessResp: []byte(testCP),
			witnessErr:  witness.ErrNoValidSignature,
			wantStatus:  http.StatusForbidden,
		}, {
			name:        "ErrUnknownLog",
			witnessResp: []byte(testCP),
			witnessErr:  witness.ErrUnknownLog,
			wantStatus:  http.StatusNotFound,
		}, {
			name:        "ErrInvalidProof",
			witnessResp: []byte(testCP),
			witnessErr:  witness.ErrInvalidProof,
			wantStatus:  http.StatusUnprocessableEntity,
		}, {
			name:        "ErrOldSizeInvalid",
			witnessResp: []byte(testCP),
			witnessErr:  witness.ErrOldSizeInvalid,
			wantStatus:  http.StatusBadRequest,
		}, {
			name:        "ErrRootMismatch",
			witnessResp: []byte(testCP),
			witnessErr:  witness.ErrRootMismatch,
			wantStatus:  http.StatusConflict,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := httpHandler{
				w:           &testWitness{updateResponse: test.witnessResp, updateErr: test.witnessErr},
				witVerifier: v,
				logs:        logs,
			}
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			sc, body, ct, err := a.handleUpdate(context.Background(), "logID", testCPOrigin, 0, []byte(testCP), [][]byte{})
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

type testWitness struct {
	latestCPErr    error
	latestCP       []byte
	updateErr      error
	updateResponse []byte
}

func (tw *testWitness) GetLatestCheckpoint(ctx context.Context, logID string) ([]byte, error) {
	return tw.latestCP, tw.latestCPErr
}

func (tw *testWitness) Update(ctx context.Context, logID string, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, error) {
	return tw.updateResponse, tw.updateErr
}

func d64(t *testing.T, s string) []byte {
	t.Helper()
	r, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("Invalid test base64 %q: %v", s, err)
	}
	return r
}
