// Copyright 2026 Google LLC. All Rights Reserved.
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

package http

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/witness/api"
	"github.com/transparency-dev/witness/witness"
)

const (
	testCPOrigin = "example.com/test-log"
	testCPSize   = 14
	testCPRoot   = "/CcKVZM9n65aH7jLaIZuUB4/MSlEFQ4+ldwUC21rDHM="
	testCPSig    = "— witness.example/w1 LijDAFSpKvDUj+ZtaJ4lUVcnvnooXd\n"
)

var testCP = fmt.Sprintf("%s\n%d\n%s\n\n%s", testCPOrigin, testCPSize, testCPRoot, testCPSig)

func TestSignSubtree(t *testing.T) {
	subRoot := []byte("12345678901234567890123456789012")
	proof := [][]byte{
		[]byte("abcdefghijklmnopqrstuvwxyz123456"),
		[]byte("0123456789abcdef0123456789abcdef"),
	}
	cp := []byte(testCP)
	wantSig := []byte("— witness.example/w1 GuvvwNqqDmhh5OoDEJyEWiNUB2F1vR\n")

	for _, tc := range []struct {
		name       string
		start      uint64
		end        uint64
		subRoot    []byte
		proof      [][]byte
		cp         []byte
		handler    http.HandlerFunc
		wantBody   []byte
		wantErr    error
		wantErrMsg string
	}{
		{
			name:    "ok",
			start:   8,
			end:     13,
			subRoot: subRoot,
			proof:   proof,
			cp:      cp,
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("got method %s, want POST", r.Method)
				}
				if r.URL.Path != api.HTTPSignSubtree {
					t.Errorf("got path %s, want %s", r.URL.Path, api.HTTPSignSubtree)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("failed to read request body: %v", err)
				}
				expectedBody := fmt.Sprintf("subtree 8 13\n%s\n%s\n%s\n\n%s",
					base64.StdEncoding.EncodeToString(subRoot),
					base64.StdEncoding.EncodeToString(proof[0]),
					base64.StdEncoding.EncodeToString(proof[1]),
					string(cp),
				)
				if got, want := string(body), expectedBody; got != want {
					t.Errorf("request body mismatch:\ngot:\n%s\nwant:\n%s", got, want)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(wantSig)
			},
			wantBody: wantSig,
		},
		{
			name:       "too many proof lines",
			start:      8,
			end:        13,
			subRoot:    subRoot,
			proof:      make([][]byte, 64),
			cp:         cp,
			wantErrMsg: "too many proof lines",
		},
		{
			name:    "400 Bad Request",
			start:   8,
			end:     13,
			subRoot: subRoot,
			proof:   proof,
			cp:      cp,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
			wantErr: witness.ErrSubtreeRangeInvalid,
		},
		{
			name:    "403 Forbidden",
			start:   8,
			end:     13,
			subRoot: subRoot,
			proof:   proof,
			cp:      cp,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			wantErr: witness.ErrNoWitnessSignature,
		},
		{
			name:    "404 Not Found",
			start:   8,
			end:     13,
			subRoot: subRoot,
			proof:   proof,
			cp:      cp,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr: witness.ErrUnknownLog,
		},
		{
			name:    "422 Unprocessable Entity",
			start:   8,
			end:     13,
			subRoot: subRoot,
			proof:   proof,
			cp:      cp,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnprocessableEntity)
			},
			wantErr: witness.ErrInvalidProof,
		},
		{
			name:    "429 Too Many Requests",
			start:   8,
			end:     13,
			subRoot: subRoot,
			proof:   proof,
			cp:      cp,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantErr: witness.ErrPushback,
		},
		{
			name:    "501 Not Implemented",
			start:   8,
			end:     13,
			subRoot: subRoot,
			proof:   proof,
			cp:      cp,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotImplemented)
			},
			wantErr: witness.ErrNotImplemented,
		},
		{
			name:    "500 Internal Server Error",
			start:   8,
			end:     13,
			subRoot: subRoot,
			proof:   proof,
			cp:      cp,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErrMsg: "unexpected status code 500",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var u *url.URL
			if tc.handler != nil {
				server := httptest.NewServer(tc.handler)
				defer server.Close()
				var err error
				u, err = url.Parse(server.URL)
				if err != nil {
					t.Fatalf("failed to parse test server url: %v", err)
				}
			} else {
				u, _ = url.Parse("http://localhost:2026")
			}

			client := NewWitness(u, http.DefaultClient)
			gotBody, err := client.SignSubtree(t.Context(), tc.start, tc.end, tc.subRoot, tc.proof, tc.cp)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("got error %v, want %v", err, tc.wantErr)
				}
				return
			}
			if tc.wantErrMsg != "" {
				if err == nil || !bytes.Contains([]byte(err.Error()), []byte(tc.wantErrMsg)) {
					t.Errorf("got error %v, want error containing %q", err, tc.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("SignSubtree unexpected error: %v", err)
			}
			if !cmp.Equal(gotBody, tc.wantBody) {
				t.Errorf("SignSubtree got body %q, want %q", gotBody, tc.wantBody)
			}
		})
	}
}
