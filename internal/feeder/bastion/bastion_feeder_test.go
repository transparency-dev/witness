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

package bastion

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const (
	testCP = "56\n7azctENRYLlBCBQ5OX2qxxIKCTOeCda1KfTwjdt0wdA=\n\n— transparency.dev-aw-ftlog-ci-2 93xidocoWXVph2jEuzW2oovU+IjU71+FeVGKtKXQknSla2HCvr6RYHRSdJfxpo4kj5geqxkjrDXcbpiSo7lK96X4Dgc=\n"
)

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

func d64(t *testing.T, s string) []byte {
	t.Helper()
	r, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("Invalid test base64 %q: %v", s, err)
	}
	return r
}
