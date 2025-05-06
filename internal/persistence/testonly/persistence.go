// Copyright 2022 Google LLC. All Rights Reserved.
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

package persistence

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/witness/internal/persistence"
)

// TestLogs exposes a test that can be invoked by tests for specific implementations of persistence.
func TestLogs(t *testing.T, lspFactory func() (persistence.LogStatePersistence, func() error)) {
	t.Helper()

	lsp, close := lspFactory()
	defer func() {
		if err := close(); err != nil {
			t.Fatalf("close(): %v", err)
		}
	}()
	if err := lsp.Init(); err != nil {
		t.Fatalf("Init(): %v", err)
	}
	if logs, err := lsp.Logs(); err != nil {
		t.Errorf("Logs(): %v", err)
	} else if got, want := len(logs), 0; got != want {
		t.Errorf("got %d logs, want %d", got, want)
	}

	newCP := []byte("foo CP")
	if err := checkAndSet(lsp, "foo", nil, newCP); err != nil {
		t.Fatal(err)
	}

	if logs, err := lsp.Logs(); err != nil {
		t.Errorf("Logs(): %v", err)
	} else if got, want := logs, []string{"foo"}; !cmp.Equal(got, want) {
		t.Errorf("got != want (%v != %v)", got, want)
	}
}

// TestUpdate exposes a test that can be invoked by tests for specific implementations of persistence.
func TestUpdate(t *testing.T, lspFactory func() (persistence.LogStatePersistence, func() error)) {
	t.Helper()

	lsp, close := lspFactory()
	defer func() {
		if err := close(); err != nil {
			t.Fatalf("close(): %v", err)
		}
	}()
	if err := lsp.Init(); err != nil {
		t.Fatalf("Init(): %v", err)
	}

	newCP := []byte("foo cp")
	if err := checkAndSet(lsp, "foo", nil, newCP); err != nil {
		t.Fatalf("checkAndSet(nil, %s): %v", newCP, err)

	}

	cpRaw, err := lsp.Latest("foo")
	if err != nil {
		t.Fatalf("Latest(): %v", err)
	}
	if got, want := cpRaw, []byte("foo cp"); !bytes.Equal(got, want) {
		t.Errorf("got != want (%s != %s)", got, want)
	}
}

func checkAndSet(lsp persistence.LogStatePersistence, id string, expect []byte, write []byte) error {
	if err := lsp.Update(id, func(current []byte) ([]byte, error) {
		if !bytes.Equal(current, expect) {
			return nil, fmt.Errorf("got current %x, want %x", current, expect)
		}
		return write, nil
	}); err != nil {
		return fmt.Errorf("Update(%s): %v", id, err)
	}
	return nil
}
