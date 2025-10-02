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
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/transparency-dev/witness/internal/persistence"
	"github.com/transparency-dev/witness/internal/witness"
)

// TestUpdate exposes a test that can be invoked by tests for specific implementations of persistence.
func TestUpdate(t *testing.T, lspFactory func() (persistence.LogStatePersistence, func() error)) {
	t.Helper()
	origin := "foo"

	lsp, close := lspFactory()
	defer func() {
		if err := close(); err != nil {
			t.Fatalf("close(): %v", err)
		}
	}()
	if err := lsp.Init(t.Context()); err != nil {
		t.Fatalf("Init(): %v", err)
	}

	// Test that a successful update is visible.
	{
		newCP := []byte("foo\ncp")
		if err := checkAndSet(t.Context(), lsp, origin, nil, newCP); err != nil {
			t.Fatalf("checkAndSet(nil, %s): %v", newCP, err)

		}

		cpRaw, err := lsp.Latest(t.Context(), origin)
		if err != nil {
			t.Fatalf("Latest(): %v", err)
		}
		if got, want := cpRaw, []byte("foo\ncp"); !bytes.Equal(got, want) {
			t.Errorf("got != want (%s != %s)", got, want)
		}
	}

	// Test that underlying witness errors are properly wrapped by the persistence implementation.
	{
		wantErr := witness.ErrCheckpointStale
		err := lsp.Update(t.Context(), origin, func(_ []byte) ([]byte, error) {
			return nil, wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("Got %[1]v (%[1]T), want %[2]v (%[2]T)", err, wantErr)
		}
	}
}

func checkAndSet(ctx context.Context, lsp persistence.LogStatePersistence, origin string, expect []byte, write []byte) error {
	if err := lsp.Update(ctx, origin, func(current []byte) ([]byte, error) {
		if !bytes.Equal(current, expect) {
			return nil, fmt.Errorf("got current %x, want %x", current, expect)
		}
		return write, nil
	}); err != nil {
		return fmt.Errorf("Update(%s): %w", origin, err)
	}
	return nil
}
