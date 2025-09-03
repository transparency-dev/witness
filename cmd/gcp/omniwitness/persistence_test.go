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

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"cloud.google.com/go/spanner/spannertest"
	"github.com/transparency-dev/witness/internal/persistence"
	ptest "github.com/transparency-dev/witness/internal/persistence/testonly"
	"golang.org/x/sync/errgroup"
)

func newSpannerServer(t *testing.T) (string, func()) {
	t.Helper()
	srv, err := spannertest.NewServer("localhost:0")
	if err != nil {
		t.Fatalf("Failed to set up test spanner: %v", err)
	}
	if err := os.Setenv("SPANNER_EMULATOR_HOST", srv.Addr); err != nil {
		t.Fatalf("Setenv: %v", err)
	}

	id := "projects/p/instances/i/databases/d"
	return id, srv.Close
}

func mustNewPersistence(t *testing.T) func() (persistence.LogStatePersistence, func() error) {
	return func() (persistence.LogStatePersistence, func() error) {
		spanner, spannerShutdown := newSpannerServer(t)
		p, clientShutdown, err := newSpannerPersistence(t.Context(), spanner)
		if err != nil {
			t.Fatalf("Failed to create spanner persistence: %v", err)
		}
		shutdown := func() error {
			if err := clientShutdown(); err != nil {
				t.Errorf("clientShutdown: %v", err)
			}
			spannerShutdown()
			return nil
		}

		return p, shutdown
	}
}

func TestUpdate(t *testing.T) {
	ptest.TestUpdate(t, mustNewPersistence(t))
}

func TestUpdateConcurrent(t *testing.T) {
	p, shutdown := mustNewPersistence(t)()
	defer func() {
		if err := shutdown(); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()

	if err := p.Init(t.Context()); err != nil {
		t.Fatalf("Failed to init persistence: %v", err)
	}

	g := errgroup.Group{}
	logID := "foo"

	for i := range 25 {
		g.Go(func() error {
			return p.Update(t.Context(), logID, func(current []byte) (next []byte, err error) {
				return fmt.Appendf(nil, "success %d", i), nil
			})
		})
	}

	if err := g.Wait(); err != nil {
		t.Error(err)
	}

	cp, err := p.Latest(t.Context(), logID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(cp), "success") {
		t.Errorf("expected at least one success but got %s", string(cp))
	}
}
