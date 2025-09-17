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
	"context"
	"fmt"
	"iter"
	"os"
	"strings"
	"testing"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/spannertest"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/internal/persistence"
	ptest "github.com/transparency-dev/witness/internal/persistence/testonly"
	"github.com/transparency-dev/witness/omniwitness"
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
	t.Helper()
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

func TestDisableLog(t *testing.T) {
	p, shutdown := mustNewPersistence(t)()
	defer func() {
		if err := shutdown(); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()
	if err := p.Init(t.Context()); err != nil {
		t.Fatalf("Init(): %v", err)
	}

	sp := p.(*spannerPersistence)

	if err := sp.AddLogs(t.Context(),
		omniwitness.ConfigYAML{
			Logs: []omniwitness.LogYAML{
				{
					Origin:    "log1",
					PublicKey: "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
				}, {
					Origin:    "log2",
					PublicKey: "armory-drive-log+16541b8f+AYDPmG5pQp4Bgu0a1mr5uDZ196+t8lIVIfWQSPWmP+Jv",
				},
			},
		}); err != nil {
		t.Fatalf("Failed to AddLogs: %v", err)
	}

	logsBefore := toSlice(t, sp.Logs(t.Context()))
	if got, want := len(logsBefore), 2; got != want {
		t.Fatalf("Got %d logs, want %d: %+v", got, want, logsBefore)
	}

	if _, err := sp.spanner.ReadWriteTransaction(t.Context(), func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement("UPDATE logs SET disabled = true WHERE logID = @logID")
		stmt.Params["logID"] = logsBefore[0].ID
		_, err := txn.Update(ctx, stmt)
		return err
	}); err != nil {
		t.Fatalf("Failed to disable log with ID %q: %v", logsBefore[0].ID, err)
	}

	logsAfter := toSlice(t, sp.Logs(t.Context()))
	if got, want := len(logsAfter), 1; got != want {
		t.Fatalf("Got %d logs, want %d: %+v", got, want, logsAfter)
	}

	if got, want := logsAfter[0].ID, logsBefore[1].ID; got != want {
		t.Fatalf("Got unexpected log ID %q, want %q", got, want)
	}
}

func TestDisabledLogStaysDisabled(t *testing.T) {
	p, shutdown := mustNewPersistence(t)()
	defer func() {
		if err := shutdown(); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()
	if err := p.Init(t.Context()); err != nil {
		t.Fatalf("Init(): %v", err)
	}

	logs := omniwitness.ConfigYAML{
		Logs: []omniwitness.LogYAML{
			{
				Origin:    "log1",
				PublicKey: "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
			},
		},
	}

	sp := p.(*spannerPersistence)

	if err := sp.AddLogs(t.Context(), logs); err != nil {
		t.Fatalf("Failed to AddLogs: %v", err)
	}

	logsBefore := toSlice(t, sp.Logs(t.Context()))
	if got, want := len(logsBefore), 1; got != want {
		t.Fatalf("Got %d logs, want %d: %+v", got, want, logsBefore)
	}

	// Now disable the log:
	if _, err := sp.spanner.ReadWriteTransaction(t.Context(), func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		stmt := spanner.NewStatement("UPDATE logs SET disabled = true WHERE logID = @logID")
		stmt.Params["logID"] = logsBefore[0].ID
		_, err := txn.Update(ctx, stmt)
		return err
	}); err != nil {
		t.Fatalf("Failed to disable log with ID %q: %v", logsBefore[0].ID, err)
	}

	// There should be zero visible logs now:
	logsDisabled := toSlice(t, sp.Logs(t.Context()))
	if got, want := len(logsDisabled), 0; got != want {
		t.Fatalf("Got %d logs, want %d: %+v", got, want, logsDisabled)
	}

	// Simulate an update of the embedded logs:
	if err := sp.AddLogs(t.Context(), logs); err != nil {
		t.Fatalf("Failed to AddLogs: %v", err)
	}

	// There should still be zero visible logs now:
	logsAfter := toSlice(t, sp.Logs(t.Context()))
	if got, want := len(logsAfter), 0; got != want {
		t.Fatalf("Got %d logs, want %d: %+v", got, want, logsAfter)
	}
}

func toSlice(t *testing.T, i iter.Seq2[config.Log, error]) []config.Log {
	t.Helper()
	logs := []config.Log{}
	for l, err := range i {
		if err != nil {
			t.Fatalf("Logs(): %v", err)
		}
		logs = append(logs, l)
	}

	return logs
}
