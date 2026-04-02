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

package sql

import (
	"testing"

	"database/sql"

	_ "github.com/mattn/go-sqlite3" // Load drivers for sqlite3
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/internal/persistence"
	ptest "github.com/transparency-dev/witness/internal/persistence/testonly"
	"github.com/transparency-dev/witness/omniwitness"
)

func TestUpdate(t *testing.T) {
	ptest.TestUpdate(t, func() (persistence.LogStatePersistence, func() error) {
		db, close := mustCreateDB(t)
		return NewPersistence(db), close
	})
}

func mustCreateDB(t *testing.T) (*sql.DB, func() error) {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open temporary DB: %v", err)
	}
	db.SetMaxOpenConns(1)
	return db, db.Close
}

func TestLogConfig(t *testing.T) {
	db, cleanup := mustCreateDB(t)
	defer cleanup()

	p := NewPersistence(db)
	if err := p.Init(t.Context()); err != nil {
		t.Fatalf("Init(): %v", err)
	}

	vkey := "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
	logs := []omniwitness.Log{
		{Origin: "log1", VKey: vkey},
		{Origin: "log2", VKey: vkey},
	}

	// Test AddLogs
	if err := p.AddLogs(t.Context(), logs); err != nil {
		t.Fatalf("AddLogs(): %v", err)
	}

	// Test Logs (list)
	sc := p.Logs(t.Context())
	gotLogs := make(map[string]omniwitness.Log)
	for l, err := range sc {
		if err != nil {
			t.Fatalf("Logs() error: %v", err)
		}
		gotLogs[l.Origin] = l
	}

	if len(gotLogs) != 2 {
		t.Errorf("expected 2 logs, got %v", gotLogs)
	}
	if _, ok := gotLogs["log1"]; !ok {
		t.Error("missing log1")
	}
	if _, ok := gotLogs["log2"]; !ok {
		t.Error("missing log2")
	}

	// Test Log (single)
	l, ok, err := p.Log(t.Context(), "log1")
	if err != nil {
		t.Fatalf("Log(): %v", err)
	}
	if !ok {
		t.Error("log1 not found")
	}
	if l.Origin != "log1" {
		t.Errorf("got log origin %s, want log1", l.Origin)
	}

	// Test duplicates (Insert or Ignore)
	if err := p.AddLogs(t.Context(), logs[:1]); err != nil {
		t.Fatalf("AddLogs() with duplicate: %v", err)
	}
	// Verify count is still 2
	sc = p.Logs(t.Context())
	count := 0
	for _, err := range sc {
		if err != nil {
			t.Fatalf("Logs() error: %v", err)
		}
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 logs after duplicate add, got %d", count)
	}
}

func TestDisabledLogs(t *testing.T) {
	db, cleanup := mustCreateDB(t)
	defer cleanup()

	p := NewPersistence(db)
	if err := p.Init(t.Context()); err != nil {
		t.Fatalf("Init(): %v", err)
	}

	vkey := "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"

	// Test disabled logs
	// Manually insert a disabled log
	if _, err := db.ExecContext(t.Context(), "INSERT INTO logs (logID, origin, vkey, contact, disabled) VALUES (?, ?, ?, ?, ?)", log.ID("log3"), "log3", vkey, "", true); err != nil {
		t.Fatalf("failed to insert disabled log: %v", err)
	}

	// Verify it is NOT returned by Log
	_, ok, err := p.Log(t.Context(), "log3")
	if err != nil {
		t.Fatalf("Log() with disabled: %v", err)
	}
	if ok {
		t.Error("found disabled log3")
	}

	// Verify it is NOT returned by Logs
	sc := p.Logs(t.Context())
	for l, err := range sc {
		if err != nil {
			t.Fatalf("Logs() error: %v", err)
		}
		if l.Origin == "log3" {
			t.Error("found disabled log3 in Logs()")
		}
	}
}
