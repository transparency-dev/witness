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

package sqlite

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/omniwitness"
	"github.com/transparency-dev/witness/witness"
	ptest "github.com/transparency-dev/witness/persistence/testonly"
	"golang.org/x/mod/sumdb/note"
)

func TestUpdate(t *testing.T) {
	ptest.TestUpdate(t, func() (*Persistence, func() error) {
		p := New(Opts{Path: ":memory:", MaxOpenConns: 1})
		return p, func() error { 
			if p.db != nil {
				return p.db.Close()
			}
			return nil
		}
	})
}

func TestLogConfig(t *testing.T) {
	p := New(Opts{Path: ":memory:", MaxOpenConns: 1})
	if err := p.Init(t.Context()); err != nil {
		t.Fatalf("Init(): %v", err)
	}
	defer func() { _ = p.db.Close() }()

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
	p := New(Opts{Path: ":memory:", MaxOpenConns: 1})
	if err := p.Init(t.Context()); err != nil {
		t.Fatalf("Init(): %v", err)
	}
	defer func() { _ = p.db.Close() }()

	vkey := "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"

	// Test disabled logs
	// Manually insert a disabled log
	if _, err := p.db.ExecContext(t.Context(), "INSERT INTO logs (logID, origin, vkey, contact, disabled) VALUES (?, ?, ?, ?, ?)", log.ID("log3"), "log3", vkey, "", true); err != nil {
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

func TestDeadlock(t *testing.T) {
	p := New(Opts{Path: ":memory:", MaxOpenConns: 1})
	if err := p.Init(t.Context()); err != nil {
		t.Fatalf("Init(): %v", err)
	}
	defer func() { _ = p.db.Close() }()

	mPK := "monkeys+db4d9f7e+AULaJMvTtDLHPUcUrjdDad9vDlh/PTfC2VV60JUtCfWT"
	wSK := "PRIVATE+KEY+witness+f13a86db+AaLa/dfyBhyo/m0Z7WCi98ENVZWtrP8pxgRNrx7tIWiA"

	logV, err := note.NewVerifier(mPK)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	err = p.AddLogs(t.Context(), []omniwitness.Log{
		{Origin: "monkeys", VKey: mPK, Verifier: logV},
	})
	if err != nil {
		t.Fatalf("AddLogs: %v", err)
	}

	ns, err := f_note.NewSignerForCosignatureV1(wSK)
	if err != nil {
		t.Fatalf("NewSignerForCosignatureV1: %v", err)
	}

	w, err := witness.New(t.Context(), witness.Opts{
		Persistence: p,
		Signers:     []note.Signer{ns},
		VerifierForLog: func(ctx context.Context, origin string) (note.Verifier, bool, error) {
			l, ok, err := p.Log(ctx, origin)
			if err != nil || !ok {
				return nil, ok, err
			}
			return l.Verifier, true, nil
		},
	})
	if err != nil {
		t.Fatalf("witness.New: %v", err)
	}

	mInit := []byte("monkeys\n5\n41smjBUiAU70EtKlT6lIOIYtRTYxYXsDB+XHfcvu/BE=\n\n— monkeys 202fftzGl3LVoqjXfwCFZZXs8I+5G22+Ek2K0AOyBuSJ/8/CZawNF+6fNlTKOCd622pbzJNkkJFWuw9DbicZCkEx9AY=\n")
	mNext := []byte("monkeys\n8\nV8K9aklZ4EPB+RMOk1/8VsJUdFZR77GDtZUQq84vSbo=\n\n— monkeys 202ffoUEboiQYpHzICeaFmoy3RNviHTpAxYrq/eO4QQVQMvu9UebKBMX2MJC76NLthZaKsnKbCA8GxrjePZhvDCH7Ag=\n")

	dh := func(h string) []byte {
		r, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	consProof := [][]byte{
		dh("b9e1d62618f7fee8034e4c5010f727ab24d8e4705cb296c374bf2025a87a10d2"),
		dh("aac66cd7a79ce4012d80762fe8eec3a77f22d1ca4145c3f4cee022e7efcd599d"),
		dh("89d0f753f66a290c483b39cd5e9eafb12021293395fad3d4a2ad053cfbcfdc9e"),
		dh("29e40bb79c966f4c6fe96aff6f30acfce5f3e8d84c02215175d6e018a5dee833"),
	}

	// First update (TOFU) - should succeed.
	_, _, err = w.Update(t.Context(), 0, mInit, nil)
	if err != nil {
		t.Fatalf("First Update (TOFU) failed: %v", err)
	}

	// Second update (consistent transition)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	_, _, err = w.Update(ctx, 5, mNext, consProof)
	if err != nil {
		t.Fatalf("Second Update failed (expected success with fix): %v", err)
	}
}
