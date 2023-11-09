// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package note

import (
	"crypto/rand"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

func TestSignerRoundtrip(t *testing.T) {
	skey, _, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatal(err)
	}

	msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\n"
	n, err := note.Sign(&note.Note{Text: msg}, s)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := note.Open(n, note.VerifierList(s.Verifier())); err != nil {
		t.Fatal(err)
	}
}

func TestSignerVerifierRoundtrip(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewVerifierForCosignatureV1(vkey)
	if err != nil {
		t.Fatal(err)
	}

	msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\n"
	n, err := note.Sign(&note.Note{Text: msg}, s)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := note.Open(n, note.VerifierList(v)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierInvalidSig(t *testing.T) {
	skey, _, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatal(err)
	}

	msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\n"
	if _, err := note.Sign(&note.Note{Text: msg}, s); err != nil {
		t.Fatal(err)
	}

	if _, err := note.Open([]byte("nobbled"), note.VerifierList(s.Verifier())); err == nil {
		t.Fatal("Verifier validated incorrect signature")
	}
}

func TestSigCoversExtensionLines(t *testing.T) {
	skey, _, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatal(err)
	}

	msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\nExtendo\n"
	n, err := note.Sign(&note.Note{Text: msg}, s)
	if err != nil {
		t.Fatal(err)
	}

	n[len(n)-2] = '@'
	if _, err := note.Open(n, note.VerifierList(s.Verifier())); err == nil {
		t.Fatal("Signature did not cover extension lines")
	}
}
