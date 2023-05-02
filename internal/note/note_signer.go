// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package note

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/note"
)

const (
	algEd25519              = 1
	algEd25519CosignatureV1 = 4
)

// NewSignerForCosignatureV1 constructs a new Signer that produces timestamped
// cosignature/v1 signatures from a standard Ed25519 encoded signer key.
//
// (The returned Signer has a different key hash from a non-timestamped one,
// meaning it will differ from the key hash in the input encoding.)
func NewSignerForCosignatureV1(skey string) (*Signer, error) {
	priv1, skey, _ := strings.Cut(skey, "+")
	priv2, skey, _ := strings.Cut(skey, "+")
	name, skey, _ := strings.Cut(skey, "+")
	hash16, key64, _ := strings.Cut(skey, "+")
	key, err := base64.StdEncoding.DecodeString(key64)
	if priv1 != "PRIVATE" || priv2 != "KEY" || len(hash16) != 8 || err != nil || !isValidName(name) || len(key) == 0 {
		return nil, errSignerID
	}

	s := &Signer{name: name}

	alg, key := key[0], key[1:]
	switch alg {
	default:
		return nil, errSignerAlg

	case algEd25519:
		if len(key) != ed25519.SeedSize {
			return nil, errSignerID
		}
		key := ed25519.NewKeyFromSeed(key)
		pubkey := append([]byte{algEd25519CosignatureV1}, key.Public().(ed25519.PublicKey)...)
		s.hash = keyHashEd25519(name, pubkey)
		s.sign = func(msg []byte) ([]byte, error) {
			t := uint64(time.Now().Unix())
			m, err := formatCosignatureV1(t, msg)
			if err != nil {
				return nil, err
			}

			// The signature itself is encoded as timestamp || signature.
			sig := make([]byte, 0, 8+ed25519.SignatureSize)
			sig = binary.LittleEndian.AppendUint64(sig, t)
			sig = append(sig, ed25519.Sign(key, m)...)
			return sig, nil
		}
		s.verify = func(msg, sig []byte) bool {
			if len(sig) != 8+ed25519.SignatureSize {
				return false
			}
			t := binary.LittleEndian.Uint64(sig)
			sig = sig[8:]
			m, err := formatCosignatureV1(t, msg)
			if err != nil {
				return false
			}
			return ed25519.Verify(key.Public().(ed25519.PublicKey), m, sig)
		}
	}

	return s, nil
}

func formatCosignatureV1(t uint64, msg []byte) ([]byte, error) {
	// The signed message is in the following format
	//
	//      cosignature/v1
	//      time TTTTTTTTTT
	//      origin line
	//      NNNNNNNNN
	//      tree hash
	//
	// where TTTTTTTTTT is the current UNIX timestamp, and the following
	// three lines are the first three lines of the note. All other
	// lines are not processed by the witness, so are not signed.

	lines := bytes.Split(msg, []byte("\n"))
	if len(lines) < 3 {
		return nil, errors.New("cosigned note format invalid")
	}
	return []byte(fmt.Sprintf(
		"cosignature/v1\ntime %d\n%s\n%s\n%s\n",
		t, lines[0], lines[1], lines[2])), nil
}

var (
	errSignerID   = errors.New("malformed verifier id")
	errSignerAlg  = errors.New("unknown verifier algorithm")
	errSignerHash = errors.New("invalid verifier hash")
)

type Signer struct {
	name   string
	hash   uint32
	sign   func([]byte) ([]byte, error)
	verify func(msg, sig []byte) bool
}

func (s *Signer) Name() string                    { return s.name }
func (s *Signer) KeyHash() uint32                 { return s.hash }
func (s *Signer) Sign(msg []byte) ([]byte, error) { return s.sign(msg) }

func (s *Signer) Verifier() note.Verifier {
	return &verifier{
		name:    s.name,
		keyHash: s.hash,
		v:       s.verify,
	}
}

// isValidName reports whether name is valid.
// It must be non-empty and not have any Unicode spaces or pluses.
func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

func keyHashEd25519(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}
