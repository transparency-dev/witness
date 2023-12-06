// Copyright 2021 Google LLC. All Rights Reserved.
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

// Package config provides the descriptor structs and example configs for
// the different entities. This allows for a common description of logs,
// witnesses, etc.
package config

import (
	"github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// NewLog creates a Log from the given origin, public key & type, and URL.
func NewLog(origin, pk, url string) (Log, error) {
	id := log.ID(origin)
	logV, err := f_note.NewVerifier(pk)
	if err != nil {
		return Log{}, err
	}
	return Log{
		ID:       id,
		Origin:   origin,
		Verifier: logV,
		URL:      url,
	}, nil
}

// Log describes a verifiable log.
type Log struct {
	// ID is the canonical ID for the log.
	ID string
	// Verifier is a signature verifier for log checkpoints.
	Verifier note.Verifier
	// Origin is the expected first line of checkpoints from the log.
	Origin string
	// URL is the URL of the root of the log.
	URL string
}
