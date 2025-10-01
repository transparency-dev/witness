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
	"golang.org/x/mod/sumdb/note"
)

// Log describes a verifiable log.
type Log struct {
	// VKey is the serialised note-compliant vkey for the log.
	VKey string
	// Verifier is a signature verifier for log checkpoints.
	Verifier note.Verifier
	// Origin is the expected first line of checkpoints from the log.
	Origin string
	// QPD is the expected number of witness requests per day from the log.
	QPD float64
	// Contact is an arbitrary string with contact information for the log operator.
	Contact string
	// URL is the URL of the root of the log.
	URL string
}
