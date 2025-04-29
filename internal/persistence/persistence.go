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

// Package persistence defines interfaces and tests for storing log state.
package persistence

// LogStatePersistence is a handle on persistent storage for log state.
type LogStatePersistence interface {
	// Init sets up the persistence layer. This should be idempotent,
	// and will be called once per process startup.
	Init() error

	// Logs returns the IDs of all logs that have checkpoints that can
	// be read.
	Logs() ([]string, error)

	// Latest returns the latest checkpoint.
	// If no checkpoint exists, it must return nil.
	Latest(logID string) ([]byte, error)

	// Update allows for atomically updating the currently stored (if any)
	// checkpoint for the given logID.
	//
	// The provided function will be passed the currently stored checkpoint
	// for the provided log ID (or nil if no such checkpoint exists), and
	// should return the serialised form of the updated checkpoint, or an
	// error.
	//
	// There is no requirement that the provuided ID is present in Logs(); if
	// the ID is not there, and this operation succeeds in committing
	// a checkpoint, then Logs() will return the new ID afterwards.
	Update(logID string, f UpdateFn) error
}

// UpdateFn is the signature of a function which takes the currently stored
// checkpoint and returns a newer version which should replace it.
//
// Implementations should interpret a nil argument as meaning there is no
// currently stored checkpoint.
type UpdateFn func(current []byte) (next []byte, err error)
