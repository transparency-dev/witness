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

// Package inmemory provides a persistence implementation that lives only in memory.
package inmemory

import (
	"sync"

	"github.com/transparency-dev/witness/internal/persistence"
)

// NewPersistence returns a persistence object that lives only in memory.
func NewPersistence() persistence.LogStatePersistence {
	return &inMemoryPersistence{
		checkpoints: make(map[string][]byte),
	}
}

type inMemoryPersistence struct {
	// mu allows checkpoints to be read concurrently, but
	// exclusively locked for writing.
	mu          sync.RWMutex
	checkpoints map[string][]byte
}

func (p *inMemoryPersistence) Init() error {
	return nil
}

func (p *inMemoryPersistence) Logs() ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	res := make([]string, 0, len(p.checkpoints))
	for k := range p.checkpoints {
		res = append(res, k)
	}
	return res, nil
}

func (p *inMemoryPersistence) Latest(logID string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.checkpoints[logID], nil
}

func (p *inMemoryPersistence) Update(logID string, f func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, err := f(p.checkpoints[logID])
	if err != nil {
		return err
	}

	p.checkpoints[logID] = u
	return nil
}
