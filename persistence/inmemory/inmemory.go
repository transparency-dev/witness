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
	"bytes"
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/omniwitness"
)

// NewPersistence returns a persistence object that lives only in memory.
func NewPersistence() *inMemoryPersistence {
	return &inMemoryPersistence{
		checkpoints: make(map[string][]byte),
		logs:        make(map[string]omniwitness.Log),
	}
}

type inMemoryPersistence struct {
	// mu allows checkpoints to be read concurrently, but
	// exclusively locked for writing.
	mu          sync.RWMutex
	checkpoints map[string][]byte
	logs        map[string]omniwitness.Log
}

func (p *inMemoryPersistence) Init(_ context.Context) error {
	return nil
}

func (p *inMemoryPersistence) AddLogs(ctx context.Context, lc []omniwitness.Log) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, l := range lc {
		logID := log.ID(l.Origin)
		p.logs[logID] = l
	}
	return nil
}

func (p *inMemoryPersistence) Logs(ctx context.Context) iter.Seq2[omniwitness.Log, error] {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return func(yield func(omniwitness.Log, error) bool) {
		for _, lc := range p.logs {
			if !yield(lc, nil) {
				return
			}
		}
	}
}

func (p *inMemoryPersistence) Log(ctx context.Context, origin string) (omniwitness.Log, bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	logID := log.ID(origin)
	lc, ok := p.logs[logID]
	if !ok {
		return lc, false, nil
	}
	return lc, true, nil
}

func (p *inMemoryPersistence) Latest(_ context.Context, origin string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	logID := log.ID(origin)
	return p.checkpoints[logID], nil
}

func (p *inMemoryPersistence) Update(_ context.Context, origin string, f func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	logID := log.ID(origin)
	u, err := f(p.checkpoints[logID])
	if err != nil {
		return err
	}

	bits := bytes.Split(u, []byte{'\n'})
	if len(bits) == 0 {
		return errors.New("invalid checkpoint")
	}
	if co := string(bits[0]); origin != co {
		return fmt.Errorf("origin mismatch, %q != %q", origin, co)
	}

	p.checkpoints[logID] = u
	return nil
}
