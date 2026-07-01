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
	"github.com/transparency-dev/witness/config"
)

// New returns a persistence object that lives only in memory.
func New() *Persistence {
	return &Persistence{
		checkpoints: make(map[string][]byte),
	}
}

type Persistence struct {
	checkpointsMu sync.RWMutex
	checkpoints   map[string][]byte

	logs sync.Map
}

func (p *Persistence) Init(_ context.Context) error {
	return nil
}

func (p *Persistence) AddLogs(ctx context.Context, lc []config.Log) error {
	for _, l := range lc {
		logID := log.ID(l.Origin)
		p.logs.Store(logID, l)
	}
	return nil
}

func (p *Persistence) Logs(ctx context.Context) iter.Seq2[config.Log, error] {
	return func(yield func(config.Log, error) bool) {
		p.logs.Range(func(key, value any) bool {
			return yield(value.(config.Log), nil)
		})
	}
}

func (p *Persistence) Log(ctx context.Context, origin string) (config.Log, bool, error) {
	logID := log.ID(origin)
	val, ok := p.logs.Load(logID)
	if !ok {
		return config.Log{}, false, nil
	}
	return val.(config.Log), true, nil
}

func (p *Persistence) Latest(_ context.Context, origin string) ([]byte, error) {
	p.checkpointsMu.RLock()
	defer p.checkpointsMu.RUnlock()
	logID := log.ID(origin)
	return p.checkpoints[logID], nil
}

func (p *Persistence) Update(_ context.Context, origin string, f func([]byte) ([]byte, error)) error {
	p.checkpointsMu.Lock()
	defer p.checkpointsMu.Unlock()
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
