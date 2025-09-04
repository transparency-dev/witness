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

package inmemory

import (
	"fmt"
	"strings"
	"testing"

	"github.com/transparency-dev/witness/internal/persistence"
	ptest "github.com/transparency-dev/witness/internal/persistence/testonly"
	"golang.org/x/sync/errgroup"
)

var nopClose = func() error { return nil }

func TestUpdate(t *testing.T) {
	ptest.TestUpdate(t, func() (persistence.LogStatePersistence, func() error) {
		return NewPersistence(), nopClose
	})
}

func TestUpdateConcurrent(t *testing.T) {
	p := NewPersistence()

	g := errgroup.Group{}
	logID := "foo"

	for i := 0; i < 25; i++ {
		i := i
		g.Go(func() error {
			return p.Update(t.Context(), logID, func(current []byte) (next []byte, err error) {
				return []byte(fmt.Sprintf("success %d", i)), nil
			})
		})
	}

	if err := g.Wait(); err != nil {
		t.Error(err)
	}

	cp, err := p.Latest(t.Context(), logID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(cp), "success") {
		t.Errorf("expected at least one success but got %s", string(cp))
	}
}
