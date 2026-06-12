// Copyright 2026 Google LLC. All Rights Reserved.
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

package main

import (
	"fmt"
	"testing"
)

func TestParseConfig(t *testing.T) {
	wantOrigin := "tlog.andxor.it"
	wantURL := "https://tlog.andxor.it"
	wantPublicKey := "tlog.andxor.it+d5e6b3d0+AU6uJ3h8tb+RRMdGjHV4KCrrHoKfIYGbhL2A46thEhKQ"
    cfg := fmt.Appendf(nil, "Logs:\n- Origin: %s\n  URL: %s\n  PublicKey: %s\n  Feeder: tiles", wantOrigin, wantURL, wantPublicKey)

	fCfg, err := newStaticFeederConfig(cfg)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}
	got := 0
	for f, err := range fCfg.Feeders(t.Context()) {
		if err != nil {
			t.Fatalf("Failed to iterate over feeders: %v", err)
		}
		got++
		if f.Log.URL != wantURL {
			t.Errorf("got URL %q, want %q", f.Log.URL, wantURL)
		}
		if f.Log.Origin != wantOrigin {
			t.Errorf("got Origin %q, want %q", f.Log.Origin, wantOrigin)
		}
		if f.Log.VKey != wantPublicKey {
			t.Errorf("got VKey %q, want %q", f.Log.VKey, wantPublicKey)
		}
		if f.Log.Verifier == nil {
			t.Error("got nil Verifier, want non-nil")
		}
		if f.Feeder != Tiles {
			t.Errorf("got Feeder %s, want Tiles", f.Feeder)
		}
	}

	if want := 1; got != want {
		t.Fatalf("Got %d feeders, want %d", got, want)
	}
}

