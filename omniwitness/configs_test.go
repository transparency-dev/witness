// Copyright 2023 Google LLC. All Rights Reserved.
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

package omniwitness_test

import (
	_ "embed"
	"testing"

	"github.com/transparency-dev/witness/omniwitness"
)

var (
	// TestConfigLogs is the testing config logs file, useful for when checking
	// features which are not yet used by the prod config.
	// Its schema is LogConfig
	//go:embed logs_test.yaml
	testConfigLogs []byte
)

func testConfig(t *testing.T, cfg []byte) {
	t.Helper()
	logCfg, err := omniwitness.NewStaticLogConfig(cfg)
	if err != nil {
		t.Fatal("failed to unmarshal config", err)
	}
	{
		c := 0
		for l, err := range logCfg.Logs(t.Context()) {
			if err != nil {
				t.Fatalf("Failed to iterate over logs: %v", err)
			}
			c++
			if len(l.URL) == 0 {
				t.Errorf("log %q has no URL", l.URL)
			}
		}
		if c == 0 {
			t.Fatal("no logs defined in config")
		}
	}

	{
		for f, err := range logCfg.Feeders(t.Context()) {
			if err != nil {
				t.Fatalf("Failed to iterate over feeders: %v", err)
			}
			if f.Feeder == omniwitness.None {
				t.Errorf("log %q has unknown feeder", f.Log.Origin)
			}
		}
	}
}

func TestProdConfig(t *testing.T) {
	testConfig(t, omniwitness.DefaultConfigLogs)
}

func TestConfig(t *testing.T) {
	testConfig(t, testConfigLogs)
}

func TestMerge(t *testing.T) {
	base, err := omniwitness.NewStaticLogConfig([]byte(`
Logs:
  - Origin: go.sum database tree
    URL: https://sum.golang.org
    PublicKey: sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8
    Feeder: sumdb
`))
	if err != nil {
		t.Fatalf("Failed to parse base config: %v", err)
	}

	extra, err := omniwitness.NewStaticLogConfig([]byte(`
Logs:
  - Origin: Armory Drive Prod 2
    URL: https://raw.githubusercontent.com/f-secure-foundry/armory-drive-log/master/log/
    PublicKey: armory-drive-log+16541b8f+AYDPmG5pQp4Bgu0a1mr5uDZ196+t8lIVIfWQSPWmP+Jv
    Feeder: serverless
`))
	if err != nil {
		t.Fatalf("Failed to parse extra config: %v", err)
	}

	base.Merge(extra)
	want := map[string]struct{}{
		"go.sum database tree": {},
		"Armory Drive Prod 2":  {},
	}
	for l, err := range base.Logs(t.Context()) {
		if err != nil {
			t.Fatalf("Failed to iterate over logs: %v", err)
		}
		if _, ok := want[l.Origin]; ok {
			delete(want, l.Origin)
		} else {
			t.Errorf("Did not find expected log with origin %q in merged config", l.Origin)
		}
	}
	if l := len(want); l != 0 {
		t.Fatalf("Found %d unexpected extra logs in merged config", l)
	}
}
