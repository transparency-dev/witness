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
	"gopkg.in/yaml.v3"
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
	logCfg := omniwitness.LogConfig{}
	if err := yaml.Unmarshal(cfg, &logCfg); err != nil {
		t.Fatal("failed to unmarshal config", err)
	}
	if len(logCfg.Logs) == 0 {
		t.Fatal("no logs defined in config")
	}
	for _, l := range logCfg.Logs {
		if l.Feeder == 0 {
			t.Errorf("log %q has unknown feeder", l.Origin)
		}
		if len(l.URL) == 0 {
			t.Errorf("log %q has no URL", l.URL)
		}
	}
}

func TestProdConfig(t *testing.T) {
	testConfig(t, omniwitness.ConfigLogs)
}

func TestConfig(t *testing.T) {
	testConfig(t, testConfigLogs)
}
