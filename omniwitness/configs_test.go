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
	"testing"

	"github.com/transparency-dev/witness/omniwitness"
	"gopkg.in/yaml.v3"
)

func Test(t *testing.T) {
	logCfg := omniwitness.LogConfig{}
	if err := yaml.Unmarshal(omniwitness.ConfigLogs, &logCfg); err != nil {
		t.Fatal("failed to unmarshal config", err)
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
