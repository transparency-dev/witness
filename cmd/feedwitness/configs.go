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

package main

import (
	"context"
	_ "embed" // embed is needed to embed files as constants
	"fmt"
	"iter"
	"maps"

	logfmt "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/omniwitness"
	"github.com/transparency-dev/formats/note"
	"gopkg.in/yaml.v3"
)

// configYAML contains a list of configuration options for known logs.
type configYAML struct {
	Logs []logYAML `yaml:"Logs"`
}

// logYAML contains the details about a log.
type logYAML struct {
	// From omniwitness.LogYAML
	Origin    string `yaml:"Origin"`
	PublicKey string `yaml:"PublicKey"`
	URL       string `yaml:"URL"`

	Feeder logFeeder `yaml:"Feeder"`
}

// newStaticFeederConfig creates a new config based on the provided YAML data.
func newStaticFeederConfig(yamlCfg []byte) (*staticFeederConfig, error) {
	cfg := &configYAML{}
	if err := yaml.Unmarshal(yamlCfg, cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal witness config: %v", err)
	}
	r := &staticFeederConfig{
		feeders: make(map[string]feederConfig),
	}
	for _, log := range cfg.Logs {
		logV, err := note.NewVerifier(log.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create signature verifier: %v", err)
		}
		logCfg := omniwitness.Log{
			VKey:     log.PublicKey,
			Verifier: logV,
			Origin:   log.Origin,
			URL:      log.URL,
		}
		if log.Origin == "" {
			log.Origin = logV.Name()
		}
		logID := logfmt.ID(log.Origin)
		if log.Feeder != None {
			f := feederConfig{
				Feeder: log.Feeder,
				Log:    logCfg,
			}
			if oldFeeder, found := r.feeders[logID]; found {
				return nil, fmt.Errorf("colliding feeder configs found for key %x: %+v and %+v", logID, oldFeeder, f)
			}
			r.feeders[logID] = f
		}
	}
	return r, nil
}

type staticFeederConfig struct {
	feeders map[string]feederConfig
}

func (s *staticFeederConfig) Feeders(_ context.Context) iter.Seq2[feederConfig, error] {
	return func(yield func(feederConfig, error) bool) {
		for _, v := range s.feeders {
			if !yield(v, nil) {
				return
			}
		}
	}
}

// Merge adds all feeders configured in other to this config.
//
// Feeders in the base config with the same ID in the config to be merged will be overridden.
func (s *staticFeederConfig) Merge(other *staticFeederConfig) {
	maps.Copy(s.feeders, other.feeders)
}
