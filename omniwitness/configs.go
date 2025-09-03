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

package omniwitness

import (
	"context"
	_ "embed" // embed is needed to embed files as constants
	"fmt"
	"iter"
	"maps"

	logfmt "github.com/transparency-dev/formats/log"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/internal/config"
	"gopkg.in/yaml.v3"
)

var (
	// DefaultConfigLogs is the config for the witness used in the omniwitness.
	// Its schema is LogConfig
	//go:embed logs.yaml
	DefaultConfigLogs []byte
)

// cfg contains a list of configuration options for known logs.
type cfg struct {
	Logs []logCfg `yaml:"Logs"`
}

// logCfg contains the details about a log.
type logCfg struct {
	Origin    string `yaml:"Origin"`
	PublicKey string `yaml:"PublicKey"`
	URL       string `yaml:"URL"`
	Feeder    Feeder `yaml:"Feeder"`
}

// NewStaticLogConfig creates a new LogConfig based on the provided YAML data.
func NewStaticLogConfig(yamlCfg []byte) (*staticLogConfig, error) {
	cfg := &cfg{}
	if err := yaml.Unmarshal(yamlCfg, cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal witness config: %v", err)
	}
	r := &staticLogConfig{
		logs: make(map[string]parsedLog),
	}
	for _, log := range cfg.Logs {
		logV, err := f_note.NewVerifier(log.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create signature verifier: %v", err)
		}
		logID := logfmt.ID(log.Origin)
		logInfo := parsedLog{
			Config: config.Log{
				ID:       logID,
				Verifier: logV,
				Origin:   log.Origin,
				URL:      log.URL,
			},
			Feeder: log.Feeder,
		}
		if oldLog, found := r.logs[logID]; found {
			return nil, fmt.Errorf("colliding log configs found for key %x: %+v and %+v", logID, oldLog, logInfo)
		}
		r.logs[logID] = logInfo
	}
	return r, nil
}

type parsedLog struct {
	Config config.Log
	// Feeder is the feeder to use for this log, if any.
	Feeder Feeder
}

type staticLogConfig struct {
	logs map[string]parsedLog
}

func (s *staticLogConfig) Logs(_ context.Context) iter.Seq2[config.Log, error] {
	return func(yield func(config.Log, error) bool) {
		for _, v := range s.logs {
			if !yield(v.Config, nil) {
				return
			}
		}
	}
}

func (s *staticLogConfig) Feeders(_ context.Context) iter.Seq2[FeederConfig, error] {
	return func(yield func(FeederConfig, error) bool) {
		for _, v := range s.logs {
			if v.Feeder != None {
				if !yield(FeederConfig{
					Feeder: v.Feeder,
					Log:    v.Config,
				}, nil) {
					return
				}
			}
		}
	}
}

func (s *staticLogConfig) Log(_ context.Context, id string) (config.Log, bool, error) {
	l, ok := s.logs[id]
	return l.Config, ok, nil
}

// Merge adds all logs configured in other to this config.
//
// Logs in the base config with the same LogID in the config to be merged will be overridden.
func (s *staticLogConfig) Merge(other *staticLogConfig) {
	maps.Copy(s.logs, other.logs)
}
