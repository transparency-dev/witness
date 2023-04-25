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
	_ "embed" // embed is needed to embed files as constants
	"fmt"

	logfmt "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	i_note "github.com/transparency-dev/witness/internal/note"
	"github.com/transparency-dev/witness/internal/witness"
)

var (
	// ConfigLogs is the config for the witness used in the omniwitness.
	// Its schema is LogConfig
	//go:embed logs.yaml
	ConfigLogs []byte
)

// LogConfig contains a list of LogInfo (configuration options for a log).
type LogConfig struct {
	Logs []LogInfo `yaml:"Logs"`
}

// AsLogMap loads the log configuration information into a map, keyed by log ID.
func (config LogConfig) AsLogMap() (map[string]witness.LogInfo, error) {
	logMap := make(map[string]witness.LogInfo)
	h := rfc6962.DefaultHasher
	for _, log := range config.Logs {
		logV, err := i_note.NewVerifier(log.PublicKeyType, log.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create signature verifier: %v", err)
		}
		logInfo := witness.LogInfo{
			SigV:       logV,
			Origin:     log.Origin,
			Hasher:     h,
			UseCompact: log.UseCompact,
		}
		logID := logfmt.ID(log.Origin, []byte(log.PublicKey))
		if oldLog, found := logMap[logID]; found {
			return nil, fmt.Errorf("colliding log configs found for key %x: %+v and %+v", logID, oldLog, logInfo)
		}
		logMap[logID] = logInfo
	}
	return logMap, nil
}

// LogInfo contains the details about a log.
type LogInfo struct {
	Origin        string `yaml:"Origin"`
	PublicKey     string `yaml:"PublicKey"`
	PublicKeyType string `yaml:"PublicKeyType"`
	Url           string `yaml:"URL"`
	Feeder        Feeder `yaml:"Feeder"`
	UseCompact    bool   `yaml:"UseCompact"`
}
