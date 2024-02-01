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

package monitoring

import (
	"fmt"
	"strings"
	"sync"

	"k8s.io/klog/v2"
)

// InertMetricFactory creates inert metrics for testing.
type InertMetricFactory struct{}

// NewCounter creates a new inert Counter.
func (imf InertMetricFactory) NewCounter(name, help string, labelNames ...string) Counter {
	return &InertCounter{
		labelCount: len(labelNames),
		vals:       make(map[string]uint64),
	}
}

// InertCounter is an internal-only implementation of both the Counter and Gauge interfaces.
type InertCounter struct {
	labelCount int
	mu         sync.Mutex
	vals       map[string]uint64
}

// Inc adds 1 to the value.
func (m *InertCounter) Inc(labelVals ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := keyForLabels(labelVals, m.labelCount)
	if err != nil {
		klog.Error(err.Error())
		return
	}
	m.vals[key] += 1
}

func keyForLabels(labelVals []string, count int) (string, error) {
	if len(labelVals) != count {
		return "", fmt.Errorf("invalid label count %d; want %d", len(labelVals), count)
	}
	return strings.Join(labelVals, "|"), nil
}
