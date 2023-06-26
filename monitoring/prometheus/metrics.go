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

// Package prometheus contains bindings to prometheus for the interfaces in
// the parent monitoring package.
package prometheus

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/transparency-dev/witness/monitoring"
)

// MetricFactory allows the creation of Prometheus-based metrics.
type MetricFactory struct {
	// Prefix is an identifier that will be used before local metric names that
	// are reported. It is strongly recommended that this ends with a valid
	// separator (e.g. "_") in order to improve readability; no separator is
	// added by this library.
	Prefix string
}

// NewCounter creates a new Counter object backed by Prometheus.
func (pmf MetricFactory) NewCounter(name, help string, labelNames ...string) monitoring.Counter {
	if len(labelNames) == 0 {
		counter := prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: pmf.Prefix + name,
				Help: help,
			})
		prometheus.MustRegister(counter)
		return &Counter{single: counter}
	}

	vec := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: pmf.Prefix + name,
			Help: help,
		},
		labelNames)
	prometheus.MustRegister(vec)
	return &Counter{labelNames: labelNames, vec: vec}

}

// Counter is a wrapper around a Prometheus Counter or CounterVec object.
type Counter struct {
	labelNames []string
	single     prometheus.Counter
	vec        *prometheus.CounterVec
}

// Inc adds 1 to a counter.
func (m *Counter) Inc(labelVals ...string) {
	labels, err := labelsFor(m.labelNames, labelVals)
	if err != nil {
		glog.Error(err.Error())
		return
	}
	if m.vec != nil {
		m.vec.With(labels).Inc()
	} else {
		m.single.Inc()
	}
}

func labelsFor(names, values []string) (prometheus.Labels, error) {
	if len(names) != len(values) {
		return nil, fmt.Errorf("got %d (%v) values for %d labels (%v)", len(values), values, len(names), names)
	}
	if len(names) == 0 {
		return nil, nil
	}
	labels := make(prometheus.Labels)
	for i, name := range names {
		labels[name] = values[i]
	}
	return labels, nil
}
