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

// Package monitoring contains interfaces and bindings for collecting metrics
// about behaviour of the witness.
// This package is a stripped down fork of the monitoring code from trillian.
// If more types of metrics are needed then it could be that copying all of
// that code is the pragmatic solution.
package monitoring

import "sync"

var (
	once sync.Once
	mf   MetricFactory
)

// SetMetricFactory sets a singleton instance of a MetricFactory that will
// be used throughout the application. Only the first call to this method
// will have any effect and it _must_ be called.
func SetMetricFactory(imf MetricFactory) {
	if imf == nil {
		panic("MetricFactory cannot be nil")
	}
	once.Do(func() {
		mf = imf
	})
}

// GetMetricFactory returns the singleton MetricFactory for this application.
// Code should not call this during static initialization as the main program
// is unlikely to have configured the factory by this time. The recommended
// pattern is to call this in a `sync.Once` before initializing counters.
func GetMetricFactory() MetricFactory {
	if mf == nil {
		panic("SetMetricFactory not called before GetMetricFactory")
	}
	return mf
}

// MetricFactory allows the creation of different types of metric.
type MetricFactory interface {
	NewCounter(name, help string, labelNames ...string) Counter
}

// Counter is a metric class for numeric values that increase.
type Counter interface {
	Inc(labelVals ...string)
}
