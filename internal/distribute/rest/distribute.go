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

// Package rest provides support for pushing witnessed checkpoints to a
// RESTful API.
package rest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"sync"

	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/monitoring"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

const (
	// HTTPCheckpointByWitness is the path of the URL to the latest checkpoint
	// for a given log by a given witness. This can take PUT requests to update
	// the latest checkpoint.
	//  * first position is for the logID (an alphanumeric string)
	//  * second position is the witness short name (alpha string)
	HTTPCheckpointByWitness = "/distributor/v0/logs/%s/byWitness/%s/checkpoint"
)

// GetLatestCheckpointFn is the signature of a function which returns the latest checkpoint the witness holds for the given logID.
// Implementations must return os.ErrNotExists if the logID is known, but it has no checkpoint for that log.
type GetLatestCheckpointFn func(ctx context.Context, logID string) ([]byte, error)

var (
	doOnce                 sync.Once
	counterDistRestAttempt monitoring.Counter
	counterDistRestSuccess monitoring.Counter
)

func initMetrics() {
	doOnce.Do(func() {
		mf := monitoring.GetMetricFactory()
		const logIDLabel = "logid"
		counterDistRestAttempt = mf.NewCounter("distribute_rest_attempt", "Number of attempts the RESTful distributor has made for the log ID", logIDLabel)
		counterDistRestSuccess = mf.NewCounter("distribute_rest_success", "Number of times the RESTful distributor has succeeded for the log ID", logIDLabel)
	})
}

// LogConfig describes the API contract of a source of logs to be distributed.
type LogConfig interface {
	// Logs should return the _current_ set of logs whose checkpoints should be distributed.
	// This may be called repeatedly by the implementation in order to ensure that changes to the underlying config are reflected in the distribution operation.
	Logs() iter.Seq[config.Log]
}

// NewDistributor creates a new Distributor from the given configuration.
func NewDistributor(baseURL string, client *http.Client, lc LogConfig, witSigV note.Verifier, getLatest GetLatestCheckpointFn) (*Distributor, error) {
	initMetrics()
	return &Distributor{
		baseURL:     baseURL,
		client:      client,
		logConfig:   lc,
		getLatest:   getLatest,
		witnessName: witSigV.Name(),
	}, nil
}

// Distributor distributes checkpoints to a REST API.
type Distributor struct {
	baseURL     string
	client      *http.Client
	logConfig   LogConfig
	getLatest   GetLatestCheckpointFn
	witnessName string
}

// DistributeOnce polls the witness for all logs and pushes the latest checkpoint to the
// RESTful distributor.
func (d *Distributor) DistributeOnce(ctx context.Context) error {
	numErrs := 0
	numLogs := 0
	for log := range d.logConfig.Logs() {
		numLogs++
		if err := d.distributeForLog(ctx, log); err != nil {
			klog.Warningf("Failed to distribute %q (%s): %v", d.baseURL, log.Origin, err)
			numErrs++
		}
	}
	if numErrs > 0 {
		return fmt.Errorf("failed to distribute %d out of %d logs", numErrs, numLogs)
	}
	return nil
}

func (d *Distributor) distributeForLog(ctx context.Context, l config.Log) error {
	logID := l.ID
	counterDistRestAttempt.Inc(logID)

	wRaw, err := d.getLatest(ctx, logID)
	if err != nil {
		return fmt.Errorf("GetLatestFn(%s): %v", logID, err)
	}

	u, err := url.Parse(d.baseURL + fmt.Sprintf(HTTPCheckpointByWitness, logID, url.PathEscape(d.witnessName)))
	if err != nil {
		return fmt.Errorf("failed to parse URL: %v", err)
	}
	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(wRaw))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := d.client.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to do http request: %v", err)
	}
	if resp.Request.Method != http.MethodPut {
		return fmt.Errorf("PUT request to %q was converted to %s request to %q", u.String(), resp.Request.Method, resp.Request.URL)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			klog.Errorf("Failed to close response body: %v", err)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %v", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("bad status response (%s): %q", resp.Status, body)
	}
	klog.V(1).Infof("Distributed checkpoint via REST for %q (%s)", l.Verifier.Name(), logID)
	counterDistRestSuccess.Inc(logID)
	return nil
}
