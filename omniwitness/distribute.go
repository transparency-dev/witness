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

package omniwitness

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"sync"

	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/monitoring"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

const (
	// httpCheckpointByWitness is the path of the URL to the latest checkpoint
	// for a given log by a given witness. This can take PUT requests to update
	// the latest checkpoint.
	//  * first position is for the logID (an alphanumeric string)
	//  * second position is the witness short name (alpha string)
	httpCheckpointByWitness = "/distributor/v0/logs/%s/byWitness/%s/checkpoint"
)

// GetLatestCheckpointFn is the signature of a function which returns the latest checkpoint the witness holds for the given logID.
// Implementations must return os.ErrNotExists if the logID is known, but it has no checkpoint for that log.
type getLatestCheckpointFn func(ctx context.Context, logID string) ([]byte, error)

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

// logsFn should return the _current_ set of logs whose checkpoints should be distributed.
// This may be called repeatedly by the implementation in order to ensure that changes to the underlying config are reflected in the distribution operation.
type logsFn func(context.Context) iter.Seq2[Log, error]

// newDistributor creates a new Distributor from the given configuration.
func newDistributor(baseURL string, client *http.Client, logs logsFn, witSigV note.Verifier, getLatest getLatestCheckpointFn, rateLimit float64) (*distributor, error) {
	initMetrics()
	return &distributor{
		baseURL:     baseURL,
		client:      client,
		logs:        logs,
		getLatest:   getLatest,
		witnessName: witSigV.Name(),
		rateLimiter: rate.NewLimiter(rate.Limit(rateLimit), max(1, int(rateLimit))),
	}, nil
}

// distributor distributes checkpoints to a REST API.
type distributor struct {
	baseURL     string
	client      *http.Client
	logs        logsFn
	getLatest   getLatestCheckpointFn
	witnessName string
	rateLimiter *rate.Limiter
}

// DistributeOnce polls the witness for all logs and pushes the latest checkpoint to the
// RESTful distributor.
func (d *distributor) DistributeOnce(ctx context.Context) error {
	numErrs := 0
	numLogs := 0
	for log, err := range d.logs(ctx) {
		if err != nil {
			return fmt.Errorf("failed to enumerate logs: %v", err)
		}
		if err := d.rateLimiter.Wait(ctx); err != nil {
			return err
		}
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

func (d *distributor) distributeForLog(ctx context.Context, l Log) error {
	logID := f_log.ID(l.Origin)
	counterDistRestAttempt.Inc(l.Origin)

	wRaw, err := d.getLatest(ctx, l.Origin)
	if err != nil {
		return fmt.Errorf("GetLatestFn(%s): %v", l.Origin, err)
	}

	u, err := url.Parse(d.baseURL + fmt.Sprintf(httpCheckpointByWitness, logID, url.PathEscape(d.witnessName)))
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
	klog.V(1).Infof("Distributed checkpoint via REST for %q (%s)", l.Verifier.Name(), l.Origin)
	counterDistRestSuccess.Inc(l.Origin)
	return nil
}
