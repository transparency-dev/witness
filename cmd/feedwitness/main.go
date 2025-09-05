// Copyright 2024 Google LLC. All Rights Reserved.
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

// feedwitness is a tool for submitting checkpoints from known logs
// to witnesses, either directly or behind bastions.
//
// The primary use case for this tool is testing bastion and/or witness setups,
// but it may also be useful for feeding checkpoints from logs which do not
// actively participate in witnessing to witnesses.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	w_http "github.com/transparency-dev/witness/client/http"
	"github.com/transparency-dev/witness/internal/feeder"
	"github.com/transparency-dev/witness/internal/witness"
	"github.com/transparency-dev/witness/monitoring"
	"github.com/transparency-dev/witness/monitoring/prometheus"
	"github.com/transparency-dev/witness/omniwitness"
	"k8s.io/klog/v2"
)

func init() {
	flag.Var(&witnessURL, "witness_url", "Root URL of the witness to submit checkpoints to (either directly, or via a bastion), can be specified multple times to submit to multiple witnesses")
}

var (
	witnessURL    multiStringFlag
	httpsInsecure = flag.Bool("https_insecure", false, "Set to true to disable TLS verification of the witness service")
	feed          = flag.String("feed", ".*", "RegEx matching log origins to feed checkpoints from")
	loopInterval  = flag.Duration("loop_interval", 0, "If set to > 0, runs in looping mode sleeping this duration between feed attempts")
	rateLimit     = flag.Float64("max_qps", 2, "Defines maximum number of requests/s to send per witness")
	metricsAddr   = flag.String("metrics_listen", ":8081", "Address to listen on for metrics")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	defer klog.Flush()

	ctx := context.Background()

	cfg, err := omniwitness.NewStaticLogConfig(omniwitness.DefaultConfigLogs)
	if err != nil {
		klog.Exitf("failed to instantiate default witness config: %v", err)
	}

	if len(witnessURL) == 0 {
		klog.Exitf("At least one --witness_url must be specifed")
	}

	if *metricsAddr != "" {
		mf := prometheus.MetricFactory{
			Prefix: "omnifeeder_",
		}
		monitoring.SetMetricFactory(mf)

		http.Handle("/metrics", promhttp.Handler())
		go func() {
			if err := http.ListenAndServe(*metricsAddr, nil); err != nil {
				klog.Errorf("ListenAndServe: %v", err)
			}
		}()
		klog.Infof("Prometheus configured to listen on %q", *metricsAddr)
	}

	httpClient := httpClientFromFlags()

	witnesses := []feeder.UpdateFn{}
	for _, wu := range witnessURL {
		u, err := url.Parse(wu)
		if err != nil {
			klog.Exitf("Invalid witness URL %q: %v", wu, err)
		}
		lc := loggingClient{
			witness: w_http.NewWitness(u, httpClient),
			url:     wu,
		}
		witnesses = append(witnesses, lc.Update)
	}

	rOpts := omniwitness.RunFeedOpts{
		Witnesses:     witnesses,
		HTTPClient:    httpClient,
		MaxWitnessQPS: *rateLimit,
		MatchLogs:     *feed,
		LogConfig:     cfg,
	}
	if err := omniwitness.RunFeeders(ctx, rOpts); err != nil {
		klog.Errorf("%v", err)
	}
}

type loggingClient struct {
	witness w_http.Witness
	url     string
}

// Update attempts to clock the witness forward for the given logID.
// The latest signed checkpoint will be returned if this succeeds, or if the error is
// http.ErrCheckpointTooOld. In all other cases no checkpoint should be expected.
func (lc *loggingClient) Update(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error) {
	rb, size, err := lc.witness.Update(ctx, oldSize, newCP, proof)

	switch name := strings.Split(string(newCP), "\n")[0]; {
	case err == nil:
		klog.Infof("✅ %s ← %s: updated with signature(s):\n%s", lc.url, name, string(rb))
	case errors.Is(err, witness.ErrCheckpointStale):
		msg := fmt.Sprintf("View stale, witness has checkpoint size %d (we have %d)", size, oldSize)
		klog.Infof("🫣 %s ← %s: conflict: %s", lc.url, name, msg)
	default:
		klog.Infof("❌ %s ← %s: %v", lc.url, name, err)
	}

	return rb, size, err
}

// multiStringFlag allows a flag to be specified multiple times on the command
// line, and stores all of these values.
type multiStringFlag []string

func (ms *multiStringFlag) String() string {
	return strings.Join(*ms, ",")
}

func (ms *multiStringFlag) Set(w string) error {
	*ms = append(*ms, w)
	return nil
}

func httpClientFromFlags() *http.Client {
	t := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          len(witnessURL) + 10,
		MaxIdleConnsPerHost:   2,
	}
	if *httpsInsecure {
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Transport: t,
	}
}
