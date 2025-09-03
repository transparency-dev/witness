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

// gcp/omniwitness is a single executable that runs a witness using GCP services.
package main

import (
	"context"
	"flag"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/witness/monitoring"
	"github.com/transparency-dev/witness/monitoring/prometheus"
	"github.com/transparency-dev/witness/omniwitness"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	addr       = flag.String("listen", ":8080", "Address to listen on")
	spannerURI = flag.String("spanner", "", "Spanner resource URI. Format: projects/{projectName}/instances/{spannerInstance}/databases/{databaseName}.")

	signerPrivateKeySecretName = flag.String("signer_private_key_secret_name", "", "Private key secret name for witnes signatures. Format: projects/{projectId}/secrets/{secretName}/versions/{secretVersion}.")
	httpTimeout                = flag.Duration("http_timeout", 10*time.Second, "HTTP timeout for outbound requests.")

	pollInterval      = flag.Duration("poll_interval", 1*time.Minute, "Time to wait between polling logs for new checkpoints. Set to 0 to disable polling logs.")
	feederConcurrency = flag.Uint("feeder_concurrency", 1, "Maximum number of concurrent feeder tasks")
	additionalLogYaml = flag.String("additional_logs", "", "The path to an optional addition logs YAML file. Entries in this file will be *added* to the logs configured by default")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	defer klog.Flush()

	ctx := context.Background()

	mf := prometheus.MetricFactory{
		Prefix: "omniwitness_",
	}
	monitoring.SetMetricFactory(mf)
	mux := &http.ServeMux{}
	mux.Handle("/metrics", promhttp.Handler())
	klog.Infof("Prometheus configured on %s", *addr)

	httpListener, err := net.Listen("tcp", *addr)
	if err != nil {
		klog.Fatalf("failed to listen on %q", *addr)
	}
	httpClient := &http.Client{
		Timeout: *httpTimeout,
	}

	signer, err := NewSecretManagerSigner(ctx, *signerPrivateKeySecretName)
	if err != nil {
		klog.Exitf("Failed to init signer v1: %v", err)
	}

	p, shutdown, err := newSpannerPersistence(ctx, *spannerURI)
	if err != nil {
		klog.Exitf("Failed to create spanner persistence: %v", err)
	}
	defer func() {
		if err := shutdown(); err != nil {
			klog.Warningf("shutdown: %v", err)
		}
	}()

	logs, err := omniwitness.NewStaticLogConfig(omniwitness.DefaultConfigLogs)
	if err != nil {
		klog.Exitf("Failed to parse default logs config: %v", err)
	}
	if *additionalLogYaml != "" {
		y, err := os.ReadFile(*additionalLogYaml)
		if err != nil {
			klog.Exitf("Failed to read additional log config from %q: %v", *additionalLogYaml, err)
		}
		additional, err := omniwitness.NewStaticLogConfig(y)
		if err != nil {
			klog.Exitf("Failed to parse additional log config from %q: %v", *additionalLogYaml, err)
		}
		logs.Merge(additional)
	}

	opConfig := omniwitness.OperatorConfig{
		WitnessKeys:      []note.Signer{signer},
		WitnessVerifier:  signer.Verifier(),
		FeedInterval:     *pollInterval,
		NumFeederWorkers: *feederConcurrency,
		ServeMux:         mux,
		Logs:             p,
	}
	if err := omniwitness.Main(ctx, opConfig, p, httpListener, httpClient); err != nil {
		klog.Exitf("Main failed: %v", err)
	}
}
