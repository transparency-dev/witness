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
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/monitoring"
	"github.com/transparency-dev/witness/monitoring/prometheus"
	"github.com/transparency-dev/witness/omniwitness"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

func init() {
	flag.Var(&publicWitnessConfigs, "public_witness_config_url", "URL of a public witness network config file. May be specified multiple times to configure the union of multiple files.")
}

var (
	addr       = flag.String("listen", ":8080", "Address to listen on")
	spannerURI = flag.String("spanner", "", "Spanner resource URI. Format: projects/{projectName}/instances/{spannerInstance}/databases/{databaseName}.")

	signerPrivateKeySecretName = flag.String("signer_private_key_secret_name", "", "Private key secret name for witnes signatures. Format: projects/{projectId}/secrets/{secretName}/versions/{secretVersion}.")
	httpTimeout                = flag.Duration("http_timeout", 10*time.Second, "HTTP timeout for outbound requests.")

	pollInterval = flag.Duration("poll_interval", 1*time.Minute, "Time to wait between polling logs for new checkpoints. Set to 0 to disable polling logs.")

	additionalLogYaml           = flag.String("additional_logs", "", "The path to an optional addition logs YAML file. Entries in this file will be *added* to the logs configured by default")
	publicWitnessConfigs        multiStringFlag
	publicWitnessConfigInterval = flag.Duration("public_witness_config_poll_interval", 1*time.Minute, "Interval between checking the public witness config for new logs to add.")
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

	mustUpdateLogs(ctx, omniwitness.DefaultConfigLogs, p)
	if *additionalLogYaml != "" {
		y, err := os.ReadFile(*additionalLogYaml)
		if err != nil {
			klog.Exitf("Failed to read additional log config from %q: %v", *additionalLogYaml, err)
		}
		mustUpdateLogs(ctx, y, p)
	}

	if len(publicWitnessConfigs) > 0 {
		go updatePublicWitnessNetworkLogs(ctx, httpClient, p)
	}

	opConfig := omniwitness.OperatorConfig{
		WitnessKeys:     []note.Signer{signer},
		WitnessVerifier: signer.Verifier(),
		FeedInterval:    *pollInterval,
		ServeMux:        mux,
		Logs:            p,
	}
	if err := omniwitness.Main(ctx, opConfig, p, httpListener, httpClient); err != nil {
		klog.Exitf("Main failed: %v", err)
	}
}

func updatePublicWitnessNetworkLogs(ctx context.Context, httpClient *http.Client, p *spannerPersistence) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(*publicWitnessConfigInterval):
		}
		for _, u := range publicWitnessConfigs {
			opts := omniwitness.PublicFetchOpts{
				Client: httpClient,
				URL:    u,
			}
			logs, err := omniwitness.FetchPublicConfig(ctx, opts)
			if err != nil {
				klog.Warningf("Failed to fetch public witness network config from %q: %v", u, err)
				continue
			}

			if err := p.AddLogs(ctx, logs); err != nil {
				klog.Warningf("Failed to update list of logs: %v", err)
				continue
			}
			klog.Infof("Successfully updated public witness config from %q...", u)
		}
	}
}

func mustUpdateLogs(ctx context.Context, y []byte, p *spannerPersistence) {
	l, err := omniwitness.NewStaticLogConfig(y)
	if err != nil {
		klog.Exitf("Failed to parse YAML logs config: %v", err)
	}
	logs := []config.Log{}
	for log, err := range l.Logs(ctx) {
		if err != nil {
			klog.Exitf("Error iterating over logs: %v", err)
		}
		logs = append(logs, log)
	}
	if err := p.AddLogs(ctx, logs); err != nil {
		klog.Exitf("Failed to add default logs to Spanner: %v", err)
	}
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
