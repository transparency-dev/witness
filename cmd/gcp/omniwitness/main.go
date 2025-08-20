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
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
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
	addr        = flag.String("listen", ":8080", "Address to listen on")
	metricsAddr = flag.String("metrics_listen", ":8081", "Address to listen on for metrics")
	spannerURI  = flag.String("spanner", "", "Spanner resource URI. Format: projects/{projectName}/instances/{spannerInstance}/databases/{databaseName}")

	signerPrivateKeySecretName = flag.String("signer_private_key_secret_name", "", "Private key secret name for witnes signatures. Format: projects/{projectId}/secrets/{secretName}/versions/{secretVersion}.")
	restDistributorBaseURL     = flag.String("rest_distro_url", "", "Optional base URL to a distributor that takes witnessed checkpoints via a PUT request")
	bastionAddr                = flag.String("bastion_addr", "", "host:port of the bastion to connect to, or empty to not connect to a bastion")
	bastionKeyPath             = flag.String("bastion_key_path", "", "Path to a file containing an ed25519 private key in PKCS8 PEM format")
	rateLimit                  = flag.Float64("rate_limit", 0, "Maximum number of update requests per second to serve, or zero to disable")
	httpTimeout                = flag.Duration("http_timeout", 10*time.Second, "HTTP timeout for outbound requests")

	pollInterval = flag.Duration("poll_interval", 1*time.Minute, "Time to wait between polling logs for new checkpoints. Set to 0 to disable polling logs.")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	defer klog.Flush()

	ctx := context.Background()

	if *metricsAddr == "" {
		klog.Info("No metrics_listen address provided so skipping prometheus setup")
		mf := monitoring.InertMetricFactory{}
		monitoring.SetMetricFactory(mf)
	} else {
		mf := prometheus.MetricFactory{
			Prefix: "omniwitness_",
		}
		monitoring.SetMetricFactory(mf)

		go func() {
			http.Handle("/metrics", promhttp.Handler())
			srv := &http.Server{
				Addr:         *metricsAddr,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
			}
			if err := srv.ListenAndServe(); err != http.ErrServerClosed {
				klog.Errorf("Error serving metrics: %v", err)
			}
		}()
		klog.Infof("Prometheus configured to listen on %q", *metricsAddr)
	}

	httpListener, err := net.Listen("tcp", *addr)
	if err != nil {
		klog.Fatalf("failed to listen on %q", *addr)
	}
	httpClient := &http.Client{
		Timeout: *httpTimeout,
	}

	var bastionKey ed25519.PrivateKey
	if *bastionKeyPath != "" {
		bastionKey, err = readPrivateKey(*bastionKeyPath)
		if err != nil {
			klog.Exitf("Failed to read provided bastion key file %q: %v", *bastionKeyPath, err)
		}
	}

	signer, err := NewSecretManagerSigner(ctx, *signerPrivateKeySecretName)
	if err != nil {
		klog.Exitf("Failed to init signer v1: %v", err)
	}

	opConfig := omniwitness.OperatorConfig{
		WitnessKeys:            []note.Signer{signer},
		WitnessVerifier:        signer.Verifier(),
		RestDistributorBaseURL: *restDistributorBaseURL,
		BastionAddr:            *bastionAddr,
		BastionKey:             bastionKey,
		RateLimit:              *rateLimit,
		FeedInterval:           *pollInterval,
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

	if err := omniwitness.Main(ctx, opConfig, p, httpListener, httpClient); err != nil {
		klog.Exitf("Main failed: %v", err)
	}
}

func readPrivateKey(f string) (ed25519.PrivateKey, error) {
	p, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read from %q: %v", f, err)
	}

	b, _ := pem.Decode(p)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key file %q: %v", f, err)
	}

	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}

	e, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("incorrect private key type %T, must be ed25519", e)
	}
	return e, nil

}
