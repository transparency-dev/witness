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

// feedbastion is a one-shot tool for submitting checkpoints from known logs
// to witnesses behind bastions.
//
// The primary use case for this tool is testing a bastion + witness setup.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"io"
	"net/http"
	"os"
	"regexp"

	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/omniwitness"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
)

var (
	bastionURL   = flag.String("bastion_url", "https://localhost:8443", "URL of the bastion service")
	feed         = flag.String("feed", ".*", "RegEx matching log origins to feed to bastion")
	loopInterval = flag.Duration("loop_interval", 0, "If set to > 0, runs in looping mode sleeping this duration between feed attempts")
	rateLimit    = flag.Float64("max_qps", 2, "Defines maximum number of requests/s to send via bastion")
)

type logFeeder struct {
	cfg  config.Log
	info omniwitness.LogInfo
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	defer klog.Flush()

	ctx := context.Background()
	rl := rate.NewLimiter(rate.Limit(*rateLimit), 1)

	httpClient := &http.Client{}
	insecureHttpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	}
	cfg := omniwitness.LogConfig{}
	if err := yaml.Unmarshal(omniwitness.ConfigLogs, &cfg); err != nil {
		klog.Exitf("failed to unmarshal witness config: %v", err)
	}

	feeders := make(map[string]logFeeder)
	originByID := make(map[string]string)
	for _, l := range cfg.Logs {
		lc, err := config.NewLog(l.Origin, l.PublicKey, l.URL)
		if err != nil {
			klog.Exitf("invalid log configuration: %v", err)
		}
		if l.Feeder != omniwitness.None {
			feeders[l.Origin] = logFeeder{
				cfg:  lc,
				info: l,
			}
		}
		originByID[lc.ID] = l.Origin
	}

	r := regexp.MustCompile(*feed)
	bc := &bastionClient{
		httpClient:    insecureHttpClient,
		url:           *bastionURL,
		originByLogID: originByID,
	}
	eg := errgroup.Group{}
	for o, lf := range feeders {
		lf := lf
		if r.Match([]byte(o)) {
			eg.Go(func() error {
				if err := rl.Wait(ctx); err != nil {
					return err
				}
				return lf.info.Feeder.FeedFunc()(ctx, lf.cfg, bc, httpClient, *loopInterval)
			})
		}
	}
	if err := eg.Wait(); err != nil {
		klog.Errorf("%v", err)
	}
}

type bastionClient struct {
	httpClient    *http.Client
	url           string
	originByLogID map[string]string
}

// GetLatestCheckpoint returns the latest checkpoint the witness holds for the given logID.
// Must return os.ErrNotExists if the logID is known, but it has no checkpoint for that log.
func (b *bastionClient) GetLatestCheckpoint(ctx context.Context, logID string) ([]byte, error) {
	// Unfortunately we don't have a way of getting this, so we'll just lie and pretend the witness has no checkpoints for this log.
	return nil, os.ErrNotExist
}

// Update attempts to clock the witness forward for the given logID.
// The latest signed checkpoint will be returned if this succeeds, or if the error is
// http.ErrCheckpointTooOld. In all other cases no checkpoint should be expected.
func (b *bastionClient) Update(ctx context.Context, logID string, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, error) {
	// The request body MUST be a sequence of
	// - a previous size line,
	// - zero or more consistency proof lines,
	// - and an empty line,
	// - followed by a [checkpoint][].
	body := "old 0\n"
	for _, p := range proof {
		body += base64.StdEncoding.EncodeToString(p) + "\n"
	}
	body += "\n"
	body += string(newCP)

	klog.V(1).Infof("sending:\n%s", body)
	resp, err := b.httpClient.Post(b.url, "", bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		klog.Errorf("failed to read response body: %v", err)
	}
	defer resp.Body.Close()
	name := logID
	if o, ok := b.originByLogID[logID]; ok {
		name = o
	}
	klog.Infof("%s: %v: %s", name, resp.Status, string(rb))
	return nil, nil
}
