// Copyright 2021 Google LLC. All Rights Reserved.
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

// Package rfc6962 is an implementation of a witness feeder for RFC6962 logs.
//
// This package uses the sunlight checkpoint representation of RFC6962 Signed Tree Head
// structures in order to be able to feed them natively into the omniwitness.
//
// Note that Signed Tree Heads and sunlight checkpoints are convertible between
// these formats without needing the log private key.
package rfc6962

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/internal/feeder"
	"k8s.io/klog/v2"
)

// proof is a partial representation of the JSON struct returned by the CT
// get-sth-consistency request.
type proof struct {
	Consistency [][]byte `json:"consistency"`
}

// FeedLog feeds checkpoints from the source log to the witness.
// If interval is non-zero, this function will return when the context is done, otherwise it will perform
// one feed cycle and return.
//
// Note that this feeder expects the configured URL to contain a "treeID" query parameter which contains the
// correct Rekor log tree ID.
func FeedLog(ctx context.Context, l config.Log, w feeder.Witness, c *http.Client, interval time.Duration) error {
	lURL, err := url.Parse(l.URL)
	if err != nil {
		return fmt.Errorf("invalid LogURL %q: %v", l.URL, err)
	}

	fetchCP := func(ctx context.Context) ([]byte, error) {
		sth, err := get(ctx, c, lURL, "ct/v1/get-sth")
		if err != nil {
			return nil, fmt.Errorf("failed to fetch STH: %v", err)
		}

		cp, err := note.RFC6962STHToCheckpoint(sth, l.Verifier)
		if err != nil {
			return nil, fmt.Errorf("unable to convert STH to checkpoint: %v", err)
		}
		return cp, nil
	}
	fetchProof := func(ctx context.Context, from, to log.Checkpoint) ([][]byte, error) {
		if from.Size == 0 {
			return [][]byte{}, nil
		}
		cp := proof{}
		if err := getJSON(ctx, c, lURL, fmt.Sprintf("ct/v1/get-sth-consistency?first=%d&second=%d", from.Size, to.Size), &cp); err != nil {
			return nil, fmt.Errorf("failed to fetch consistency proof: %v", err)
		}
		return cp.Consistency, nil
	}

	opts := feeder.FeedOpts{
		LogID:           l.ID,
		LogOrigin:       l.Origin,
		FetchCheckpoint: fetchCP,
		FetchProof:      fetchProof,
		LogSigVerifier:  l.Verifier,
		Witness:         w,
	}
	if interval > 0 {
		return feeder.Run(ctx, interval, opts)
	}
	_, err = feeder.FeedOnce(ctx, opts)
	return err
}

func getJSON(ctx context.Context, c *http.Client, base *url.URL, path string, s interface{}) error {
	raw, err := get(ctx, c, base, path)
	if err != nil {
		return fmt.Errorf("failed to get: %v", err)
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}
	return nil
}

func get(ctx context.Context, c *http.Client, base *url.URL, path string) ([]byte, error) {
	u, err := base.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "application/json")

	rsp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to %q: %v", u.String(), err)
	}
	defer func() {
		if err := rsp.Body.Close(); err != nil {
			klog.Infof("Close: %v", err)
		}
	}()

	if rsp.StatusCode == 404 {
		return nil, os.ErrNotExist
	}
	if rsp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status fetching %q: %s", u.String(), rsp.Status)
	}

	raw, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body from %q: %v", u.String(), err)
	}
	return raw, nil
}
