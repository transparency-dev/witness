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

// Package rekor is an implementation of a witness feeder for the Sigstore log: Rekór.
package rekor_v1

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/internal/feeder"
	"k8s.io/klog/v2"
)

// inactiveShardLogInfo is a presentation of the JSON object returned
// by Rekor when there are inactive shards.
type inactiveShardLogInfo struct {
	RootHash string `json:"rootHash"`
	// SignedTreeHead contains a Rekór checkpoint.
	SignedTreeHead string `json:"signedTreeHead"`
	TreeID         string `json:"treeID"`
	TreeSize       int64  `json:"treeSize"`
}

// logInfo is a representation of the JSON object returned by Rekór's
// api/v1/log request.
type logInfo struct {
	// SignedTreeHead contains a Rekór checkpoint.
	SignedTreeHead string                 `json:"signedTreeHead"`
	RootHash       string                 `json:"rootHash"`
	TreeID         string                 `json:"treeID"`
	TreeSize       int64                  `json:"treeSize"`
	InactiveShards []inactiveShardLogInfo `json:"inactiveShards"`
}

// proof is a partial representation of the JSON struct returned by the Rekór
// api/v1/log/proof request.
type proof struct {
	Hashes []string `json:"hashes"`
}

// NewFeedSource returns a populated FeedSource struct configured for Rekor v1 logs.
func NewFeedSource(l config.Log, c *http.Client) (feeder.Source, error) {
	lURL, err := url.Parse(l.URL)
	if err != nil {
		return feeder.Source{}, fmt.Errorf("invalid LogURL %q: %v", l.URL, err)
	}
	treeID := lURL.Query().Get("treeID")
	if treeID == "" {
		return feeder.Source{}, errors.New("configured LogURL does not contain the required treeID query parameter")
	}

	fetchCP := func(ctx context.Context) ([]byte, error) {
		// Each Rekor feeder will request the same log info.
		// TODO: Explore if it's feasible to request this once for all Rekor feeders.
		li := logInfo{}
		if err := getJSON(ctx, c, lURL, "api/v1/log", &li); err != nil {
			return nil, fmt.Errorf("failed to fetch log info: %v", err)
		}
		// Active shard
		if li.TreeID == treeID {
			return []byte(li.SignedTreeHead), nil
		}
		// Search inactive shards
		for _, shard := range li.InactiveShards {
			if shard.TreeID == treeID {
				return []byte(shard.SignedTreeHead), nil
			}
		}
		return nil, fmt.Errorf("failed to find shard that matched log ID %s from config", l.ID)
	}
	fetchProof := func(ctx context.Context, from uint64, to log.Checkpoint) ([][]byte, error) {
		if from == 0 {
			return [][]byte{}, nil
		}
		cp := proof{}
		if err := getJSON(ctx, c, lURL, fmt.Sprintf("api/v1/log/proof?firstSize=%d&lastSize=%d&treeID=%s", from, to.Size, treeID), &cp); err != nil {
			return nil, fmt.Errorf("failed to fetch log info: %v", err)
		}
		var err error
		p := make([][]byte, len(cp.Hashes))
		for i := range cp.Hashes {
			p[i], err = hex.DecodeString(cp.Hashes[i])
			if err != nil {
				return nil, fmt.Errorf("invalid proof element at %d: %v", i, err)
			}
		}
		return p, nil
	}

	return feeder.Source{
		LogID:           l.ID,
		LogOrigin:       l.Origin,
		FetchCheckpoint: fetchCP,
		FetchProof:      fetchProof,
		LogSigVerifier:  l.Verifier,
	}, nil

}

func getJSON(ctx context.Context, c *http.Client, base *url.URL, path string, s interface{}) error {
	u, err := base.Parse(path)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "application/json")

	rsp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request to %q: %v", u.String(), err)
	}
	defer func() {
		if err := rsp.Body.Close(); err != nil {
			klog.Errorf("Failed to close response body: %v", err)
		}
	}()

	if rsp.StatusCode == 404 {
		return os.ErrNotExist
	}
	if rsp.StatusCode != 200 {
		return fmt.Errorf("unexpected status fetching %q: %s", u.String(), rsp.Status)
	}

	raw, err := io.ReadAll(rsp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body from %q: %v", u.String(), err)
	}
	if err := json.Unmarshal(raw, s); err != nil {
		klog.Infof("Got body:\n%s", string(raw))
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}
	return nil
}
