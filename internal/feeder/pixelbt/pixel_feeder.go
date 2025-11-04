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

// Package pixelbt is an implementation of a witness feeder for the Pixel BT log.
package pixelbt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/internal/feeder"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"k8s.io/klog/v2"
)

const (
	// tileHeight is the tlog tile height.
	// From: https://developers.google.com/android/binary_transparency/tile
	tileHeight = 1
)

// NewFeedSource returns a FeedSource configured for PixelBT logs.
func NewFeedSource(origin string, verifier note.Verifier, logURL string, c *http.Client) (feeder.Source, error) {
	lURL, err := url.Parse(logURL)
	if err != nil {
		return feeder.Source{}, fmt.Errorf("invalid LogURL %q: %v", logURL, err)
	}

	fetchCP := func(ctx context.Context) ([]byte, error) {
		cpTxt, err := fetch(ctx, c, lURL, "checkpoint.txt")
		if err != nil {
			return nil, fmt.Errorf("failed to fetch checkpoint.txt: %v", err)
		}
		return cpTxt, err
	}
	fetchProof := func(ctx context.Context, from uint64, to log.Checkpoint) ([][]byte, error) {
		if from == 0 {
			return [][]byte{}, nil
		}
		var h [32]byte
		copy(h[:], to.Hash)
		tree := tlog.Tree{
			N:    int64(to.Size),
			Hash: h,
		}
		tr := tileReader{fetch: func(p string) ([]byte, error) {
			return fetch(ctx, c, lURL, p)
		}}

		proof, err := tlog.ProveTree(int64(to.Size), int64(from), tlog.TileHashReader(tree, tr))
		if err != nil {
			return nil, fmt.Errorf("ProveTree: %v", err)
		}
		r := make([][]byte, 0, len(proof))
		for _, h := range proof {
			h := h
			r = append(r, h[:])
		}
		return r, nil
	}

	return feeder.Source{
		LogOrigin:       origin,
		FetchCheckpoint: fetchCP,
		FetchProof:      fetchProof,
		LogSigVerifier:  verifier,
	}, nil
}

type tileReader struct {
	fetch func(p string) ([]byte, error)
}

func (tr tileReader) Height() int { return tileHeight }

func (tr tileReader) SaveTiles([]tlog.Tile, [][]byte) {}

func (tr tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	r := make([][]byte, 0, len(tiles))
	for _, t := range tiles {
		path := fmt.Sprintf("tile/%d/%d/%03d", t.H, t.L, t.N)
		if t.W < 1<<t.H {
			path += fmt.Sprintf(".p/%d", t.W)
		}
		tile, err := tr.fetch(path)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch %q: %v", path, err)
		}
		r = append(r, tile)
	}
	return r, nil
}

func fetch(ctx context.Context, c *http.Client, base *url.URL, path string) ([]byte, error) {
	u, err := base.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	klog.V(2).Infof("GET %s", u.String())
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req = req.WithContext(ctx)

	rsp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to %q: %v", u.String(), err)
	}
	defer func() {
		if err := rsp.Body.Close(); err != nil {
			klog.Errorf("Failed to close response body: %v", err)
		}
	}()

	if rsp.StatusCode == 404 {
		return nil, os.ErrNotExist
	}
	if rsp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status fetching %q: %s", u.String(), rsp.Status)
	}

	return io.ReadAll(rsp.Body)
}
