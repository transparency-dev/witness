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

// Package sumdb implements a feeder for the Go SumDB log.
package sumdb

import (
	"context"
	"fmt"
	"net/http"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/internal/client"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/internal/feeder"
	"golang.org/x/mod/sumdb/tlog"
	"k8s.io/klog/v2"
)

const (
	tileHeight    = 8
	leavesPerTile = 1 << tileHeight
)

// FeedLog continually feeds checkpoints from the given log into the witness.
// This method blocks until the context is done.
func FeedLog(ctx context.Context, l config.Log, sizeHint uint64, update feeder.UpdateFn, c *http.Client) (uint64, error) {
	sdb := client.NewSumDB(tileHeight, l.Verifier, l.URL, c)

	fetchProof := func(ctx context.Context, from uint64, to log.Checkpoint) ([][]byte, error) {
		if from == 0 {
			return [][]byte{}, nil
		}
		tr := tileReader{c: sdb}
		tree := tlog.Tree{
			N:    int64(to.Size),
			Hash: tlog.Hash(to.Hash),
		}
		proof, err := tlog.ProveTree(int64(to.Size), int64(from), tlog.TileHashReader(tree, tr))
		if err != nil {
			return nil, fmt.Errorf("ProveTree: %v", err)
		}
		r := make([][]byte, 0, len(proof))
		for _, h := range proof {
			h := h
			r = append(r, h[:])
		}
		klog.V(1).Infof("Fetched proof from %d -> %d", from, to.Size)
		return r, nil
	}

	fetchCheckpoint := func(_ context.Context) ([]byte, error) {
		sdbcp, err := sdb.LatestCheckpoint()
		if err != nil {
			return nil, fmt.Errorf("failed to get latest checkpoint: %v", err)
		}
		return sdbcp.Raw, nil

	}

	opts := feeder.FeedOpts{
		LogID:           l.ID,
		LogOrigin:       l.Origin,
		FetchCheckpoint: fetchCheckpoint,
		FetchProof:      fetchProof,
		LogSigVerifier:  l.Verifier,
		Update:          update,
	}

	newSize, err := feeder.FeedOnce(ctx, sizeHint, opts)
	return newSize, err
}

type tileReader struct {
	c *client.SumDBClient
}

func (tr tileReader) Height() int { return tileHeight }

func (tr tileReader) SaveTiles([]tlog.Tile, [][]byte) {}

func (tr tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	r := make([][]byte, 0, len(tiles))
	for _, t := range tiles {
		width := t.W
		if width == leavesPerTile {
			width = -1
		}
		tile, err := tr.c.TileData(t.L, int(t.N), width)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch tile data: %v", err)
		}
		r = append(r, tile)
	}
	return r, nil
}
