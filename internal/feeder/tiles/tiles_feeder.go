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

// Package tiles is an implementation of a witness feeder for C2SP tlog-tiles compatible logs.
package tiles

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/trillian-tessera/client"
	"github.com/transparency-dev/witness/internal/feeder"
	"golang.org/x/mod/sumdb/note"
)

// NewFeedSource returns a populated feeder.NewFeedSource configured for a tlog-tiles log.
func NewFeedSource(origin string, verifier note.Verifier, logURL string, c *http.Client) (feeder.Source, error) {
	lURL, err := url.Parse(logURL)
	if err != nil {
		return feeder.Source{}, fmt.Errorf("invalid LogURL %q: %v", logURL, err)
	}
	f, err := client.NewHTTPFetcher(lURL, c)
	if err != nil {
		return feeder.Source{}, fmt.Errorf("failed to create fetcher: %v", err)
	}

	fetchProof := func(ctx context.Context, from uint64, to log.Checkpoint) ([][]byte, error) {
		if from == 0 {
			return [][]byte{}, nil
		}
		pb, err := client.NewProofBuilder(ctx, to.Size, f.ReadTile)
		if err != nil {
			return nil, fmt.Errorf("failed to create proof builder for %q: %v", origin, err)
		}

		conP, err := pb.ConsistencyProof(ctx, from, to.Size)
		if err != nil {
			return nil, fmt.Errorf("failed to create proof for %q(%d -> %d): %v", origin, from, to.Size, err)
		}
		return conP, nil
	}

	return feeder.Source{
		LogOrigin:       origin,
		FetchCheckpoint: f.ReadCheckpoint,
		FetchProof:      fetchProof,
		LogSigVerifier:  verifier,
	}, nil
}
