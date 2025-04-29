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
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/trillian-tessera/client"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/internal/feeder"
)

// FeedLog periodically feeds checkpoints from the log to the witness.
// This function returns once the provided context is done.
func FeedLog(ctx context.Context, l config.Log, update feeder.UpdateFn, c *http.Client, interval time.Duration) error {
	lURL, err := url.Parse(l.URL)
	if err != nil {
		return fmt.Errorf("invalid LogURL %q: %v", l.URL, err)
	}
	f, err := client.NewHTTPFetcher(lURL, c)
	if err != nil {
		return fmt.Errorf("failed to create fetcher: %v", err)
	}

	fetchProof := func(ctx context.Context, from uint64, to log.Checkpoint) ([][]byte, error) {
		if from == 0 {
			return [][]byte{}, nil
		}
		pb, err := client.NewProofBuilder(ctx, to.Size, f.ReadTile)
		if err != nil {
			return nil, fmt.Errorf("failed to create proof builder for %q: %v", l.Origin, err)
		}

		conP, err := pb.ConsistencyProof(ctx, from, to.Size)
		if err != nil {
			return nil, fmt.Errorf("failed to create proof for %q(%d -> %d): %v", l.Origin, from, to.Size, err)
		}
		return conP, nil
	}

	opts := feeder.FeedOpts{
		LogID:           l.ID,
		LogOrigin:       l.Origin,
		FetchCheckpoint: f.ReadCheckpoint,
		FetchProof:      fetchProof,
		LogSigVerifier:  l.Verifier,
		Update:          update,
	}
	if interval > 0 {
		return feeder.Run(ctx, interval, opts)
	}
	_, err = feeder.FeedOnce(ctx, opts)
	return err
}
