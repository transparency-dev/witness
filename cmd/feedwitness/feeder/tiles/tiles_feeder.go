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
	"golang.org/x/mod/sumdb/note"
)

// NewFeedSource returns a populated feeder.NewFeedSource configured for a tlog-tiles log.
func NewFeedSource(origin string, verifier note.Verifier, logURL string, c *http.Client) (*Source, error) {
	lURL, err := url.Parse(logURL)
	if err != nil {
		return nil, fmt.Errorf("invalid LogURL %q: %v", logURL, err)
	}
	f, err := newHTTPFetcher(lURL, c)
	if err != nil {
		return nil, fmt.Errorf("failed to create fetcher: %v", err)
	}

	return &Source{
		v:       verifier,
		origin:  origin,
		fetcher: f,
	}, nil
}

// Source is a FeederSource which knows how to interact with tlog-tiles logs.
type Source struct {
	v       note.Verifier
	origin  string
	fetcher *httpFetcher
}

func (s Source) FetchCheckpoint(ctx context.Context) ([]byte, error) {
	return s.fetcher.ReadCheckpoint(ctx)
}

func (s Source) FetchProof(ctx context.Context, from uint64, to log.Checkpoint) ([][]byte, error) {
	if from == 0 {
		return [][]byte{}, nil
	}
	pb, err := newProofBuilder(ctx, to.Size, s.fetcher.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof builder for %q: %v", s.origin, err)
	}

	conP, err := pb.ConsistencyProof(ctx, from, to.Size)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof for %q(%d -> %d): %v", s.origin, from, to.Size, err)
	}
	return conP, nil
}

func (s Source) LogSigVerifier() note.Verifier {
	return s.v
}

func (s Source) LogOrigin() string {
	return s.origin
}
