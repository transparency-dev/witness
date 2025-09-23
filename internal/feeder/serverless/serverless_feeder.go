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

// Package serverless is an implementation of a witness feeder for serverless logs.
package serverless

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/serverless-log/client"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/internal/feeder"
	"k8s.io/klog/v2"
)

// NewFeedSource returns a populated FeedSource configured for a serverless log.
func NewFeedSource(l config.Log, c *http.Client) (feeder.Source, error) {
	lURL, err := url.Parse(l.URL)
	if err != nil {
		return feeder.Source{}, fmt.Errorf("invalid LogURL %q: %v", l.URL, err)
	}
	f := newFetcher(c, lURL)
	h := rfc6962.DefaultHasher

	fetchCP := func(ctx context.Context) ([]byte, error) {
		return f(ctx, "checkpoint")
	}
	fetchProof := func(ctx context.Context, from uint64, to log.Checkpoint) ([][]byte, error) {
		if from == 0 {
			return [][]byte{}, nil
		}
		pb := client.NewProofBuilderForSize(ctx, to.Size, h.HashChildren, f)

		conP, err := pb.ConsistencyProof(ctx, from, to.Size)
		if err != nil {
			return nil, fmt.Errorf("failed to create proof for %q(%d -> %d): %v", l.Origin, from, to.Size, err)
		}
		return conP, nil
	}

	return feeder.Source{
		LogID:           l.ID,
		LogOrigin:       l.Origin,
		FetchCheckpoint: fetchCP,
		FetchProof:      fetchProof,
		LogSigVerifier:  l.Verifier,
	}, nil
}

// TODO(al): factor this stuff out and share between tools:
// Consider moving client.Fetcher to somewhere more general, and then
// replacing http.Client with this Fetcher in all feeder impls.

// newFetcher creates a Fetcher for the log at the given root location.
// If the scheme is http/https then the client provided will be used.
func newFetcher(c *http.Client, root *url.URL) client.Fetcher {
	var get func(context.Context, *url.URL) ([]byte, error)
	switch root.Scheme {
	case "http":
		fallthrough
	case "https":
		get = func(ctx context.Context, u *url.URL) ([]byte, error) {
			req, err := http.NewRequest(http.MethodGet, u.String(), nil)
			if err != nil {
				return nil, err
			}
			resp, err := c.Do(req.WithContext(ctx))
			if err != nil {
				return nil, err
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					klog.Errorf("Failed to close response body: %v", err)
				}
			}()
			return io.ReadAll(resp.Body)
		}
	case "file":
		get = func(_ context.Context, u *url.URL) ([]byte, error) {
			return os.ReadFile(u.Path)
		}
	default:
		panic(fmt.Errorf("unsupported URL scheme %s", root.Scheme))
	}

	return func(ctx context.Context, p string) ([]byte, error) {
		u, err := root.Parse(p)
		if err != nil {
			return nil, err
		}
		return get(ctx, u)
	}
}
