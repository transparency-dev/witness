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

// Package http is a simple client for interacting with witnesses over HTTP.
package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/transparency-dev/witness/internal/witness"
	"k8s.io/klog/v2"
)

// NewWitness returns a Witness accessed over http at the given URL
// using the client provided.
func NewWitness(url *url.URL, c *http.Client) Witness {
	return Witness{
		url:    url,
		client: c,
	}
}

// Witness is a simple client for interacting with tlog-witness compatible witnesses over HTTP.
type Witness struct {
	url    *url.URL
	client *http.Client
}

// Update attempts to clock the witness forward.
//
// Returns the HTTP status code and the response body, or an error.
func (w Witness) Update(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error) {
	if l := len(proof); l > 63 {
		return nil, 0, errors.New("too many proof lines")
	}

	// bytes.Buffer cannot return an error for writes, so we can omit error checking on writes below.
	reqBody := &bytes.Buffer{}

	_, _ = fmt.Fprintf(reqBody, "old %d\n", oldSize)
	for _, p := range proof {
		_, _ = fmt.Fprintln(reqBody, base64.StdEncoding.EncodeToString(p))
	}
	_, _ = fmt.Fprintln(reqBody)
	_, _ = reqBody.Write(newCP)

	req, err := http.NewRequest(http.MethodPost, w.url.String(), reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := w.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to do http request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			klog.Errorf("Failed to close response body: %v", err)
		}
	}()

	if resp.Request.Method != http.MethodPost {
		return nil, 0, fmt.Errorf("POST request to %q was converted to %s request to %q", w.url.String(), resp.Request.Method, resp.Request.URL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read body: %v", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, 0:
		return body, 0, nil
	case http.StatusConflict:
		if resp.Header.Get(http.CanonicalHeaderKey("Content-Type")) == "text/x.tlog.size" {
			size, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid tlog size in response body: %v", err)
			}
			return nil, size, witness.ErrCheckpointStale
		}
		return nil, 0, witness.ErrRootMismatch
	case http.StatusNotFound:
		return nil, 0, witness.ErrUnknownLog
	case http.StatusForbidden:
		return nil, 0, witness.ErrNoValidSignature
	case http.StatusBadRequest:
		return nil, 0, witness.ErrOldSizeInvalid
	case http.StatusUnprocessableEntity:
		return nil, 0, witness.ErrInvalidProof
	default:
		return nil, 0, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
}
