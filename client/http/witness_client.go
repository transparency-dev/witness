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

	"github.com/transparency-dev/witness/api"
	"github.com/transparency-dev/witness/witness"
	"k8s.io/klog/v2"
)

// maxResponseBodyBytes is the limit on the number of bytes we'll read from incoming responses.
// 16 should be more than enough, even in a PQ world.
const maxResponseBodyBytes int64 = 16 << 10

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

// checkpointSize returns the size from the second line of the provided checkpoint.
//
// The checkpoint is otherwise opaque to this client: no signature verification is performed, and ok
// is false if the size cannot be determined, in which case callers should make no assumptions about
// the checkpoint and let the witness decide.
func checkpointSize(cp []byte) (uint64, bool) {
	parts := bytes.SplitN(cp, []byte{'\n'}, 3)
	if len(parts) < 3 {
		return 0, false
	}
	size, err := strconv.ParseUint(string(parts[1]), 10, 64)
	if err != nil {
		return 0, false
	}
	return size, true
}

// Update attempts to clock the witness forward.
//
// Returns the HTTP status code and the response body, or an error.
func (w Witness) Update(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error) {
	if l := len(proof); l > 63 {
		return nil, 0, errors.New("too many proof lines")
	}
	// SPEC: The old size MUST be equal to or lower than the checkpoint size. Otherwise, the witness
	//       MUST respond with a "400 Bad Request" HTTP status code.
	//
	// We can determine this without asking, which saves a doomed round trip and lets us report the
	// specific cause: a 400 from the witness carries nothing to distinguish it from any other invalid
	// request.
	if size, ok := checkpointSize(newCP); ok && oldSize > size {
		return nil, 0, fmt.Errorf("%w (%d > %d)", witness.ErrOldSizeInvalid, oldSize, size)
	}

	// bytes.Buffer cannot return an error for writes, so we can omit error checking on writes below.
	reqBody := &bytes.Buffer{}

	_, _ = fmt.Fprintf(reqBody, "old %d\n", oldSize)
	for _, p := range proof {
		_, _ = fmt.Fprintln(reqBody, base64.StdEncoding.EncodeToString(p))
	}
	_, _ = fmt.Fprintln(reqBody)
	_, _ = reqBody.Write(newCP)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url.JoinPath(api.HTTPAddCheckpoint).String(), reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := w.client.Do(req)
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read body: %v", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, 0:
		return body, 0, nil
	case http.StatusConflict:
		if resp.Header.Get("Content-Type") == "text/x.tlog.size" {
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
		// SPEC: no response body, Content-Type or header is defined for 400, so we can't tell why the
		//       witness rejected this. The old size case is ruled out before we send.
		return nil, 0, fmt.Errorf("%w (invalid old size, or malformed request)", witness.ErrBadRequest)
	case http.StatusUnprocessableEntity:
		return nil, 0, witness.ErrInvalidProof
	case http.StatusTooManyRequests:
		return nil, 0, witness.ErrPushback
	default:
		return nil, 0, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
}

// SignSubtree attempts to request a subtree cosignature from the witness,
// by providing a checkpoint signed by the witness and a subtree consistency
// proof.
func (w Witness) SignSubtree(ctx context.Context, start, end uint64, subRoot []byte, proof [][]byte, cp []byte) ([]byte, error) {
	if l := len(proof); l > 63 {
		return nil, errors.New("too many proof lines")
	}

	// bytes.Buffer cannot return an error for writes, so we can omit error checking on writes below.
	reqBody := &bytes.Buffer{}

	_, _ = fmt.Fprintf(reqBody, "subtree %d %d\n", start, end)
	_, _ = fmt.Fprintln(reqBody, base64.StdEncoding.EncodeToString(subRoot))
	for _, p := range proof {
		_, _ = fmt.Fprintln(reqBody, base64.StdEncoding.EncodeToString(p))
	}
	_, _ = fmt.Fprintln(reqBody)
	_, _ = reqBody.Write(cp)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url.JoinPath(api.HTTPSignSubtree).String(), reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do http request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			klog.Errorf("Failed to close response body: %v", err)
		}
	}()

	if resp.Request.Method != http.MethodPost {
		return nil, fmt.Errorf("POST request to %q was converted to %s request to %q", w.url.String(), resp.Request.Method, resp.Request.URL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}

	switch resp.StatusCode {
	case http.StatusOK, 0:
		return body, nil
	case http.StatusBadRequest:
		// SPEC: 400 covers every invalid sign-subtree request (range line, subtree range, malformed
		//       checkpoint), with nothing in the response to say which rule was broken.
		return nil, fmt.Errorf("%w (invalid subtree range, or malformed request)", witness.ErrBadRequest)
	case http.StatusForbidden:
		return nil, witness.ErrNoWitnessSignature
	case http.StatusNotFound:
		return nil, witness.ErrUnknownLog
	case http.StatusUnprocessableEntity:
		return nil, witness.ErrInvalidProof
	case http.StatusNotImplemented:
		return nil, witness.ErrNotImplemented
	case http.StatusTooManyRequests:
		return nil, witness.ErrPushback
	default:
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
}
