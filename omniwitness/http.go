// Copyright 2025 Google LLC. All Rights Reserved.
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

package omniwitness

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/transparency-dev/witness/internal/witness"
	"github.com/transparency-dev/witness/monitoring"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

// maxRequestBodyBytes is the limit on the number of bytes we'll read from incoming requests.
// 10KB should be more than enough, even in a PQ world.
const maxRequestBodyBytes = 10 << 10

var (
	httpDoOnce                  sync.Once
	counterHTTPIncomingRequest  monitoring.Counter
	counterHTTPIncomingResponse monitoring.Counter
	counterHTTPIncomingPushback monitoring.Counter
)

func initHTTPMetrics() {
	httpDoOnce.Do(func() {
		mf := monitoring.GetMetricFactory()
		const (
			origin = "origin"
			status = "status"
		)

		counterHTTPIncomingRequest = mf.NewCounter("http_request", "Number of HTTP requests received")
		counterHTTPIncomingResponse = mf.NewCounter("http_response", "HTTP responses", origin, status)
		counterHTTPIncomingPushback = mf.NewCounter("http_pushback", "Number of pushed-back HTTP requests")
	})
}

// httpHandler knows how to handle tlog-witness HTTP requests.
type httpHandler struct {
	update      func(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error)
	logs        LogConfig
	witVerifier note.Verifier
	limiter     *rate.Limiter
}

// ServeHTTP is a http.Handler which speaks the tlog-witness protocol.
func (a *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		_ = r.Body.Close()
	}()
	counterHTTPIncomingRequest.Inc()

	if a.limiter != nil && !a.limiter.Allow() {
		counterHTTPIncomingPushback.Inc()
		klog.V(1).Infof("Too many HTTP requests, pushing back.")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	oldSize, proof, cp, err := parseBody(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
	if err != nil {
		klog.V(1).Infof("invalid body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		counterHTTPIncomingResponse.Inc("unknown", strconv.Itoa(http.StatusBadRequest))
		return
	}
	s := strings.SplitN(string(cp), "\n", 2)
	if len(s) != 2 {
		klog.V(1).Infof("invalid cp: %v", cp)
		w.WriteHeader(http.StatusBadRequest)
		counterHTTPIncomingResponse.Inc("unknown", strconv.Itoa(http.StatusBadRequest))
		return
	}

	origin := s[0]
	sc, body, contentType, err := a.handleUpdate(r.Context(), oldSize, cp, proof)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, witness.ErrPushback) {
			status = http.StatusTooManyRequests
		}
		klog.Errorf("handleUpdate: %v", err)
		w.WriteHeader(status)
		counterHTTPIncomingResponse.Inc(origin, strconv.Itoa(status))
		return
	}

	if contentType != "" {
		w.Header().Add("Content-Type", contentType)
	}
	w.WriteHeader(sc)
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			klog.Infof("Failed to write response body: %v", err)
		}
	}
	counterHTTPIncomingResponse.Inc(origin, strconv.Itoa(sc))
}

// handleUpdate submits the provided checkpoint to the witness and interprets any errors which may result.
//
// Returns an appropriate HTTP status code, response body, and Content Type representing the outcome.
func (a *httpHandler) handleUpdate(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) (int, []byte, string, error) {
	sigs, trustedSize, updateErr := a.update(ctx, oldSize, newCP, proof)
	// Finally, handle any "soft" error from the update:
	if updateErr != nil {
		switch {
		case errors.Is(updateErr, witness.ErrCheckpointStale):
			return http.StatusConflict, fmt.Appendf(nil, "%d\n", trustedSize), "text/x.tlog.size", nil
		case errors.Is(updateErr, witness.ErrUnknownLog):
			return http.StatusNotFound, nil, "", nil
		case errors.Is(updateErr, witness.ErrNoValidSignature):
			return http.StatusForbidden, nil, "", nil
		case errors.Is(updateErr, witness.ErrOldSizeInvalid):
			return http.StatusBadRequest, nil, "", nil
		case errors.Is(updateErr, witness.ErrInvalidProof):
			return http.StatusUnprocessableEntity, nil, "", nil
		case errors.Is(updateErr, witness.ErrRootMismatch):
			return http.StatusConflict, nil, "", nil
		default:
			return http.StatusInternalServerError, nil, "", updateErr
		}
	}

	return http.StatusOK, sigs, "", nil
}

// parseBody reads the incoming request and parses into constituent parts.
//
// The request body MUST be a sequence of
// - a previous size line,
// - zero or more consistency proof lines,
// - and an empty line,
// - followed by a [checkpoint][].
func parseBody(r io.Reader) (uint64, [][]byte, []byte, error) {
	b := bufio.NewReader(r)
	sizeLine, _, err := b.ReadLine()
	if err != nil {
		klog.Infof("read sizeline: %v", err)
		return 0, nil, nil, err
	}
	var size uint64
	if n, err := fmt.Sscanf(string(sizeLine), "old %d", &size); err != nil || n != 1 {
		klog.Infof("scan sizeline: %v", err)
		return 0, nil, nil, err
	}
	proof := [][]byte{}
	for {
		l, _, err := b.ReadLine()
		if err != nil {
			klog.Infof("read proofline: %v", err)
			return 0, nil, nil, err
		}
		if len(l) == 0 {
			break
		}
		hash, err := base64.StdEncoding.DecodeString(string(l))
		if err != nil {
			klog.Infof("base64 proof: %v", err)
			return 0, nil, nil, err
		}
		proof = append(proof, hash)
	}
	cp, err := io.ReadAll(b)
	if err != nil {
		klog.Infof("read cp: %v", err)
		return 0, nil, nil, err
	}
	return size, proof, cp, nil
}
