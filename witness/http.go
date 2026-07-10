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

package witness

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// maxRequestBodyBytes is the limit on the number of bytes we'll read from incoming requests.
// 16 should be more than enough, even in a PQ world.
var MaxRequestBodyBytes int64 = 16 << 10

func NewHTTPHandler(w *Witness) *HTTPHandler {
	return &HTTPHandler{witness: w}
}

// HTTPHandler provides tlog-witness compatible handlers intended to be used with the stdlib http server.
type HTTPHandler struct {
	witness witness
}

// AddCheckpoint is a http.Handler which speaks the tlog-witness protocol for add-checkpoint.
func (a *HTTPHandler) AddCheckpoint(w http.ResponseWriter, r *http.Request) {
	defer func() {
		_, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
	}()

	oldSize, proof, cp, err := parseBody(http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sc, body, contentType, err := a.handleUpdate(r.Context(), oldSize, cp, proof)
	if err != nil {
		status := http.StatusInternalServerError
		w.WriteHeader(status)
		return
	}

	if contentType != "" {
		w.Header().Add("Content-Type", contentType)
	}
	w.WriteHeader(sc)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

// handleUpdate submits the provided checkpoint to the witness and interprets any errors which may result.
//
// Returns an appropriate HTTP status code, response body, and Content Type representing the outcome.
func (a *HTTPHandler) handleUpdate(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) (int, []byte, string, error) {
	sigs, trustedSize, updateErr := a.witness.Update(ctx, oldSize, newCP, proof)
	// Finally, handle any "soft" error from the update:
	if updateErr != nil {
		switch {
		case errors.Is(updateErr, ErrCheckpointStale):
			return http.StatusConflict, fmt.Appendf(nil, "%d\n", trustedSize), "text/x.tlog.size", nil
		case errors.Is(updateErr, ErrUnknownLog):
			return http.StatusNotFound, nil, "", nil
		case errors.Is(updateErr, ErrNoValidSignature):
			return http.StatusForbidden, nil, "", nil
		case errors.Is(updateErr, ErrOldSizeInvalid):
			return http.StatusBadRequest, nil, "", nil
		case errors.Is(updateErr, ErrInvalidProof):
			return http.StatusUnprocessableEntity, nil, "", nil
		case errors.Is(updateErr, ErrRootMismatch):
			return http.StatusUnprocessableEntity, nil, "", nil
		case errors.Is(updateErr, ErrPushback):
			return http.StatusTooManyRequests, nil, "", nil
		default:
			slog.ErrorContext(ctx, "Unknown error", slog.Any("error", updateErr))
			return http.StatusInternalServerError, nil, "", updateErr
		}
	}

	return http.StatusOK, sigs, "", nil
}

// SignSubtree is a http.Handler which speaks the tlog-witness protocol for sign-subtree.
func (a *HTTPHandler) SignSubtree(w http.ResponseWriter, r *http.Request) {
	defer func() {
		_, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
	}()

	start, end, subRoot, proof, cp, err := parseSubtreeBody(http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sc, body, contentType, err := a.handleSignSubtree(r.Context(), start, end, subRoot, proof, cp)
	if err != nil {
		status := http.StatusInternalServerError
		w.WriteHeader(status)
		return
	}

	if contentType != "" {
		w.Header().Add("Content-Type", contentType)
	}
	w.WriteHeader(sc)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

// handleSignSubtree submits the sign-subtree request to the witness and interprets any errors.
func (a *HTTPHandler) handleSignSubtree(ctx context.Context, start, end uint64, subRoot []byte, proof [][]byte, cp []byte) (int, []byte, string, error) {
	sigs, err := a.witness.SignSubtree(ctx, start, end, subRoot, proof, cp)
	if err != nil {
		switch {
		case errors.Is(err, ErrUnknownLog):
			return http.StatusNotFound, nil, "", nil
		case errors.Is(err, ErrNoWitnessSignature):
			return http.StatusForbidden, nil, "", nil
		case errors.Is(err, ErrSubtreeRangeInvalid):
			return http.StatusBadRequest, nil, "", nil
		case errors.Is(err, ErrInvalidProof):
			return http.StatusUnprocessableEntity, nil, "", nil
		case errors.Is(err, ErrNotImplemented):
			return http.StatusNotImplemented, nil, "", nil
		case errors.Is(err, ErrPushback):
			return http.StatusTooManyRequests, nil, "", nil
		default:
			slog.ErrorContext(ctx, "Unknown error", slog.Any("error", err))
			return http.StatusInternalServerError, nil, "", err
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
		return 0, nil, nil, err
	}
	var size uint64
	if n, err := fmt.Sscanf(string(sizeLine), "old %d", &size); err != nil || n != 1 {
		return 0, nil, nil, err
	}
	proof := [][]byte{}
	for {
		l, _, err := b.ReadLine()
		if err != nil {
			return 0, nil, nil, err
		}
		if len(l) == 0 {
			break
		}
		hash, err := base64.StdEncoding.DecodeString(string(l))
		if err != nil {
			return 0, nil, nil, err
		}
		proof = append(proof, hash)
	}
	cp, err := io.ReadAll(b)
	if err != nil {
		return 0, nil, nil, err
	}
	return size, proof, cp, nil
}

// parseSubtreeBody reads the incoming request and parses into constituent parts.
func parseSubtreeBody(r io.Reader) (uint64, uint64, []byte, [][]byte, []byte, error) {
	b := bufio.NewReader(r)
	rangeLine, _, err := b.ReadLine()
	if err != nil {
		return 0, 0, nil, nil, nil, err
	}
	var start, end uint64
	if n, err := fmt.Sscanf(string(rangeLine), "subtree %d %d", &start, &end); err != nil || n != 2 {
		return 0, 0, nil, nil, nil, err
	}

	hashLine, _, err := b.ReadLine()
	if err != nil {
		return 0, 0, nil, nil, nil, err
	}
	subRoot, err := base64.StdEncoding.DecodeString(string(hashLine))
	if err != nil {
		return 0, 0, nil, nil, nil, err
	}

	proof := [][]byte{}
	for {
		l, _, err := b.ReadLine()
		if err != nil {
			return 0, 0, nil, nil, nil, err
		}
		if len(l) == 0 {
			break
		}
		hash, err := base64.StdEncoding.DecodeString(string(l))
		if err != nil {
			return 0, 0, nil, nil, nil, err
		}
		proof = append(proof, hash)
	}
	cp, err := io.ReadAll(b)
	if err != nil {
		return 0, 0, nil, nil, nil, err
	}
	return start, end, subRoot, proof, cp, nil
}

// witness is the contract expected of the backend for HTTPHandler.
// This interface only really exists to make testing easier.
type witness interface {
	Update(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error)
	SignSubtree(ctx context.Context, start, end uint64, subRoot []byte, proof [][]byte, cp []byte) ([]byte, error)
}
