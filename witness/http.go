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
	return &HTTPHandler{
		addCheckpointHandler: NewAddCheckpointHandler(w.Update),
		signSubtreeHandler:   NewSignSubtreeHandler(w.SignSubtree),
	}
}

// HTTPHandler provides tlog-witness compatible handlers intended to be used with the stdlib http server.
type HTTPHandler struct {
	addCheckpointHandler http.HandlerFunc
	signSubtreeHandler   http.HandlerFunc
}

// AddCheckpoint handles HTTP requests conforming to the tlog-witness add-checkpoint protocol.
func (a *HTTPHandler) AddCheckpoint(w http.ResponseWriter, r *http.Request) {
	a.addCheckpointHandler(w, r)
}

// SignSubtree is a http.Handler which speaks the tlog-witness protocol for sign-subtree.
func (a *HTTPHandler) SignSubtree(w http.ResponseWriter, r *http.Request) {
	a.signSubtreeHandler(w, r)
}

// UpdateFunc knows how to update a log's checkpoint given an old size, a new checkpoint, and a Merkle proof.
type UpdateFunc func(ctx context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error)

// NewAddCheckpointHandler returns an http.Handler for the tlog-witness add-checkpoint protocol.
func NewAddCheckpointHandler(update UpdateFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			_, _ = io.ReadAll(r.Body)
			_ = r.Body.Close()
		}()

		oldSize, proof, cp, err := parseBody(http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sc, body, contentType, err := handleUpdate(r.Context(), update, oldSize, cp, proof)
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
}

// handleUpdate submits the provided checkpoint to the witness and interprets any errors which may result.
//
// Returns an appropriate HTTP status code, response body, and Content Type representing the outcome.
func handleUpdate(ctx context.Context, update UpdateFunc, oldSize uint64, newCP []byte, proof [][]byte) (int, []byte, string, error) {
	sigs, trustedSize, updateErr := update(ctx, oldSize, newCP, proof)
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

// SignSubtreeFunc knows how to verify and sign a subtree.
type SignSubtreeFunc func(ctx context.Context, start, end uint64, subRoot []byte, proof [][]byte, cp []byte) ([]byte, error)

// NewSignSubtreeHandler returns an http.Handler for the tlog-witness sign-subtree protocol.
func NewSignSubtreeHandler(signSubtree SignSubtreeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			_, _ = io.ReadAll(r.Body)
			_ = r.Body.Close()
		}()

		start, end, subRoot, proof, cp, err := parseSubtreeBody(http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sc, body, contentType, err := handleSignSubtree(r.Context(), signSubtree, start, end, subRoot, proof, cp)
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
}

// handleSignSubtree submits the sign-subtree request to the witness and interprets any errors.
func handleSignSubtree(ctx context.Context, signSubtree SignSubtreeFunc, start, end uint64, subRoot []byte, proof [][]byte, cp []byte) (int, []byte, string, error) {
	sigs, err := signSubtree(ctx, start, end, subRoot, proof, cp)
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
		if err == nil {
			err = fmt.Errorf("expected 2 arguments, got %d", n)
		}
		return 0, 0, nil, nil, nil, fmt.Errorf("failed to parse subtree range line %q: %v", string(rangeLine), err)
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
