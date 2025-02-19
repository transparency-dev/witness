// Copyright 2024 Google LLC. All Rights Reserved.
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

// Package bastion is an implementation of a witness feeder which talks to a bastion server.
package bastion

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/internal/feeder"
	"github.com/transparency-dev/witness/internal/witness"
	"github.com/transparency-dev/witness/monitoring"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

// RequestLimits describes how incoming requests should be limited.
type RequestLimits struct {
	// TotalPerSecond is the total number of incoming requests per second which should be served, zero mean no requests will be served.
	TotalPerSecond rate.Limit
}

type Config struct {
	Addr            string
	Prefix          string
	Logs            []config.Log
	BastionKey      ed25519.PrivateKey
	WitnessVerifier note.Verifier
	Limits          RequestLimits
}

// FeedBastion talks to the bastion to receive checkpoints to be witnessed.
// This function returns once the provided context is done.
func FeedBastion(ctx context.Context, c Config, w feeder.Witness) error {
	initMetrics()
	klog.Infof("My bastion backend ID: %064x", sha256.Sum256(c.BastionKey.Public().(ed25519.PublicKey)))
	h := &addHandler{
		w:           w,
		logs:        make(map[string]config.Log),
		witVerifier: c.WitnessVerifier,
		limiter:     rate.NewLimiter(c.Limits.TotalPerSecond, int(c.Limits.TotalPerSecond)),
	}
	for _, l := range c.Logs {
		h.logs[l.ID] = l
	}

	return connectAndServe(ctx, c.Addr, h, c.BastionKey)
}

var (
	doOnce                         sync.Once
	counterBastionRegisterAttempt  monitoring.Counter
	counterBastionRegisterSuccess  monitoring.Counter
	counterBastionIncomingRequest  monitoring.Counter
	counterBastionIncomingResponse monitoring.Counter
	counterBastionIncomingPushback monitoring.Counter
)

func initMetrics() {
	doOnce.Do(func() {
		mf := monitoring.GetMetricFactory()
		const (
			bastionID = "bastionid"
			origin    = "origin"
			status    = "status"
		)

		counterBastionRegisterAttempt = mf.NewCounter("bastion_register_attempt", "Number of attempts to register with bastion", bastionID)
		counterBastionRegisterSuccess = mf.NewCounter("bastion_register_success", "Number of successful registrations with bastion", bastionID)
		counterBastionIncomingRequest = mf.NewCounter("bastion_request", "Number of bastion requests received", bastionID)
		counterBastionIncomingResponse = mf.NewCounter("bastion_response", "Bastion mediated responses", bastionID, origin, status)
		counterBastionIncomingPushback = mf.NewCounter("bastion_pushback", "Number of pushed-back bastion mediated requests", bastionID)
	})
}

type addHandler struct {
	w           feeder.Witness
	logs        map[string]config.Log
	witVerifier note.Verifier
	limiter     *rate.Limiter
}

func (a *addHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	bastionID := r.RemoteAddr
	counterBastionIncomingRequest.Inc(bastionID)

	if !a.limiter.Allow() {
		counterBastionIncomingPushback.Inc(bastionID)
		klog.V(1).Infof("Too many bastion requests, pushing back.")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	oldSize, proof, cp, err := parseBody(r.Body)
	if err != nil {
		klog.V(1).Infof("invalid body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		counterBastionIncomingResponse.Inc(bastionID, "unknown", strconv.Itoa(http.StatusBadRequest))
		return
	}
	s := strings.SplitN(string(cp), "\n", 2)
	if len(s) != 2 {
		klog.V(1).Infof("invalid cp: %v", cp)
		w.WriteHeader(http.StatusBadRequest)
		counterBastionIncomingResponse.Inc(bastionID, "unknown", strconv.Itoa(http.StatusBadRequest))
		return
	}

	logID := log.ID(s[0])
	logCfg, ok := a.logs[logID]
	if !ok {
		klog.V(1).Infof("unknown log: %v", logID)
		w.WriteHeader(http.StatusNotFound)
		counterBastionIncomingResponse.Inc(bastionID, "unknown", strconv.Itoa(http.StatusNotFound))
		return
	}

	sc, body, contentType, err := a.handleUpdate(r.Context(), logID, logCfg.Origin, oldSize, cp, proof)
	if err != nil {
		klog.Errorf("handleUpdate: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		counterBastionIncomingResponse.Inc(bastionID, logCfg.Origin, strconv.Itoa(http.StatusInternalServerError))
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
	counterBastionIncomingResponse.Inc(bastionID, logCfg.Origin, strconv.Itoa(sc))
}

// handleUpdate submits the provided checkpoint to the witness and interprets any errors which may result.
//
// Returns an appropriate HTTP status code, response body, and Content Type representing the outcome.
func (a *addHandler) handleUpdate(ctx context.Context, logID string, origin string, oldSize uint64, newCP []byte, proof [][]byte) (int, []byte, string, error) {
	trusted, updateErr := a.w.Update(ctx, logID, oldSize, newCP, proof)
	// Whatever happened, we usually get the latest trusted CP from the witness (whether it's the old one or the one we've just updated to).
	// If we get nothing at all, then something's gone quite wrong.
	if trusted == nil {
		return http.StatusInternalServerError, nil, "", fmt.Errorf("something went quite wrong during update: %v", updateErr)
	}
	// We'll need to use the old CP when sending responses, so parse it once here:
	trustedCP, _, n, cpErr := log.ParseCheckpoint(trusted, origin, a.witVerifier)
	if cpErr != nil {
		return http.StatusInternalServerError, nil, "", fmt.Errorf("invalid stored checkpoint!: %v", cpErr)
	}

	// Finally, handle any "soft" error from the update:
	if updateErr != nil {
		switch updateErr {
		case witness.ErrCheckpointStale:
			return http.StatusConflict, []byte(fmt.Sprintf("%d\n", trustedCP.Size)), "text/x.tlog.size", nil
		case witness.ErrUnknownLog:
			return http.StatusNotFound, nil, "", nil
		case witness.ErrNoValidSignature:
			return http.StatusForbidden, nil, "", nil
		case witness.ErrOldSizeInvalid:
			return http.StatusBadRequest, nil, "", nil
		case witness.ErrInvalidProof:
			return http.StatusUnprocessableEntity, nil, "", nil
		case witness.ErrRootMismatch:
			return http.StatusConflict, nil, "", nil
		default:
			return http.StatusInternalServerError, nil, "", updateErr
		}
	}

	body := []byte(fmt.Sprintf("— %s %s\n", n.Sigs[0].Name, n.Sigs[0].Base64))
	return http.StatusOK, body, "", nil
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

func connectAndServe(ctx context.Context, host string, handler http.Handler, key ed25519.PrivateKey) error {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		counterBastionRegisterAttempt.Inc(host)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C: // Don't spam bastion in a tight loop in case of error below.
		}

		cert, err := selfSignedCertificate(key)
		if err != nil {
			return err
		}

		// Connect to the bastion and serve.
		// We do this in an inline func to make it easier to cancel contexts via defers.
		func() {
			klog.Infof("Connecting to bastion...")
			dctx, dCancel := context.WithTimeout(ctx, 10*time.Second)
			defer dCancel()

			conn, err := (&tls.Dialer{
				Config: &tls.Config{
					Certificates: []tls.Certificate{{
						Certificate: [][]byte{cert},
						PrivateKey:  key,
					}},
					MinVersion: tls.VersionTLS13,
					MaxVersion: tls.VersionTLS13,
					NextProtos: []string{"bastion/0"},
				},
			}).DialContext(dctx, "tcp", host)
			if err != nil {
				klog.Infof("Failed to connect to bastion: %v", err)
				return
			}

			klog.Infof("Connected to bastion. Serving connection...")
			counterBastionRegisterSuccess.Inc(host)
			(&http2.Server{
				IdleTimeout:     300 * time.Second,
				ReadIdleTimeout: 10 * time.Second,
				PingTimeout:     15 * time.Second,
			}).ServeConn(conn, &http2.ServeConnOpts{
				Context: ctx,
				Handler: http.MaxBytesHandler(handler, 16*1024),
				BaseConfig: &http.Server{
					BaseContext:  func(net.Listener) context.Context { return ctx },
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 5 * time.Second,
				},
			})
		}()
	}
}

func selfSignedCertificate(key ed25519.PrivateKey) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Bastion backend"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate self-signed certificate: %v", err)
	}
	return cert, nil
}
