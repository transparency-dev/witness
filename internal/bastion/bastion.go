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

// Package bastion implements support for the https://c2sp.org/https-bastion protocol.
package bastion

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/monitoring"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/net/http2"
	"k8s.io/klog/v2"
)

type Config struct {
	Addr            string
	Prefix          string
	Logs            []config.Log
	BastionKey      ed25519.PrivateKey
	WitnessVerifier note.Verifier
}

// Register connects to the bastion to receive checkpoints to be witnessed.
//
// If the connection to the bastion is broken for any reason, it will be retried.
// This function returns only once the provided context is done.
func Register(ctx context.Context, c Config, witnessHandler http.Handler) error {
	initMetrics()
	klog.Infof("My bastion backend ID: %064x", sha256.Sum256(c.BastionKey.Public().(ed25519.PublicKey)))

	return connectAndServe(ctx, c.Addr, witnessHandler, c.BastionKey)
}

var (
	doOnce                        sync.Once
	counterBastionRegisterAttempt monitoring.Counter
	counterBastionRegisterSuccess monitoring.Counter
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
	})
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
