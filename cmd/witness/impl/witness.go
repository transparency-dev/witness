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

// Package impl is the implementation of the witness server.
package impl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3" // Load drivers for sqlite3
	ih "github.com/transparency-dev/witness/internal/http"
	wsql "github.com/transparency-dev/witness/internal/persistence/sql"
	"github.com/transparency-dev/witness/internal/witness"
	"github.com/transparency-dev/witness/omniwitness"
	"golang.org/x/mod/sumdb/note"
)

// ServerOpts are the options for a server (specified in main.go).
type ServerOpts struct {
	// Where to listen for requests.
	ListenAddr string
	// The file for sqlite3 storage.
	DBFile string
	// The signer for the witness.
	Signer note.Signer
	// The log configuration information.
	Config omniwitness.LogConfig
}

// Main runs the witness until the context is canceled.
func Main(ctx context.Context, opts ServerOpts) error {
	if len(opts.DBFile) == 0 {
		return errors.New("DBFile is required")
	}
	// Start up local database.
	glog.Infof("Connecting to local DB at %q", opts.DBFile)
	db, err := sql.Open("sqlite3", opts.DBFile)
	if err != nil {
		return fmt.Errorf("failed to connect to DB: %w", err)
	}
	// Avoid "database locked" issues with multiple concurrent updates.
	db.SetMaxOpenConns(1)

	// Load log configuration into the map.
	logMap, err := opts.Config.AsLogMap()
	if err != nil {
		return fmt.Errorf("failed to load configurations: %v", err)
	}

	w, err := witness.New(witness.Opts{
		Persistence: wsql.NewPersistence(db),
		Signer:      opts.Signer,
		KnownLogs:   logMap,
	})
	if err != nil {
		return fmt.Errorf("error creating witness: %v", err)
	}

	glog.Infof("Starting witness server...")
	srv := ih.NewServer(w)
	r := mux.NewRouter()
	srv.RegisterHandlers(r)
	hServer := &http.Server{
		Addr:    opts.ListenAddr,
		Handler: r,
	}
	e := make(chan error, 1)
	go func() {
		e <- hServer.ListenAndServe()
		close(e)
	}()
	<-ctx.Done()
	glog.Info("Server shutting down")
	if err := hServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %v", err)
	}
	return <-e
}
