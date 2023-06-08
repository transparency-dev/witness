// Copyright 2023 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package rest_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/internal/distribute/rest"
	"golang.org/x/mod/sumdb/note"
)

const (
	lPK = "monkeys+db4d9f7e+AULaJMvTtDLHPUcUrjdDad9vDlh/PTfC2VV60JUtCfWT"
	lSK = "PRIVATE+KEY+monkeys+db4d9f7e+ATWIAF3yVBG+Hv1rZFQoNt/BaURkLPtOFMAM2HrEeIr6"

	wPK = "witness+f13a86db+AdYV1Ztajd9BvyjP2HgpwrqYL6TjOwIjGMOq8Bu42xbN"
	wSK = "PRIVATE+KEY+witness+f13a86db+AaLa/dfyBhyo/m0Z7WCi98ENVZWtrP8pxgRNrx7tIWiA"
)

func TestDistributeOnce(t *testing.T) {
	fd := &fakeDistributor{}
	r := mux.NewRouter()
	r.HandleFunc(fmt.Sprintf(rest.HTTPCheckpointByWitness, "{logid:[a-zA-Z0-9-]+}", "{witid:[^ +]+}"), fd.update).Methods("PUT")
	ts := httptest.NewServer(r)
	defer ts.Close()

	log := config.Log{
		Origin:    "Log Checkpoint v0",
		PublicKey: "monkeys+db4d9f7e+AULaJMvTtDLHPUcUrjdDad9vDlh/PTfC2VV60JUtCfWT",
		ID:        "thisisthelogid",
	}
	logs := []config.Log{log}
	wV, err := note.NewVerifier(wPK)
	if err != nil {
		t.Fatal(err)
	}

	lSign, err := note.NewSigner(lSK)
	if err != nil {
		t.Fatal(err)
	}
	wSign, err := note.NewSigner(wSK)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := note.Sign(&note.Note{Text: "Log Checkpoint v0\n5\n41smjBUiAU70EtKlT6lIOIYtRTYxYXsDB+XHfcvu/BE=\n"}, lSign, wSign)
	if err != nil {
		t.Fatal(err)
	}

	wit := &silentWitness{}
	wit.result = msg
	d, err := rest.NewDistributor(ts.URL, http.DefaultClient, logs, wV, wit)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DistributeOnce(context.Background()); err != nil {
		t.Error(err)
	}
	if got, want := fd.lastCheckpoint, wit.result; !bytes.Equal(got, want) {
		t.Errorf("got %v != want %v", got, want)
	}
	if got, want := fd.lastLogID, log.ID; got != want {
		t.Errorf("got %q != want %q", got, want)
	}
	if got, want := fd.lastWitID, "witness"; got != want {
		t.Errorf("got %q != want %q", got, want)
	}
}

type silentWitness struct {
	result    []byte
	resultErr error
}

func (w *silentWitness) GetLatestCheckpoint(ctx context.Context, logID string) ([]byte, error) {
	return w.result, w.resultErr
}

type fakeDistributor struct {
	lastLogID      string
	lastWitID      string
	lastCheckpoint []byte
}

func (d *fakeDistributor) update(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	d.lastLogID = v["logid"]
	d.lastWitID = v["witid"]

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot read request body: %v", err.Error()), http.StatusBadRequest)
		return
	}
	d.lastCheckpoint = body
}
