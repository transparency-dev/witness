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

package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/gorilla/mux"
	f_note "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/witness/api"
	"github.com/transparency-dev/witness/internal/persistence/inmemory"
	"github.com/transparency-dev/witness/internal/witness"
	"github.com/transparency-dev/witness/monitoring"
	"golang.org/x/mod/sumdb/note"

	_ "github.com/mattn/go-sqlite3" // Load drivers for sqlite3
)

var (
	mPK   = "monkeys+87be2a55+AeK/t7elVrIheVCPxQNYkvKFw/2ahkj6Gm9afBJw6S8q"
	bPK   = "bananas+cf639f13+AaPjhFnPCQnid/Ql32KWhmh+uk72FVRfK+2DLmO3BI3M"
	wSK   = "PRIVATE+KEY+witness+f13a86db+AaLa/dfyBhyo/m0Z7WCi98ENVZWtrP8pxgRNrx7tIWiA"
	mInit = []byte("Log Checkpoint v0\n5\n41smjBUiAU70EtKlT6lIOIYtRTYxYXsDB+XHfcvu/BE=\n\n— monkeys h74qVe5jWoK8CX/zXrT9X80SyEaiwPb/0p7VW7u+cnXxq5pJYQ6vhxUZ5Ywz9WSD3HIyygccizAg+oMxOe6pRgqqOQE=\n")
	bInit = []byte("Log Checkpoint v0\n5\n41smjBUiAU70EtKlT6lIOIYtRTYxYXsDB+XHfcvu/BE=\n\n— bananas z2OfE18+NwUjjJBXH7m+fh67bu29p1Jbypr4GFUQohgQgCeuPJZtGTvfR9Pquh2Iebfq+6bhl3G/77lsKiGIea6NAwE=\n")
)

const logOrigin = "Log Checkpoint v0"

type logOpts struct {
	ID     string
	origin string
	PK     string
}

func newWitness(t *testing.T, logs []logOpts) *witness.Witness {
	// Set up Opts for the witness.
	ns, err := f_note.NewSignerForCosignatureV1(wSK)
	if err != nil {
		t.Fatalf("couldn't create a witness signer: %v", err)
	}
	h := rfc6962.DefaultHasher
	logMap := make(map[string]witness.LogInfo)
	for _, log := range logs {
		logV, err := note.NewVerifier(log.PK)
		if err != nil {
			t.Fatalf("couldn't create a log verifier: %v", err)
		}
		logInfo := witness.LogInfo{
			Origin: log.origin,
			SigV:   logV,
			Hasher: h,
		}
		logMap[log.ID] = logInfo
	}
	opts := witness.Opts{
		Persistence: inmemory.NewPersistence(),
		Signers:     []note.Signer{ns},
		KnownLogs:   logMap,
	}
	// Create the witness
	w, err := witness.New(opts)
	if err != nil {
		t.Fatalf("couldn't create witness: %v", err)
	}
	return w
}

func createTestEnv(w *witness.Witness) (*httptest.Server, func()) {
	r := mux.NewRouter()
	server := NewServer(w)
	server.RegisterHandlers(r)
	ts := httptest.NewServer(r)
	return ts, ts.Close
}

func TestGetLogs(t *testing.T) {
	monitoring.SetMetricFactory(monitoring.InertMetricFactory{})
	for _, test := range []struct {
		desc       string
		logIDs     []string
		logPKs     []string
		chkpts     [][]byte
		wantStatus int
		wantBody   []string
	}{
		{
			desc:       "no logs",
			logIDs:     []string{},
			wantStatus: http.StatusOK,
			wantBody:   []string{},
		}, {
			desc:       "one log",
			logIDs:     []string{"monkeys"},
			logPKs:     []string{mPK},
			chkpts:     [][]byte{mInit},
			wantStatus: http.StatusOK,
			wantBody:   []string{"monkeys"},
		}, {
			desc:       "two logs",
			logIDs:     []string{"bananas", "monkeys"},
			logPKs:     []string{bPK, mPK},
			chkpts:     [][]byte{bInit, mInit},
			wantStatus: http.StatusOK,
			wantBody:   []string{"bananas", "monkeys"},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			ctx := context.Background()
			// Set up witness and give it some checkpoints.
			logs := make([]logOpts, len(test.logIDs))
			for i, logID := range test.logIDs {
				logs[i] = logOpts{
					ID:     logID,
					origin: logOrigin,
					PK:     test.logPKs[i],
				}
			}
			w := newWitness(t, logs)
			for i, logID := range test.logIDs {
				if _, err := w.Update(ctx, logID, 0, test.chkpts[i], nil); err != nil {
					t.Errorf("failed to set checkpoint: %v", err)
				}
			}
			// Now set up the http server.
			ts, tsCloseFn := createTestEnv(w)
			defer tsCloseFn()
			client := ts.Client()
			url := fmt.Sprintf("%s%s", ts.URL, api.HTTPGetLogs)
			resp, err := client.Get(url)
			if err != nil {
				t.Errorf("error response: %v", err)
			}
			if got, want := resp.StatusCode, test.wantStatus; got != want {
				t.Errorf("status code got %d, want %d", got, want)
			}
			if len(test.wantBody) > 0 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("failed to read body: %v", err)
				}
				var logs []string
				if err := json.Unmarshal(body, &logs); err != nil {
					t.Fatalf("failed to unmarshal body: %v", err)
				}
				if len(logs) != len(test.wantBody) {
					t.Fatalf("got %d logs, want %d", len(logs), len(test.wantBody))
				}
				sort.Strings(logs)
				for i := range logs {
					if logs[i] != test.wantBody[i] {
						t.Fatalf("got %q, want %q", logs[i], test.wantBody[i])
					}
				}
			}
		})
	}
}

func TestGetChkpt(t *testing.T) {
	for _, test := range []struct {
		desc       string
		setID      string
		setPK      string
		queryID    string
		queryPK    string
		c          []byte
		wantStatus int
	}{
		{
			desc:       "happy path",
			setID:      "monkeys",
			setPK:      mPK,
			queryID:    "monkeys",
			queryPK:    mPK,
			c:          mInit,
			wantStatus: http.StatusOK,
		}, {
			desc:       "other log",
			setID:      "monkeys",
			setPK:      mPK,
			queryID:    "bananas",
			c:          mInit,
			wantStatus: http.StatusNotFound,
		}, {
			desc:       "nothing there",
			setID:      "monkeys",
			setPK:      mPK,
			queryID:    "monkeys",
			c:          nil,
			wantStatus: http.StatusNotFound,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			ctx := context.Background()
			// Set up witness.
			w := newWitness(t, []logOpts{{
				ID:     test.setID,
				origin: logOrigin,
				PK:     test.setPK,
			}})
			// Set a checkpoint for the log if we want to for this test.
			if test.c != nil {
				if _, err := w.Update(ctx, test.setID, 0, test.c, nil); err != nil {
					t.Errorf("failed to set checkpoint: %v", err)
				}
			}
			// Now set up the http server.
			ts, tsCloseFn := createTestEnv(w)
			defer tsCloseFn()
			client := ts.Client()
			chkptQ := fmt.Sprintf(api.HTTPGetCheckpoint, test.queryID)
			url := fmt.Sprintf("%s%s", ts.URL, chkptQ)
			resp, err := client.Get(url)
			if err != nil {
				t.Errorf("error response: %v", err)
			}
			if got, want := resp.StatusCode, test.wantStatus; got != want {
				t.Errorf("status code got %d, want %d", got, want)
			}
		})
	}
}
