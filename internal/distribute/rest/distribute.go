// Copyright 2023 Google LLC. All Rights Reserved.
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

// Package rest provides support for pushing witnessed checkpoints to a
// RESTful API.
package rest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/golang/glog"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/witness/internal/config"
	i_note "github.com/transparency-dev/witness/internal/note"
	"golang.org/x/mod/sumdb/note"
)

const (
	// HTTPCheckpointByWitness is the path of the URL to the latest checkpoint
	// for a given log by a given witness. This can take PUT requests to update
	// the latest checkpoint.
	//  * first position is for the logID (an alphanumeric string)
	//  * second position is the witness short name (alpha string)
	HTTPCheckpointByWitness = "/distributor/v0/logs/%s/byWitness/%s/checkpoint"
)

// Witness describes the operations the redistributor needs to interact with a witness.
type Witness interface {
	// GetLatestCheckpoint returns the latest checkpoint the witness holds for the given logID.
	// Must return os.ErrNotExists if the logID is known, but it has no checkpoint for that log.
	GetLatestCheckpoint(ctx context.Context, logID string) ([]byte, error)
}

// logAndVerifier represents a log known to the distributor.
type logAndVerifier struct {
	config config.Log
	sigV   note.Verifier
}

// NewDistributor creates a new Distributor from the given configuration.
func NewDistributor(baseURL string, client *http.Client, logs []config.Log, witSigV note.Verifier, wit Witness) (*Distributor, error) {
	lvs := make([]logAndVerifier, len(logs), len(logs))
	for i, l := range logs {
		logSigV, err := i_note.NewVerifier(l.PublicKeyType, l.PublicKey)
		if err != nil {
			return nil, err
		}
		lvs[i] = logAndVerifier{
			config: l,
			sigV:   logSigV,
		}
	}
	return &Distributor{
		baseURL: baseURL,
		client:  client,
		logs:    lvs,
		witSigV: witSigV,
		witness: wit,
	}, nil
}

// Distributor distributes checkpoints to a REST API.
type Distributor struct {
	baseURL string
	client  *http.Client
	logs    []logAndVerifier
	witSigV note.Verifier
	witness Witness
}

// DistributeOnce polls the witness for all logs and pushes the latest checkpoint to the
// RESTful distributor.
func (d *Distributor) DistributeOnce(ctx context.Context) error {
	numErrs := 0
	for _, log := range d.logs {
		if err := d.distributeForLog(ctx, log); err != nil {
			glog.Warningf("Failed to distribute %q (%s): %v", d.baseURL, log.config.Origin, err)
			numErrs++
		}
	}
	if numErrs > 0 {
		return fmt.Errorf("failed to distribute %d out of %d logs", numErrs, len(d.logs))
	}
	return nil
}

func (d *Distributor) distributeForLog(ctx context.Context, l logAndVerifier) error {
	// This will be used on both the witness and the distributor.
	// At the moment the ID is arbitrary and is up to the discretion of the operators
	// of these parties. We should address this. If we don't manage to do so in time,
	// we'll need to allow this ID to be configured separately for each entity.
	logID := l.config.ID

	wRaw, err := d.witness.GetLatestCheckpoint(ctx, logID)
	if err != nil {
		return fmt.Errorf("GetLatestCheckpoint(): %v", err)
	}
	_, wcpRaw, witnessNote, err := log.ParseCheckpoint(wRaw, l.config.Origin, l.sigV, d.witSigV)
	if err != nil {
		return fmt.Errorf("couldn't parse witnessed checkpoint: %v", err)
	}
	if nWitSigs, want := len(witnessNote.Sigs)-1, 1; nWitSigs != want {
		return fmt.Errorf("checkpoint has %d witness sigs, want %d", nWitSigs, want)
	}

	u, err := url.Parse(fmt.Sprintf(HTTPCheckpointByWitness, logID, url.PathEscape(d.witSigV.Name())))
	if err != nil {
		return fmt.Errorf("failed to parse URL: %v", err)
	}
	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(wcpRaw))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := d.client.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to do http request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %v", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("bad status response (%s): %q", resp.Status, body)
	}
	return nil
}
