// Copyright 2022 Google LLC. All Rights Reserved.
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

package main

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"cloud.google.com/go/spanner"
	database "cloud.google.com/go/spanner/admin/database/apiv1"
	adminpb "cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/internal/config"
	"github.com/transparency-dev/witness/omniwitness"
	"k8s.io/klog/v2"
)

// newSpannerPersistence returns a persistence object that is backed by the SQL database.
func newSpannerPersistence(ctx context.Context, spannerURI string) (*spannerPersistence, func() error, error) {
	sc, err := spanner.NewClient(ctx, spannerURI)
	if err != nil {
		return nil, nil, err
	}
	shutdown := func() error {
		sc.Close()
		return nil
	}
	ret := &spannerPersistence{
		spannerURI: spannerURI,
		spanner:    sc,
	}
	// Need to create tables here because omniGCP may try to update logs from the embedded config.
	if err := ret.createTablesIfNotExist(ctx); err != nil {
		return nil, nil, err
	}

	return ret, shutdown, nil
}

type spannerPersistence struct {
	spannerURI string
	spanner    *spanner.Client
}

func (p *spannerPersistence) Init(ctx context.Context) error {
	return nil
}

func (p *spannerPersistence) createTablesIfNotExist(ctx context.Context) error {
	adminClient, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := adminClient.Close(); err != nil {
			klog.Warningf("adminClient.Close(): %v", err)
		}
	}()

	op, err := adminClient.UpdateDatabaseDdl(ctx, &adminpb.UpdateDatabaseDdlRequest{
		Database: p.spannerURI,
		Statements: []string{
			"CREATE TABLE IF NOT EXISTS checkpoints (logID STRING(MAX) NOT NULL, checkpoint BYTES(MAX) NOT NULL) PRIMARY KEY (logID)",
			"CREATE TABLE IF NOT EXISTS logs (logID STRING(2048), origin STRING(2048) NOT NULL, vkey STRING(2048) NOT NULL, url STRING(2048), feeder STRING(32)) PRIMARY KEY(logID)",
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create tables: %v", err)
	}
	if err := op.Wait(ctx); err != nil {
		return err
	}

	return nil
}

func (p *spannerPersistence) Logs(ctx context.Context) iter.Seq2[config.Log, error] {
	return func(yield func(config.Log, error) bool) {
		r := p.spanner.Single().Read(ctx, "logs", spanner.AllKeys(), []string{"logID", "origin", "vkey", "url"})
		for {
			row, err := r.Next()
			if err != nil {
				if !yield(config.Log{}, fmt.Errorf("failed to read row: %v", err)) {
					return
				}
			}
			c := config.Log{}
			vkey := ""
			if err := row.Columns(&c.ID, &c.Origin, &vkey, &c.URL); err != nil {
				if !yield(config.Log{}, fmt.Errorf("failed to read columns: %v", err)) {
					return
				}
			}
			c.Verifier, err = note.NewVerifier(vkey)
			if err != nil {
				if !yield(config.Log{}, fmt.Errorf("failed to create verifier: %v", err)) {
					return
				}
			}
			if !yield(c, nil) {
				return
			}
		}
	}
}

func (p *spannerPersistence) Feeders(ctx context.Context) iter.Seq2[omniwitness.FeederConfig, error] {
	return func(yield func(omniwitness.FeederConfig, error) bool) {
		r := p.spanner.Single().Read(ctx, "logs", spanner.AllKeys(), []string{"logID", "origin", "vkey", "url", "feeder"})
		for {
			row, err := r.Next()
			if err != nil {
				if !yield(omniwitness.FeederConfig{}, fmt.Errorf("failed to read row: %v", err)) {
					return
				}
			}
			c := omniwitness.FeederConfig{}
			vkey := ""
			feeder := ""
			if err := row.Columns(&c.Log.ID, &c.Log.Origin, &vkey, &c.Log.URL, &feeder); err != nil {
				if !yield(omniwitness.FeederConfig{}, fmt.Errorf("failed to read columns: %v", err)) {
					return
				}
			}
			c.Log.Verifier, err = note.NewVerifier(vkey)
			if err != nil {
				if !yield(omniwitness.FeederConfig{}, fmt.Errorf("failed to create verifier: %v", err)) {
					return
				}
			}
			c.Feeder, err = omniwitness.ParseFeeder(feeder)
			if err != nil {
				if !yield(omniwitness.FeederConfig{}, fmt.Errorf("failed to create feeder: %v", err)) {
					return
				}
			}
			if !yield(c, nil) {
				return
			}
		}
	}

}

func (p *spannerPersistence) Log(ctx context.Context, id string) (config.Log, bool, error) {
	row, err := p.spanner.Single().ReadRow(ctx, "logs", spanner.Key{id}, []string{"origin", "vkey", "url"})
	if err != nil {
		if errors.Is(err, spanner.ErrRowNotFound) {
			return config.Log{}, false, nil
		}
		return config.Log{}, false, fmt.Errorf("failed to read row: %v", err)
	}
	c := config.Log{}
	vkey := ""
	if err := row.Columns(&c.ID, &c.Origin, &vkey, &c.URL); err != nil {
		return config.Log{}, false, fmt.Errorf("failed to read columns: %v", err)
	}
	c.Verifier, err = note.NewVerifier(vkey)
	if err != nil {
		return config.Log{}, false, fmt.Errorf("failed to create verifier: %v", err)
	}
	return c, true, nil
}

func (p *spannerPersistence) Latest(ctx context.Context, logID string) ([]byte, error) {
	return getLatestCheckpoint(ctx, p.spanner.Single().ReadRow, logID)
}

func (p *spannerPersistence) Update(ctx context.Context, logID string, f func([]byte) ([]byte, error)) error {
	_, err := p.spanner.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		current, err := getLatestCheckpoint(ctx, txn.ReadRow, logID)
		if err != nil {
			return err
		}

		updated, err := f(current)
		if err != nil {
			return err
		}
		m := []*spanner.Mutation{spanner.InsertOrUpdate("checkpoints", []string{"logID", "checkpoint"}, []any{logID, updated})}
		if err := txn.BufferWrite(m); err != nil {
			return fmt.Errorf("failed to buffer write: %v", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update: %w", err)
	}

	return nil
}

func getLatestCheckpoint(ctx context.Context, readRow func(ctx context.Context, table string, key spanner.Key, columns []string) (*spanner.Row, error), logID string) ([]byte, error) {
	row, err := readRow(ctx, "checkpoints", spanner.Key{logID}, []string{"checkpoint"})
	if err != nil {
		if errors.Is(err, spanner.ErrRowNotFound) {
			return nil, nil
		}
		return nil, err
	}
	var chkpt []byte
	if err := row.Column(0, &chkpt); err != nil {
		return nil, err
	}
	return chkpt, nil
}
