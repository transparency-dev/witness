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

	"cloud.google.com/go/spanner"
	database "cloud.google.com/go/spanner/admin/database/apiv1"
	adminpb "cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"github.com/transparency-dev/witness/internal/persistence"
	"k8s.io/klog/v2"
)

// newSpannerPersistence returns a persistence object that is backed by the SQL database.
func newSpannerPersistence(ctx context.Context, spannerURI string) (persistence.LogStatePersistence, func() error, error) {
	sc, err := spanner.NewClient(ctx, spannerURI)
	if err != nil {
		return nil, nil, err
	}
	shutdown := func() error {
		sc.Close()
		return nil
	}
	return &spannerPersistence{
		spannerURI: spannerURI,
		spanner:    sc,
	}, shutdown, nil
}

type spannerPersistence struct {
	spannerURI string
	spanner    *spanner.Client
}

func (p *spannerPersistence) Init(ctx context.Context) error {
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
