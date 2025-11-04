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
	"cloud.google.com/go/spanner/apiv1/spannerpb"
	logfmt "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/omniwitness"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		batchWrite: batchWrite,
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

	// batchWrite is a function to use for doing spanner batch writes.
	// This only exists as an escape hatch for testing; the spanner inmemory test code doesn't
	// support BatchWrite, so tests need to be able to replace this with _something else_.
	batchWrite func(context.Context, *spanner.Client, []*spanner.MutationGroup) error
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
			"CREATE TABLE IF NOT EXISTS logs (logID STRING(2048), origin STRING(2048) NOT NULL, vkey STRING(2048) NOT NULL, contact STRING(2048), qpd FLOAT64, disabled BOOL) PRIMARY KEY(logID)",
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

func (p *spannerPersistence) AddLogs(ctx context.Context, lc []omniwitness.Log) error {
	m := []*spanner.MutationGroup{}
	for _, l := range lc {
		// Note that it's a deliberate choice here to use Insert so as to guarantee that we will not
		// update the stored config for a given log. There may be reasons to revisit this in the future,
		// and the spec isn't [yet] clear. One thing we certainly will _not_ want, though, is that an
		// automated update from the public witness network configs can re-enable an administratively
		// disabled log.
		m = append(m, &spanner.MutationGroup{Mutations: []*spanner.Mutation{spanner.Insert(
			"logs",
			[]string{"logID", "origin", "vkey", "contact"},
			[]any{logfmt.ID(l.Origin), l.Origin, l.VKey, l.Contact},
		)}})
	}
	return p.batchWrite(ctx, p.spanner, m)
}

func batchWrite(ctx context.Context, s *spanner.Client, m []*spanner.MutationGroup) error {
	errs := []error{}
	err := s.BatchWrite(ctx, m).Do(func(r *spannerpb.BatchWriteResponse) error {
		switch c := codes.Code(r.Status.Code); c {
		case codes.OK:
		case codes.AlreadyExists:
		default:
			errs = append(errs, status.Error(codes.Code(r.Status.Code), r.Status.Message))
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to inspect batch write responses: %v", err)

	}

	return errors.Join(errs...)
}

func (p *spannerPersistence) Logs(ctx context.Context) iter.Seq2[omniwitness.Log, error] {
	return func(yield func(omniwitness.Log, error) bool) {
		r := p.spanner.Single().Read(ctx, "logs", spanner.AllKeys(), []string{"origin", "vkey", "contact", "disabled"})
		for {
			row, err := r.Next()
			if err != nil {
				if err == iterator.Done {
					return
				}
				if !yield(omniwitness.Log{}, fmt.Errorf("failed to read row: %v", err)) {
					return
				}
			}
			c := omniwitness.Log{}
			var disabled spanner.NullBool
			var contact spanner.NullString
			if err := row.Columns(&c.Origin, &c.VKey, &contact, &disabled); err != nil {
				if !yield(omniwitness.Log{}, fmt.Errorf("failed to read columns: %v", err)) {
					return
				}
			}
			if disabled.Bool {
				klog.V(1).Infof("Skipping disabled log %q", c.Origin)
				continue
			}
			c.Contact = contact.StringVal
			c.Verifier, err = note.NewVerifier(c.VKey)
			if err != nil {
				if !yield(omniwitness.Log{}, fmt.Errorf("failed to create verifier: %v", err)) {
					return
				}
			}
			if !yield(c, nil) {
				return
			}
		}
	}
}

func (p *spannerPersistence) Log(ctx context.Context, origin string) (omniwitness.Log, bool, error) {
	logID := logfmt.ID(origin)
	row, err := p.spanner.Single().ReadRow(ctx, "logs", spanner.Key{logID}, []string{"origin", "vkey", "contact", "disabled"})
	if err != nil {
		if errors.Is(err, spanner.ErrRowNotFound) {
			return omniwitness.Log{}, false, nil
		}
		return omniwitness.Log{}, false, fmt.Errorf("failed to read row: %v", err)
	}
	c := omniwitness.Log{}
	var disabled spanner.NullBool
	var contact spanner.NullString
	if err := row.Columns(&c.Origin, &c.VKey, &contact, &disabled); err != nil {
		return omniwitness.Log{}, false, fmt.Errorf("failed to read columns: %v", err)
	}
	if disabled.Bool {
		klog.V(1).Infof("Ignoring disabled log %q", c.Origin)
		return c, false, nil
	}
	c.Contact = contact.StringVal
	c.Verifier, err = note.NewVerifier(c.VKey)
	if err != nil {
		return omniwitness.Log{}, false, fmt.Errorf("failed to create verifier: %v", err)
	}
	return c, true, nil
}

func (p *spannerPersistence) Latest(ctx context.Context, origin string) ([]byte, error) {
	logID := logfmt.ID(origin)
	return getLatestCheckpoint(ctx, p.spanner.Single().ReadRow, logID)
}

func (p *spannerPersistence) Update(ctx context.Context, origin string, f func([]byte) ([]byte, error)) error {
	logID := logfmt.ID(origin)
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
