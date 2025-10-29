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

// Package sql provides log state persistence backed by a SQL database.
package sql

import (
	"context"
	"database/sql"
	"fmt"
	"iter"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/internal/config"
	"k8s.io/klog/v2"
)

// NewPersistence returns a persistence object that is backed by the SQL database.
func NewPersistence(db *sql.DB) *sqlLogPersistence {
	return &sqlLogPersistence{
		db: db,
	}
}

type sqlLogPersistence struct {
	db *sql.DB
}

func (p *sqlLogPersistence) Init(ctx context.Context) error {
	for _, ddl := range []string{
		"CREATE TABLE IF NOT EXISTS chkpts (logID BLOB PRIMARY KEY, chkpt BLOB)",
		"CREATE TABLE IF NOT EXISTS logs (logID BLOB PRIMARY KEY, origin STRING NOT NULL, vkey STRING NOT NULL, contact STRING, qpd FLOAT64, disabled BOOL)",
	} {
		if _, err := p.db.ExecContext(ctx, ddl); err != nil {
			return err
		}
	}
	return nil
}

func (p *sqlLogPersistence) AddLogs(ctx context.Context, lc []config.Log) error {
	for _, l := range lc {
		// Note that it's a deliberate choice here to use Insert so as to guarantee that we will not
		// update the stored config for a given log. There may be reasons to revisit this in the future,
		// and the spec isn't [yet] clear. One thing we certainly will _not_ want, though, is that an
		// automated update from the public witness network configs can re-enable an administratively
		// disabled log.
		if _, err := p.db.ExecContext(ctx, "INSERT OR IGNORE INTO logs (logID, origin, vkey, contact, qpd, disabled) VALUES (?, ?, ?, ?, ?,  False)", log.ID(l.Origin), l.Origin, l.VKey, l.Contact, l.QPD); err != nil {
			return fmt.Errorf("failed to insert config for log %q: %v", l.Origin, err)
		}
		klog.V(1).Infof("Provisioned log %q into config", l.Origin)
	}
	return nil
}

func (p *sqlLogPersistence) Logs(ctx context.Context) iter.Seq2[config.Log, error] {
	return func(yield func(config.Log, error) bool) {
		rows, err := p.db.QueryContext(ctx, "SELECT origin, vkey, contact, disabled FROM logs")
		if err != nil {
			if !yield(config.Log{}, fmt.Errorf("failed to select from logs: %v", err)) {
				return
			}
		}
		defer func() {
			_ = rows.Close()
		}()
		for rows.Next() {
			c := config.Log{}
			disabled := false
			if err := rows.Scan(&c.Origin, &c.VKey, &c.Contact, &disabled); err != nil {
				if !yield(config.Log{}, fmt.Errorf("failed to scan columns: %v", err)) {
					return
				}
			}
			if disabled {
				klog.V(1).Infof("Skipping disabled log %q", c.Origin)
				continue
			}
			c.Verifier, err = note.NewVerifier(c.VKey)
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

func (p *sqlLogPersistence) Log(ctx context.Context, origin string) (config.Log, bool, error) {
	logID := log.ID(origin)
	row := p.db.QueryRowContext(ctx, "SELECT origin, vkey, contact, disabled FROM logs WHERE logID = ?", logID)
	if row.Err() != nil {
		return config.Log{}, false, fmt.Errorf("failed to select from logs: %v", row.Err())
	}
	c := config.Log{}
	disabled := false
	if err := row.Scan(&c.Origin, &c.VKey, &c.Contact, &disabled); err != nil {
		return config.Log{}, false, fmt.Errorf("failed to scan columns: %v", err)
	}
	if disabled {
		klog.V(1).Infof("Ignoring disabled log %q", c.Origin)
		return c, false, nil
	}
	var err error
	c.Verifier, err = note.NewVerifier(c.VKey)
	if err != nil {
		return config.Log{}, false, fmt.Errorf("failed to create verifier: %v", err)
	}
	return c, true, nil
}

func (p *sqlLogPersistence) Latest(ctx context.Context, origin string) ([]byte, error) {
	logID := log.ID(origin)
	return getLatestCheckpoint(ctx, p.db.QueryRowContext, logID)
}

func (p *sqlLogPersistence) Update(ctx context.Context, origin string, f func([]byte) ([]byte, error)) error {
	logID := log.ID(origin)
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	current, err := getLatestCheckpoint(ctx, tx.QueryRowContext, logID)
	if err != nil {
		return err
	}

	updated, err := f(current)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO chkpts (logID, chkpt) VALUES (?, ?)`, logID, updated); err != nil {
		return fmt.Errorf("Exec(): %v", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	tx = nil
	return nil
}

func getLatestCheckpoint(ctx context.Context, queryRow func(ctx context.Context, query string, args ...interface{}) *sql.Row, logID string) ([]byte, error) {
	row := queryRow(ctx, "SELECT chkpt FROM chkpts WHERE logID = ?", logID)
	if err := row.Err(); err != nil {
		return nil, err
	}
	var chkpt []byte
	if err := row.Scan(&chkpt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return chkpt, nil
}
