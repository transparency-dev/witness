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

	"github.com/transparency-dev/witness/internal/persistence"
	"k8s.io/klog/v2"
)

// NewPersistence returns a persistence object that is backed by the SQL database.
func NewPersistence(db *sql.DB) persistence.LogStatePersistence {
	return &sqlLogPersistence{
		db: db,
	}
}

type sqlLogPersistence struct {
	db *sql.DB
}

func (p *sqlLogPersistence) Init(_ context.Context) error {
	_, err := p.db.Exec(`CREATE TABLE IF NOT EXISTS chkpts (
		logID BLOB PRIMARY KEY,
		chkpt BLOB
		)`)
	return err
}

func (p *sqlLogPersistence) Logs(_ context.Context) ([]string, error) {
	rows, err := p.db.Query("SELECT logID FROM chkpts")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			klog.Errorf("Failed to close rows: %v", err)
		}
	}()

	var logs []string
	for rows.Next() {
		var logID string
		err := rows.Scan(&logID)
		if err != nil {
			return nil, err
		}
		logs = append(logs, logID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return logs, nil
}

func (p *sqlLogPersistence) Latest(_ context.Context, logID string) ([]byte, error) {
	return getLatestCheckpoint(p.db.QueryRow, logID)
}

func (p *sqlLogPersistence) Update(_ context.Context, logID string, f func([]byte) ([]byte, error)) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	current, err := getLatestCheckpoint(tx.QueryRow, logID)
	if err != nil {
		return err
	}

	updated, err := f(current)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO chkpts (logID, chkpt) VALUES (?, ?)`, logID, updated); err != nil {
		return fmt.Errorf("Exec(): %v", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	tx = nil
	return nil
}

func getLatestCheckpoint(queryRow func(query string, args ...interface{}) *sql.Row, logID string) ([]byte, error) {
	row := queryRow("SELECT chkpt FROM chkpts WHERE logID = ?", logID)
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
