// Copyright (C) 2019-2023 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package store

import (
	"context"
	"database/sql"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
)

type trackerSQLStore struct {
	// expose the internals for now so we can slowly change the code depending on them
	pair db.Pair
}

// TODO: maintain a SQL tx for now
type batchFn func(ctx context.Context, tx *sql.Tx) error

// TODO: maintain a SQL tx for now
type snapshotFn func(ctx context.Context, tx *sql.Tx) error

// TODO: maintain a SQL tx for now
type transactionFn func(ctx context.Context, tx *sql.Tx) error

// TrackerStore is the interface for the tracker db.
type TrackerStore interface {
	SetLogger(log logging.Logger)
	SetSynchronousMode(ctx context.Context, mode db.SynchronousMode, fullfsync bool) (err error)
	IsSharedCacheConnection() bool

	Batch(fn batchFn) (err error)
	BatchContext(ctx context.Context, fn batchFn) (err error)

	Snapshot(fn snapshotFn) (err error)
	SnapshotContext(ctx context.Context, fn snapshotFn) (err error)

	Transaction(fn transactionFn) (err error)
	TransactionContext(ctx context.Context, fn transactionFn) (err error)

	CreateAccountsReader() (AccountsReader, error)
	CreateOnlineAccountsReader() (OnlineAccountsReader, error)

	CreateCatchpointReaderWriter() (CatchpointReaderWriter, error)

	Vacuum(ctx context.Context) (stats db.VacuumStats, err error)
	Close()
}

// OpenTrackerSQLStore opens the sqlite database store
func OpenTrackerSQLStore(dbFilename string, dbMem bool) (store *trackerSQLStore, err error) {
	db, err := db.OpenPair(dbFilename, dbMem)
	if err != nil {
		return
	}

	return &trackerSQLStore{db}, nil
}

// CreateTrackerSQLStore crates a tracker SQL db from sql db handle.
func CreateTrackerSQLStore(pair db.Pair) *trackerSQLStore {
	return &trackerSQLStore{pair}
}

// SetLogger sets the Logger, mainly for unit test quietness
func (s *trackerSQLStore) SetLogger(log logging.Logger) {
	s.pair.Rdb.SetLogger(log)
	s.pair.Wdb.SetLogger(log)
}

func (s *trackerSQLStore) SetSynchronousMode(ctx context.Context, mode db.SynchronousMode, fullfsync bool) (err error) {
	return s.pair.Wdb.SetSynchronousMode(ctx, mode, fullfsync)
}

func (s *trackerSQLStore) IsSharedCacheConnection() bool {
	return s.pair.Wdb.IsSharedCacheConnection()
}

func (s *trackerSQLStore) Batch(fn batchFn) (err error) {
	return s.BatchContext(context.Background(), fn)
}

func (s *trackerSQLStore) BatchContext(ctx context.Context, fn batchFn) (err error) {
	return s.pair.Wdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, tx)
	})
}

func (s *trackerSQLStore) Snapshot(fn snapshotFn) (err error) {
	return s.SnapshotContext(context.Background(), fn)
}

func (s *trackerSQLStore) SnapshotContext(ctx context.Context, fn snapshotFn) (err error) {
	return s.pair.Rdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, tx)
	})
}

func (s *trackerSQLStore) Transaction(fn transactionFn) (err error) {
	return s.TransactionContext(context.Background(), fn)
}

func (s *trackerSQLStore) TransactionContext(ctx context.Context, fn transactionFn) (err error) {
	return s.pair.Wdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, tx)
	})
}

func (s *trackerSQLStore) CreateAccountsReader() (AccountsReader, error) {
	return AccountsInitDbQueries(s.pair.Rdb.Handle)
}

func (s *trackerSQLStore) CreateOnlineAccountsReader() (OnlineAccountsReader, error) {
	return OnlineAccountsInitDbQueries(s.pair.Rdb.Handle)
}

func (s *trackerSQLStore) CreateCatchpointReaderWriter() (CatchpointReaderWriter, error) {
	w := NewCatchpointSQLReaderWriter(s.pair.Wdb.Handle)
	return w, nil
}

// TODO: rename: this is a sqlite specific name, this could also be used to trigger compact on KV stores.
// it seems to only be used during a v2 migration
func (s *trackerSQLStore) Vacuum(ctx context.Context) (stats db.VacuumStats, err error) {
	_, err = s.pair.Wdb.Vacuum(ctx)
	return
}

func (s *trackerSQLStore) Close() {
	s.pair.Close()
}
