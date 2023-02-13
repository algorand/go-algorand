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
	"os"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

type trackerSQLStore struct {
	// expose the internals for now so we can slowly change the code depending on them
	pair db.Pair
}

type batchFn func(ctx context.Context, tx BatchScope) error

// BatchScope is the write scope to the store.
type BatchScope interface {
	MakeCatchpointWriter() (CatchpointWriter, error)
	MakeAccountsWriter() (AccountsWriterExt, error)
	MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (AccountsWriter, error)

	RunMigrations(ctx context.Context, params TrackerDBParams, log logging.Logger, targetVersion int32) (mgr TrackerDBInitParams, err error)
	ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error)

	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsUpdateSchemaTest(ctx context.Context) (err error)
}
type sqlBatchScope struct {
	tx *sql.Tx
}

type snapshotFn func(ctx context.Context, tx SnapshotScope) error

// SnapshotScope is the read scope to the store.
type SnapshotScope interface {
	MakeAccountsReader() (AccountsReaderExt, error)
	MakeCatchpointReader() (CatchpointReader, error)

	MakeCatchpointPendingHashesIterator(hashCount int) *catchpointPendingHashesIterator
}
type sqlSnapshotScope struct {
	tx *sql.Tx
}

type transactionFn func(ctx context.Context, tx TransactionScope) error

// TransactionScope is the read/write scope to the store.
type TransactionScope interface {
	MakeCatchpointReaderWriter() (CatchpointReaderWriter, error)
	MakeAccountsReaderWriter() (AccountsReaderWriter, error)
	MakeAccountsOptimizedReader() (AccountsReader, error)
	MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (AccountsWriter, error)
	MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (w OnlineAccountsWriter, err error)
	MakeOnlineAccountsOptimizedReader() (OnlineAccountsReader, error)

	MakeMerkleCommitter(staging bool) (MerkleCommitter, error)

	MakeOrderedAccountsIter(accountCount int) *orderedAccountsIter
	MakeKVsIter(ctx context.Context) (*kvsIter, error)
	MakeEncodedAccoutsBatchIter() *encodedAccountsBatchIter

	RunMigrations(ctx context.Context, params TrackerDBParams, log logging.Logger, targetVersion int32) (mgr TrackerDBInitParams, err error)
	ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error)

	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error)
}
type sqlTransactionScope struct {
	tx *sql.Tx
}

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

	MakeAccountsReader() (AccountsReader, error)
	MakeOnlineAccountsReader() (OnlineAccountsReader, error)

	MakeCatchpointReaderWriter() (CatchpointReaderWriter, error)

	Vacuum(ctx context.Context) (stats db.VacuumStats, err error)
	Close()
	CleanupTest(dbName string, inMemory bool)
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
		return fn(ctx, sqlBatchScope{tx})
	})
}

func (s *trackerSQLStore) Snapshot(fn snapshotFn) (err error) {
	return s.SnapshotContext(context.Background(), fn)
}

func (s *trackerSQLStore) SnapshotContext(ctx context.Context, fn snapshotFn) (err error) {
	return s.pair.Rdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, sqlSnapshotScope{tx})
	})
}

func (s *trackerSQLStore) Transaction(fn transactionFn) (err error) {
	return s.TransactionContext(context.Background(), fn)
}

func (s *trackerSQLStore) TransactionContext(ctx context.Context, fn transactionFn) (err error) {
	return s.pair.Wdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, sqlTransactionScope{tx})
	})
}

func (s *trackerSQLStore) MakeAccountsReader() (AccountsReader, error) {
	return AccountsInitDbQueries(s.pair.Rdb.Handle)
}

func (s *trackerSQLStore) MakeOnlineAccountsReader() (OnlineAccountsReader, error) {
	return OnlineAccountsInitDbQueries(s.pair.Rdb.Handle)
}

func (s *trackerSQLStore) MakeCatchpointReaderWriter() (CatchpointReaderWriter, error) {
	w := NewCatchpointSQLReaderWriter(s.pair.Wdb.Handle)
	return w, nil
}

// TODO: rename: this is a sqlite specific name, this could also be used to trigger compact on KV stores.
// it seems to only be used during a v2 migration
func (s *trackerSQLStore) Vacuum(ctx context.Context) (stats db.VacuumStats, err error) {
	_, err = s.pair.Wdb.Vacuum(ctx)
	return
}

func (s *trackerSQLStore) CleanupTest(dbName string, inMemory bool) {
	s.pair.Close()
	if !inMemory {
		os.Remove(dbName)
	}
}

func (s *trackerSQLStore) Close() {
	s.pair.Close()
}

func (txs sqlTransactionScope) MakeCatchpointReaderWriter() (CatchpointReaderWriter, error) {
	return NewCatchpointSQLReaderWriter(txs.tx), nil
}

func (txs sqlTransactionScope) MakeAccountsReaderWriter() (AccountsReaderWriter, error) {
	return NewAccountsSQLReaderWriter(txs.tx), nil
}

func (txs sqlTransactionScope) MakeAccountsOptimizedReader() (AccountsReader, error) {
	return AccountsInitDbQueries(txs.tx)
}

func (txs sqlTransactionScope) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (AccountsWriter, error) {
	return MakeAccountsSQLWriter(txs.tx, hasAccounts, hasResources, hasKvPairs, hasCreatables)
}

func (txs sqlTransactionScope) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (w OnlineAccountsWriter, err error) {
	return MakeOnlineAccountsSQLWriter(txs.tx, hasAccounts)
}

func (txs sqlTransactionScope) MakeOnlineAccountsOptimizedReader() (r OnlineAccountsReader, err error) {
	return OnlineAccountsInitDbQueries(txs.tx)
}

func (txs sqlTransactionScope) MakeMerkleCommitter(staging bool) (MerkleCommitter, error) {
	return MakeMerkleCommitter(txs.tx, staging)
}

func (txs sqlTransactionScope) MakeOrderedAccountsIter(accountCount int) *orderedAccountsIter {
	return MakeOrderedAccountsIter(txs.tx, accountCount)
}

func (txs sqlTransactionScope) MakeKVsIter(ctx context.Context) (*kvsIter, error) {
	return MakeKVsIter(ctx, txs.tx)
}

func (txs sqlTransactionScope) MakeEncodedAccoutsBatchIter() *encodedAccountsBatchIter {
	return MakeEncodedAccoutsBatchIter(txs.tx)
}

func (txs sqlTransactionScope) RunMigrations(ctx context.Context, params TrackerDBParams, log logging.Logger, targetVersion int32) (mgr TrackerDBInitParams, err error) {
	return RunMigrations(ctx, txs.tx, params, log, targetVersion)
}

func (txs sqlTransactionScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return db.ResetTransactionWarnDeadline(ctx, txs.tx, deadline)
}

func (txs sqlTransactionScope) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return AccountsInitTest(tb, txs.tx, initAccounts, proto)
}

func (txs sqlTransactionScope) AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error) {
	return AccountsInitLightTest(tb, txs.tx, initAccounts, proto)
}

func (bs sqlBatchScope) MakeCatchpointWriter() (CatchpointWriter, error) {
	return NewCatchpointSQLReaderWriter(bs.tx), nil
}

func (bs sqlBatchScope) MakeAccountsWriter() (AccountsWriterExt, error) {
	return NewAccountsSQLReaderWriter(bs.tx), nil
}

func (bs sqlBatchScope) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (AccountsWriter, error) {
	return MakeAccountsSQLWriter(bs.tx, hasAccounts, hasResources, hasKvPairs, hasCreatables)
}

func (bs sqlBatchScope) RunMigrations(ctx context.Context, params TrackerDBParams, log logging.Logger, targetVersion int32) (mgr TrackerDBInitParams, err error) {
	return RunMigrations(ctx, bs.tx, params, log, targetVersion)
}

func (bs sqlBatchScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return db.ResetTransactionWarnDeadline(ctx, bs.tx, deadline)
}

func (bs sqlBatchScope) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return AccountsInitTest(tb, bs.tx, initAccounts, proto)
}

func (bs sqlBatchScope) AccountsUpdateSchemaTest(ctx context.Context) (err error) {
	return AccountsUpdateSchemaTest(ctx, bs.tx)
}

func (ss sqlSnapshotScope) MakeAccountsReader() (AccountsReaderExt, error) {
	return NewAccountsSQLReaderWriter(ss.tx), nil
}

func (ss sqlSnapshotScope) MakeCatchpointReader() (CatchpointReader, error) {
	return NewCatchpointSQLReaderWriter(ss.tx), nil
}

func (ss sqlSnapshotScope) MakeCatchpointPendingHashesIterator(hashCount int) *catchpointPendingHashesIterator {
	return MakeCatchpointPendingHashesIterator(hashCount, ss.tx)
}
