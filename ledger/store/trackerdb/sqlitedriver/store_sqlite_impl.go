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

package sqlitedriver

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

type trackerSQLStore struct {
	// expose the internals for now so we can slowly change the code depending on them
	pair db.Pair
}

type sqlBatchScope struct {
	tx *sql.Tx
}

type sqlSnapshotScope struct {
	tx *sql.Tx
}

type sqlTransactionScope struct {
	tx *sql.Tx
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

func (s *trackerSQLStore) Batch(fn trackerdb.BatchFn) (err error) {
	return s.BatchContext(context.Background(), fn)
}

func (s *trackerSQLStore) BatchContext(ctx context.Context, fn trackerdb.BatchFn) (err error) {
	return s.pair.Wdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, sqlBatchScope{tx})
	})
}

func (s *trackerSQLStore) Snapshot(fn trackerdb.SnapshotFn) (err error) {
	return s.SnapshotContext(context.Background(), fn)
}

func (s *trackerSQLStore) SnapshotContext(ctx context.Context, fn trackerdb.SnapshotFn) (err error) {
	return s.pair.Rdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, sqlSnapshotScope{tx})
	})
}

func (s *trackerSQLStore) Transaction(fn trackerdb.TransactionFn) (err error) {
	return s.TransactionContext(context.Background(), fn)
}

func (s *trackerSQLStore) TransactionContext(ctx context.Context, fn trackerdb.TransactionFn) (err error) {
	return s.pair.Wdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, sqlTransactionScope{tx})
	})
}

func (s *trackerSQLStore) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	return NewAccountsSQLReaderWriter(s.pair.Wdb.Handle), nil
}

func (s *trackerSQLStore) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	return NewAccountsSQLReaderWriter(s.pair.Rdb.Handle), nil
}

func (s *trackerSQLStore) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	return MakeAccountsSQLWriter(s.pair.Wdb.Handle, hasAccounts, hasResources, hasKvPairs, hasCreatables)
}

func (s *trackerSQLStore) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	return AccountsInitDbQueries(s.pair.Rdb.Handle)
}

func (s *trackerSQLStore) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (trackerdb.OnlineAccountsWriter, error) {
	return MakeOnlineAccountsSQLWriter(s.pair.Wdb.Handle, hasAccounts)
}

func (s *trackerSQLStore) MakeOnlineAccountsOptimizedReader() (trackerdb.OnlineAccountsReader, error) {
	return OnlineAccountsInitDbQueries(s.pair.Rdb.Handle)
}

func (s *trackerSQLStore) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
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

func (s *trackerSQLStore) ResetToV6Test(ctx context.Context) error {
	var resetExprs = []string{
		`DROP TABLE IF EXISTS onlineaccounts`,
		`DROP TABLE IF EXISTS txtail`,
		`DROP TABLE IF EXISTS onlineroundparamstail`,
		`DROP TABLE IF EXISTS catchpointfirststageinfo`,
	}

	return s.pair.Wdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		for _, stmt := range resetExprs {
			_, err := tx.ExecContext(ctx, stmt)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *trackerSQLStore) Close() {
	s.pair.Close()
}

// Testing returns this scope, exposed as an interface with test functions
func (txs sqlTransactionScope) Testing() trackerdb.TestTransactionScope {
	return txs
}

func (txs sqlTransactionScope) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
	return NewCatchpointSQLReaderWriter(txs.tx), nil
}

func (txs sqlTransactionScope) MakeAccountsReaderWriter() (trackerdb.AccountsReaderWriter, error) {
	return NewAccountsSQLReaderWriter(txs.tx), nil
}

// implements Testing interface
func (txs sqlTransactionScope) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	return AccountsInitDbQueries(txs.tx)
}

func (txs sqlTransactionScope) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	return MakeAccountsSQLWriter(txs.tx, hasAccounts, hasResources, hasKvPairs, hasCreatables)
}

func (txs sqlTransactionScope) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (w trackerdb.OnlineAccountsWriter, err error) {
	return MakeOnlineAccountsSQLWriter(txs.tx, hasAccounts)
}

// implements Testing interface
func (txs sqlTransactionScope) MakeOnlineAccountsOptimizedReader() (r trackerdb.OnlineAccountsReader, err error) {
	return OnlineAccountsInitDbQueries(txs.tx)
}

func (txs sqlTransactionScope) MakeMerkleCommitter(staging bool) (trackerdb.MerkleCommitter, error) {
	return MakeMerkleCommitter(txs.tx, staging)
}

func (txs sqlTransactionScope) MakeOrderedAccountsIter(accountCount int) trackerdb.OrderedAccountsIter {
	return MakeOrderedAccountsIter(txs.tx, accountCount)
}

func (txs sqlTransactionScope) MakeKVsIter(ctx context.Context) (trackerdb.KVsIter, error) {
	return MakeKVsIter(ctx, txs.tx)
}

func (txs sqlTransactionScope) MakeEncodedAccoutsBatchIter() trackerdb.EncodedAccountsBatchIter {
	return MakeEncodedAccoutsBatchIter(txs.tx)
}

func (txs sqlTransactionScope) MakeSpVerificationCtxReaderWriter() trackerdb.SpVerificationCtxReaderWriter {
	return makeStateProofVerificationReaderWriter(txs.tx, txs.tx)
}

func (txs sqlTransactionScope) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	return RunMigrations(ctx, txs.tx, params, log, targetVersion)
}

func (txs sqlTransactionScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return db.ResetTransactionWarnDeadline(ctx, txs.tx, deadline)
}

// implements Testing interface
func (txs sqlTransactionScope) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return AccountsInitTest(tb, txs.tx, initAccounts, proto)
}

// implements Testing interface
func (txs sqlTransactionScope) AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error) {
	return AccountsInitLightTest(tb, txs.tx, initAccounts, proto)
}

// Testing returns this scope, exposed as an interface with test functions
func (bs sqlBatchScope) Testing() trackerdb.TestBatchScope {
	return bs
}

func (bs sqlBatchScope) MakeCatchpointWriter() (trackerdb.CatchpointWriter, error) {
	return NewCatchpointSQLReaderWriter(bs.tx), nil
}

func (bs sqlBatchScope) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	return NewAccountsSQLReaderWriter(bs.tx), nil
}

func (bs sqlBatchScope) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	return MakeAccountsSQLWriter(bs.tx, hasAccounts, hasResources, hasKvPairs, hasCreatables)
}

// implements Testing interface
func (bs sqlBatchScope) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	return RunMigrations(ctx, bs.tx, params, log, targetVersion)
}

func (bs sqlBatchScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return db.ResetTransactionWarnDeadline(ctx, bs.tx, deadline)
}

// implements Testing interface
func (bs sqlBatchScope) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return AccountsInitTest(tb, bs.tx, initAccounts, proto)
}

// implements Testing interface
func (bs sqlBatchScope) ModifyAcctBaseTest() error {
	return modifyAcctBaseTest(bs.tx)
}

// implements Testing interface
func (bs sqlBatchScope) AccountsUpdateSchemaTest(ctx context.Context) (err error) {
	return AccountsUpdateSchemaTest(ctx, bs.tx)
}

func (bs sqlBatchScope) MakeSpVerificationCtxWriter() trackerdb.SpVerificationCtxWriter {
	return makeStateProofVerificationWriter(bs.tx)
}

func (ss sqlSnapshotScope) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	return NewAccountsSQLReaderWriter(ss.tx), nil
}

func (ss sqlSnapshotScope) MakeCatchpointReader() (trackerdb.CatchpointReader, error) {
	return NewCatchpointSQLReaderWriter(ss.tx), nil
}

func (ss sqlSnapshotScope) MakeCatchpointPendingHashesIterator(hashCount int) trackerdb.CatchpointPendingHashesIter {
	return MakeCatchpointPendingHashesIterator(hashCount, ss.tx)
}

func (ss sqlSnapshotScope) MakeSpVerificationCtxReader() trackerdb.SpVerificationCtxReader {
	return makeStateProofVerificationReader(ss.tx)
}
