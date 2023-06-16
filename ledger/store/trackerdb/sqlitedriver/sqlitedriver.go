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
	pair db.Pair
	trackerdb.Reader
	trackerdb.Writer
	trackerdb.Catchpoint
}

// Open opens the sqlite database store
func Open(dbFilename string, dbMem bool, log logging.Logger) (store trackerdb.Store, err error) {
	pair, err := db.OpenPair(dbFilename, dbMem)
	if err != nil {
		return
	}
	pair.Rdb.SetLogger(log)
	pair.Wdb.SetLogger(log)
	return MakeStore(pair), nil
}

// MakeStore crates a tracker SQL db from sql db handle.
func MakeStore(pair db.Pair) trackerdb.Store {
	return &trackerSQLStore{pair, &sqlReader{pair.Rdb.Handle}, &sqlWriter{pair.Wdb.Handle}, &sqlCatchpoint{pair.Wdb.Handle}}
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
		return fn(ctx, &sqlBatchScope{tx, false, &sqlWriter{tx}})
	})
}

func (s *trackerSQLStore) BeginBatch(ctx context.Context) (trackerdb.Batch, error) {
	handle, err := s.pair.Wdb.Handle.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &sqlBatchScope{handle, false, &sqlWriter{handle}}, nil
}

func (s *trackerSQLStore) Snapshot(fn trackerdb.SnapshotFn) (err error) {
	return s.SnapshotContext(context.Background(), fn)
}

func (s *trackerSQLStore) SnapshotContext(ctx context.Context, fn trackerdb.SnapshotFn) (err error) {
	return s.pair.Rdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, sqlSnapshotScope{tx, &sqlReader{tx}})
	})
}

func (s *trackerSQLStore) BeginSnapshot(ctx context.Context) (trackerdb.Snapshot, error) {
	handle, err := s.pair.Rdb.Handle.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &sqlSnapshotScope{handle, &sqlReader{handle}}, nil
}

func (s *trackerSQLStore) Transaction(fn trackerdb.TransactionFn) (err error) {
	return s.TransactionContext(context.Background(), fn)
}

func (s *trackerSQLStore) TransactionContext(ctx context.Context, fn trackerdb.TransactionFn) (err error) {
	return s.pair.Wdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, &sqlTransactionScope{tx, false, &sqlReader{tx}, &sqlWriter{tx}, &sqlCatchpoint{tx}})
	})
}

func (s *trackerSQLStore) BeginTransaction(ctx context.Context) (trackerdb.Transaction, error) {
	handle, err := s.pair.Wdb.Handle.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &sqlTransactionScope{handle, false, &sqlReader{handle}, &sqlWriter{handle}, &sqlCatchpoint{handle}}, nil
}

func (s trackerSQLStore) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	err = s.pair.Wdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		mgr, err = RunMigrations(ctx, tx, params, log, targetVersion)
		return err
	})
	return
}

// TODO: rename: this is a sqlite specific name, this could also be used to trigger compact on KV stores.
// it seems to only be used during a v2 migration
func (s *trackerSQLStore) Vacuum(ctx context.Context) (stats db.VacuumStats, err error) {
	_, err = s.pair.Wdb.Vacuum(ctx)
	return
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

type sqlReader struct {
	q db.Queryable
}

// MakeAccountsOptimizedReader implements trackerdb.Reader
func (r *sqlReader) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	return AccountsInitDbQueries(r.q)
}

// MakeAccountsReader implements trackerdb.Reader
func (r *sqlReader) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	// TODO: create and use a make accounts reader that takes just a queryable
	return NewAccountsSQLReader(r.q), nil
}

// MakeOnlineAccountsOptimizedReader implements trackerdb.Reader
func (r *sqlReader) MakeOnlineAccountsOptimizedReader() (trackerdb.OnlineAccountsReader, error) {
	return OnlineAccountsInitDbQueries(r.q)
}

// MakeSpVerificationCtxReader implements trackerdb.Reader
func (r *sqlReader) MakeSpVerificationCtxReader() trackerdb.SpVerificationCtxReader {
	return makeStateProofVerificationReader(r.q)
}

type sqlWriter struct {
	e db.Executable
}

// MakeAccountsOptimizedWriter implements trackerdb.Writer
func (w *sqlWriter) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	return MakeAccountsSQLWriter(w.e, hasAccounts, hasResources, hasKvPairs, hasCreatables)
}

// MakeAccountsWriter implements trackerdb.Writer
func (w *sqlWriter) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	return NewAccountsSQLReaderWriter(w.e), nil
}

// MakeOnlineAccountsOptimizedWriter implements trackerdb.Writer
func (w *sqlWriter) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (trackerdb.OnlineAccountsWriter, error) {
	return MakeOnlineAccountsSQLWriter(w.e, hasAccounts)
}

// MakeSpVerificationCtxWriter implements trackerdb.Writer
func (w *sqlWriter) MakeSpVerificationCtxWriter() trackerdb.SpVerificationCtxWriter {
	return makeStateProofVerificationWriter(w.e)
}

// Testing implements trackerdb.Writer
func (w *sqlWriter) Testing() trackerdb.WriterTestExt {
	return w
}

// AccountsInitLightTest implements trackerdb.WriterTestExt
func (w *sqlWriter) AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error) {
	return AccountsInitLightTest(tb, w.e, initAccounts, proto)
}

// AccountsInitTest implements trackerdb.WriterTestExt
func (w *sqlWriter) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return AccountsInitTest(tb, w.e, initAccounts, proto)
}

// AccountsUpdateSchemaTest implements trackerdb.WriterTestExt
func (w *sqlWriter) AccountsUpdateSchemaTest(ctx context.Context) (err error) {
	return AccountsUpdateSchemaTest(ctx, w.e)
}

// ModifyAcctBaseTest implements trackerdb.WriterTestExt
func (w *sqlWriter) ModifyAcctBaseTest() error {
	return modifyAcctBaseTest(w.e)
}

type sqlCatchpoint struct {
	e db.Executable
}

// MakeCatchpointPendingHashesIterator implements trackerdb.Catchpoint
func (c *sqlCatchpoint) MakeCatchpointPendingHashesIterator(hashCount int) trackerdb.CatchpointPendingHashesIter {
	return MakeCatchpointPendingHashesIterator(hashCount, c.e)
}

// MakeCatchpointReader implements trackerdb.Catchpoint
func (c *sqlCatchpoint) MakeCatchpointReader() (trackerdb.CatchpointReader, error) {
	return NewCatchpointSQLReaderWriter(c.e), nil
}

// MakeCatchpointReaderWriter implements trackerdb.Catchpoint
func (c *sqlCatchpoint) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
	return NewCatchpointSQLReaderWriter(c.e), nil
}

// MakeCatchpointWriter implements trackerdb.Catchpoint
func (c *sqlCatchpoint) MakeCatchpointWriter() (trackerdb.CatchpointWriter, error) {
	return NewCatchpointSQLReaderWriter(c.e), nil
}

// MakeEncodedAccoutsBatchIter implements trackerdb.Catchpoint
func (c *sqlCatchpoint) MakeEncodedAccoutsBatchIter() trackerdb.EncodedAccountsBatchIter {
	return MakeEncodedAccoutsBatchIter(c.e)
}

// MakeKVsIter implements trackerdb.Catchpoint
func (c *sqlCatchpoint) MakeKVsIter(ctx context.Context) (trackerdb.KVsIter, error) {
	return MakeKVsIter(ctx, c.e)
}

// MakeMerkleCommitter implements trackerdb.Catchpoint
func (c *sqlCatchpoint) MakeMerkleCommitter(staging bool) (trackerdb.MerkleCommitter, error) {
	return MakeMerkleCommitter(c.e, staging)
}

// MakeOrderedAccountsIter implements trackerdb.Catchpoint
func (c *sqlCatchpoint) MakeOrderedAccountsIter(accountCount int) trackerdb.OrderedAccountsIter {
	return MakeOrderedAccountsIter(c.e, accountCount)
}

type sqlBatchScope struct {
	tx        *sql.Tx
	committed bool
	trackerdb.Writer
}

func (bs *sqlBatchScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return db.ResetTransactionWarnDeadline(ctx, bs.tx, deadline)
}

func (bs *sqlBatchScope) Close() error {
	if !bs.committed {
		return bs.tx.Rollback()
	}
	return nil
}

func (bs *sqlBatchScope) Commit() error {
	err := bs.tx.Commit()
	if err != nil {
		return err
	}
	bs.committed = true
	return nil
}

type sqlSnapshotScope struct {
	tx *sql.Tx
	trackerdb.Reader
}

func (ss sqlSnapshotScope) Close() error {
	return ss.tx.Rollback()
}

type sqlTransactionScope struct {
	tx        *sql.Tx
	committed bool
	trackerdb.Reader
	trackerdb.Writer
	trackerdb.Catchpoint
}

func (txs *sqlTransactionScope) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	return RunMigrations(ctx, txs.tx, params, log, targetVersion)
}

func (txs *sqlTransactionScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return db.ResetTransactionWarnDeadline(ctx, txs.tx, deadline)
}

func (txs *sqlTransactionScope) Close() error {
	if !txs.committed {
		return txs.tx.Rollback()
	}
	return nil
}

func (txs *sqlTransactionScope) Commit() error {
	err := txs.tx.Commit()
	if err != nil {
		return err
	}
	txs.committed = true
	return nil
}
