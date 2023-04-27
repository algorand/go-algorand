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

package dualdriver

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
	"github.com/google/go-cmp/cmp"
)

var ErrInconsistentResult = errors.New("inconsistent results between store engines")

var allowAllUnexported = cmp.Exporter(func(f reflect.Type) bool { return true })

type trackerStore struct {
	primary   trackerdb.TrackerStore
	secondary trackerdb.TrackerStore
}

// MakeStore creates a dual tracker store that verifies that both stores return the same results.
func MakeStore(primary trackerdb.TrackerStore, secondary trackerdb.TrackerStore) *trackerStore {
	return &trackerStore{primary, secondary}
}

func (s *trackerStore) SetLogger(log logging.Logger) {
	s.primary.SetLogger(log)
	s.secondary.SetLogger(log)
}

func (s *trackerStore) SetSynchronousMode(ctx context.Context, mode db.SynchronousMode, fullfsync bool) (err error) {
	errP := s.primary.SetSynchronousMode(ctx, mode, fullfsync)
	errS := s.secondary.SetSynchronousMode(ctx, mode, fullfsync)
	return coalesceErrors(errP, errS)
}

func (s *trackerStore) IsSharedCacheConnection() bool {
	// TODO
	return false
}

func (s *trackerStore) Batch(fn trackerdb.BatchFn) (err error) {
	return s.BatchContext(context.Background(), fn)
}

func (s *trackerStore) BatchContext(ctx context.Context, fn trackerdb.BatchFn) (err error) {
	handle, err := s.BeginBatch(ctx)
	if err != nil {
		return err
	}
	err = fn(ctx, handle)
	if err != nil {
		handle.Close()
		return err
	}
	return handle.Commit()
}

func (s *trackerStore) BeginBatch(ctx context.Context) (trackerdb.Batch, error) {
	primary, err := s.primary.BeginBatch(ctx)
	if err != nil {
		return nil, err
	}
	secondary, err := s.secondary.BeginBatch(ctx)
	if err != nil {
		return nil, err
	}
	return &batch{primary, secondary}, nil
}

func (s *trackerStore) Snapshot(fn trackerdb.SnapshotFn) (err error) {
	return s.SnapshotContext(context.Background(), fn)
}

func (s *trackerStore) SnapshotContext(ctx context.Context, fn trackerdb.SnapshotFn) (err error) {
	handle, err := s.BeginSnapshot(ctx)
	defer handle.Close()
	if err != nil {
		return err
	}
	err = fn(ctx, handle)
	if err != nil {
		return err
	}
	return nil
}

func (s *trackerStore) BeginSnapshot(ctx context.Context) (trackerdb.Snapshot, error) {
	primary, err := s.primary.BeginSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	secondary, err := s.secondary.BeginSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return &snapshot{primary, secondary}, nil
}

func (s *trackerStore) Transaction(fn trackerdb.TransactionFn) (err error) {
	return s.TransactionContext(context.Background(), fn)
}

func (s *trackerStore) TransactionContext(ctx context.Context, fn trackerdb.TransactionFn) error {
	handle, err := s.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	err = fn(ctx, handle)
	if err != nil {
		handle.Close()
		return err
	}
	return handle.Commit()
}

func (s *trackerStore) BeginTransaction(ctx context.Context) (trackerdb.Transaction, error) {
	primary, err := s.primary.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	secondary, err := s.secondary.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	return &transaction{primary, secondary}, nil
}

func (s *trackerStore) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	primary, errP := s.primary.MakeAccountsWriter()
	secondary, errS := s.secondary.MakeAccountsWriter()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsWriterExt{primary, secondary}, nil
}

func (s *trackerStore) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	primary, errP := s.primary.MakeAccountsReader()
	secondary, errS := s.secondary.MakeAccountsReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsReaderExt{primary, secondary}, nil
}

func (s *trackerStore) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	primary, errP := s.primary.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	secondary, errS := s.secondary.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsWriter{primary, secondary}, nil
}

func (s *trackerStore) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	primary, errP := s.primary.MakeAccountsOptimizedReader()
	secondary, errS := s.secondary.MakeAccountsOptimizedReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsReader{primary, secondary}, nil
}

func (s *trackerStore) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (trackerdb.OnlineAccountsWriter, error) {
	primary, errP := s.primary.MakeOnlineAccountsOptimizedWriter(hasAccounts)
	secondary, errS := s.secondary.MakeOnlineAccountsOptimizedWriter(hasAccounts)
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &onlineAccountsWriter{primary, secondary}, nil
}

func (s *trackerStore) MakeOnlineAccountsOptimizedReader() (trackerdb.OnlineAccountsReader, error) {
	primary, errP := s.primary.MakeOnlineAccountsOptimizedReader()
	secondary, errS := s.secondary.MakeOnlineAccountsOptimizedReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &onlineAccountsReader{primary, secondary}, nil
}

func (s *trackerStore) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
	// TODO
	return nil, nil
}

func (s *trackerStore) Vacuum(ctx context.Context) (stats db.VacuumStats, err error) {
	// ignore the stats
	// Note: this is a SQL specific operation, so the are unlikely to match
	stats, errP := s.primary.Vacuum(ctx)
	_, errS := s.secondary.Vacuum(ctx)
	err = coalesceErrors(errP, errS)
	return
}

func (s *trackerStore) CleanupTest(dbName string, inMemory bool) {
	s.primary.CleanupTest(dbName, inMemory)
	s.secondary.CleanupTest(dbName, inMemory)
}

func (s *trackerStore) ResetToV6Test(ctx context.Context) error {
	// TODO
	return nil
}

func (s *trackerStore) Close() {
	s.primary.Close()
	s.secondary.Close()
}

type batch struct {
	primary   trackerdb.Batch
	secondary trackerdb.Batch
}

// MakeAccountsOptimizedWriter implements trackerdb.Batch
func (b *batch) MakeAccountsOptimizedWriter(hasAccounts bool, hasResources bool, hasKvPairs bool, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	primary, errP := b.primary.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	secondary, errS := b.secondary.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsWriter{primary, secondary}, nil
}

// MakeAccountsWriter implements trackerdb.Batch
func (b *batch) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	primary, errP := b.primary.MakeAccountsWriter()
	secondary, errS := b.secondary.MakeAccountsWriter()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsWriterExt{primary, secondary}, nil
}

// MakeCatchpointWriter implements trackerdb.Batch
func (b *batch) MakeCatchpointWriter() (trackerdb.CatchpointWriter, error) {
	// TODO:
	return nil, nil
}

// MakeSpVerificationCtxWriter implements trackerdb.Batch
func (b *batch) MakeSpVerificationCtxWriter() trackerdb.SpVerificationCtxWriter {
	// TODO:
	return nil
}

// ResetTransactionWarnDeadline implements trackerdb.Batch
func (b *batch) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	b.primary.ResetTransactionWarnDeadline(ctx, deadline)
	b.secondary.ResetTransactionWarnDeadline(ctx, deadline)
	// ignore results, this is very engine specific
	return
}

// Testing implements trackerdb.Batch
func (b *batch) Testing() trackerdb.TestBatchScope {
	// TODO:
	return nil
}

// Close implements trackerdb.Batch
func (b *batch) Close() error {
	b.primary.Close()
	b.secondary.Close()
	// errors are unlikely to match between engines
	return nil
}

// Commit implements trackerdb.Batch
func (b *batch) Commit() error {
	b.primary.Commit()
	b.secondary.Commit()
	// errors are unlikely to match between engines
	return nil
}

type transaction struct {
	primary   trackerdb.Transaction
	secondary trackerdb.Transaction
}

// MakeAccountsOptimizedReader implements trackerdb.Transaction
func (tx *transaction) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	primary, errP := tx.primary.MakeAccountsOptimizedReader()
	secondary, errS := tx.secondary.MakeAccountsOptimizedReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsReader{primary, secondary}, nil
}

// MakeAccountsOptimizedWriter implements trackerdb.Transaction
func (tx *transaction) MakeAccountsOptimizedWriter(hasAccounts bool, hasResources bool, hasKvPairs bool, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	primary, errP := tx.primary.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	secondary, errS := tx.secondary.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsWriter{primary, secondary}, nil
}

type accountsReaderWriter struct {
	accountsReaderExt
	accountsWriterExt
}

// MakeAccountsReaderWriter implements trackerdb.Transaction
func (tx *transaction) MakeAccountsReaderWriter() (trackerdb.AccountsReaderWriter, error) {
	primary, errP := tx.primary.MakeAccountsReaderWriter()
	secondary, errS := tx.secondary.MakeAccountsReaderWriter()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsReaderWriter{accountsReaderExt{primary, secondary}, accountsWriterExt{primary, secondary}}, nil
}

// MakeCatchpointReaderWriter implements trackerdb.Transaction
func (tx *transaction) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
	// TODO: implement
	return nil, nil
}

// MakeEncodedAccoutsBatchIter implements trackerdb.Transaction
func (tx *transaction) MakeEncodedAccoutsBatchIter() trackerdb.EncodedAccountsBatchIter {
	// TODO: implement
	return nil
}

// MakeKVsIter implements trackerdb.Transaction
func (tx *transaction) MakeKVsIter(ctx context.Context) (trackerdb.KVsIter, error) {
	// TODO: implement
	return nil, nil
}

// MakeMerkleCommitter implements trackerdb.Transaction
func (tx *transaction) MakeMerkleCommitter(staging bool) (trackerdb.MerkleCommitter, error) {
	// TODO: implement
	return nil, nil
}

// MakeOnlineAccountsOptimizedWriter implements trackerdb.Transaction
func (tx *transaction) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (trackerdb.OnlineAccountsWriter, error) {
	primary, errP := tx.primary.MakeOnlineAccountsOptimizedWriter(hasAccounts)
	secondary, errS := tx.secondary.MakeOnlineAccountsOptimizedWriter(hasAccounts)
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &onlineAccountsWriter{primary, secondary}, nil
}

// MakeOrderedAccountsIter implements trackerdb.Transaction
func (tx *transaction) MakeOrderedAccountsIter(accountCount int) trackerdb.OrderedAccountsIter {
	// TODO: implement
	return nil
}

// MakeSpVerificationCtxReaderWriter implements trackerdb.Transaction
func (tx *transaction) MakeSpVerificationCtxReaderWriter() trackerdb.SpVerificationCtxReaderWriter {
	// TODO: implement
	return nil
}

// ResetTransactionWarnDeadline implements trackerdb.Transaction
func (tx *transaction) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	tx.primary.ResetTransactionWarnDeadline(ctx, deadline)
	tx.secondary.ResetTransactionWarnDeadline(ctx, deadline)
	// ignore results, this is very engine specific
	return
}

// RunMigrations implements trackerdb.Transaction
func (tx *transaction) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	paramsP, errP := tx.primary.RunMigrations(ctx, params, log, targetVersion)
	paramsS, errS := tx.secondary.RunMigrations(ctx, params, log, targetVersion)
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results
	if paramsP != paramsS {
		err = ErrInconsistentResult
		return
	}
	// return primary result
	return paramsP, nil
}

// Testing implements trackerdb.Transaction
func (tx *transaction) Testing() trackerdb.TestTransactionScope {
	// TODO: implement
	return nil
}

// Close implements trackerdb.Transaction
func (tx *transaction) Close() error {
	tx.primary.Close()
	tx.secondary.Close()
	// errors are unlikely to match between engines
	return nil
}

// Commit implements trackerdb.Transaction
func (tx *transaction) Commit() error {
	tx.primary.Commit()
	tx.secondary.Commit()
	// errors are unlikely to match between engines
	return nil
}

type snapshot struct {
	primary   trackerdb.Snapshot
	secondary trackerdb.Snapshot
}

// MakeAccountsReader implements trackerdb.Snapshot
func (s *snapshot) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	primary, errP := s.primary.MakeAccountsReader()
	secondary, errS := s.secondary.MakeAccountsReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsReaderExt{primary, secondary}, nil
}

// MakeCatchpointPendingHashesIterator implements trackerdb.Snapshot
func (s *snapshot) MakeCatchpointPendingHashesIterator(hashCount int) trackerdb.CatchpointPendingHashesIter {
	// TODO: implement
	return nil
}

// MakeCatchpointReader implements trackerdb.Snapshot
func (s *snapshot) MakeCatchpointReader() (trackerdb.CatchpointReader, error) {
	// TODO: implement
	return nil, nil
}

// MakeSpVerificationCtxReader implements trackerdb.Snapshot
func (s *snapshot) MakeSpVerificationCtxReader() trackerdb.SpVerificationCtxReader {
	// TODO: implement
	return nil
}

// Close implements trackerdb.Snapshot
func (s *snapshot) Close() error {
	s.primary.Close()
	s.secondary.Close()
	// errors are unlikely to match between engines
	return nil
}

//
// refs
//

type accountRef struct {
	primary   trackerdb.AccountRef
	secondary trackerdb.AccountRef
}

// AccountRefMarker implements trackerdb.AccountRef
func (accountRef) AccountRefMarker() {}

func coalesceAccountRefs(primary, secondary trackerdb.AccountRef) (trackerdb.AccountRef, error) {
	if primary != nil && secondary != nil {
		return accountRef{primary, secondary}, nil
	} else if primary == nil && secondary == nil {
		// all good, ref is nil
		return nil, nil
	} else {
		// ref mismatch
		return nil, ErrInconsistentResult
	}
}

type onlineAccountRef struct {
	primary   trackerdb.OnlineAccountRef
	secondary trackerdb.OnlineAccountRef
}

// OnlineAccountRefMarker implements trackerdb.OnlineAccountRef
func (onlineAccountRef) OnlineAccountRefMarker() {}

func coalesceOnlineAccountRefs(primary, secondary trackerdb.OnlineAccountRef) (trackerdb.OnlineAccountRef, error) {
	if primary != nil && secondary != nil {
		return onlineAccountRef{primary, secondary}, nil
	} else if primary == nil && secondary == nil {
		// all good, ref is nil
		return nil, nil
	} else {
		// ref mismatch
		return nil, ErrInconsistentResult
	}
}

type resourceRef struct {
	primary   trackerdb.ResourceRef
	secondary trackerdb.ResourceRef
}

// ResourceRefMarker implements trackerdb.ResourceRef
func (resourceRef) ResourceRefMarker() {}

type creatableRef struct {
	primary   trackerdb.CreatableRef
	secondary trackerdb.CreatableRef
}

// CreatableRefMarker implements trackerdb.CreatableRef
func (creatableRef) CreatableRefMarker() {}

//
// helpers
//

func coalesceErrors(errP error, errS error) error {
	// TODO: we need to log that one side errored and the other didn't
	if errP == nil && errS != nil {
		logging.Base().Error("secondary engine error", errS)
		return errS
	}
	if errP != nil && errS == nil {
		logging.Base().Error("primary engine error", errP)
		// TODO: log that the primary didn't error
		return errP
	}
	// happy case (no errors)
	if errP == nil && errS == nil {
		return nil
	}
	// happy case (both errored)
	return errP
}
