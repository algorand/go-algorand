// Copyright (C) 2019-2024 Algorand, Inc.
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
	"fmt"
	"reflect"
	"time"

	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
	"github.com/google/go-cmp/cmp"
)

// ErrInconsistentResult is returned when the two stores return different results.
var ErrInconsistentResult = errors.New("inconsistent results between store engines")

var allowAllUnexported = cmp.Exporter(func(f reflect.Type) bool { return true })

type trackerStore struct {
	primary   trackerdb.Store
	secondary trackerdb.Store
	trackerdb.Reader
	trackerdb.Writer
	trackerdb.Catchpoint
}

// MakeStore creates a dual tracker store that verifies that both stores return the same results.
func MakeStore(primary trackerdb.Store, secondary trackerdb.Store) trackerdb.Store {
	return &trackerStore{primary, secondary, &reader{primary, secondary}, &writer{primary, secondary}, &catchpoint{primary, secondary}}
}

func (s *trackerStore) SetSynchronousMode(ctx context.Context, mode db.SynchronousMode, fullfsync bool) (err error) {
	errP := s.primary.SetSynchronousMode(ctx, mode, fullfsync)
	errS := s.secondary.SetSynchronousMode(ctx, mode, fullfsync)
	return coalesceErrors(errP, errS)
}

func (s *trackerStore) IsSharedCacheConnection() bool {
	// Note: this is not something to check for being equal but rather keep the most conservative answer.
	return s.primary.IsSharedCacheConnection() || s.secondary.IsSharedCacheConnection()
}

func (s *trackerStore) Batch(fn trackerdb.BatchFn) (err error) {
	return s.BatchContext(context.Background(), fn)
}

func (s *trackerStore) BatchContext(ctx context.Context, fn trackerdb.BatchFn) (err error) {
	handle, err := s.BeginBatch(ctx)
	if err != nil {
		return err
	}
	defer handle.Close()

	err = fn(ctx, handle)
	if err != nil {
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
	return &batch{primary, secondary, &writer{primary, secondary}}, nil
}

func (s *trackerStore) Snapshot(fn trackerdb.SnapshotFn) (err error) {
	return s.SnapshotContext(context.Background(), fn)
}

func (s *trackerStore) SnapshotContext(ctx context.Context, fn trackerdb.SnapshotFn) (err error) {
	handle, err := s.BeginSnapshot(ctx)
	if err != nil {
		return err
	}
	defer handle.Close()

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
	return &snapshot{primary, secondary, &reader{primary, secondary}}, nil
}

func (s *trackerStore) Transaction(fn trackerdb.TransactionFn) (err error) {
	return s.TransactionContext(context.Background(), fn)
}

func (s *trackerStore) TransactionContext(ctx context.Context, fn trackerdb.TransactionFn) error {
	handle, err := s.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer handle.Close()

	err = fn(ctx, handle)
	if err != nil {
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
	return &transaction{primary, secondary, &reader{primary, secondary}, &writer{primary, secondary}, &catchpoint{primary, secondary}}, nil
}

// RunMigrations implements trackerdb.Transaction
func (s *trackerStore) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	paramsP, errP := s.primary.RunMigrations(ctx, params, log, targetVersion)
	paramsS, errS := s.secondary.RunMigrations(ctx, params, log, targetVersion)
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

func (s *trackerStore) Vacuum(ctx context.Context) (stats db.VacuumStats, err error) {
	// ignore the stats
	// Note: this is a SQL specific operation, so the are unlikely to match
	stats, errP := s.primary.Vacuum(ctx)
	_, errS := s.secondary.Vacuum(ctx)
	err = coalesceErrors(errP, errS)
	return
}

func (s *trackerStore) ResetToV6Test(ctx context.Context) error {
	// TODO
	return nil
}

func (s *trackerStore) Close() {
	s.primary.Close()
	s.secondary.Close()
}

type reader struct {
	primary   trackerdb.Reader
	secondary trackerdb.Reader
}

// MakeAccountsOptimizedReader implements trackerdb.Reader
func (r *reader) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	primary, errP := r.primary.MakeAccountsOptimizedReader()
	secondary, errS := r.secondary.MakeAccountsOptimizedReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsReader{primary, secondary}, nil
}

// MakeAccountsReader implements trackerdb.Reader
func (r *reader) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	primary, errP := r.primary.MakeAccountsReader()
	secondary, errS := r.secondary.MakeAccountsReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsReaderExt{primary, secondary}, nil
}

// MakeOnlineAccountsOptimizedReader implements trackerdb.Reader
func (r *reader) MakeOnlineAccountsOptimizedReader() (trackerdb.OnlineAccountsReader, error) {
	primary, errP := r.primary.MakeOnlineAccountsOptimizedReader()
	secondary, errS := r.secondary.MakeOnlineAccountsOptimizedReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &onlineAccountsReader{primary, secondary}, nil
}

// MakeSpVerificationCtxReader implements trackerdb.Reader
func (r *reader) MakeSpVerificationCtxReader() trackerdb.SpVerificationCtxReader {
	primary := r.primary.MakeSpVerificationCtxReader()
	secondary := r.secondary.MakeSpVerificationCtxReader()
	return &stateproofReader{primary, secondary}
}

// MakeCatchpointPendingHashesIterator implements trackerdb.Reader
func (*reader) MakeCatchpointPendingHashesIterator(hashCount int) trackerdb.CatchpointPendingHashesIter {
	// TODO: catchpoint
	return nil
}

// MakeCatchpointReader implements trackerdb.Reader
func (*reader) MakeCatchpointReader() (trackerdb.CatchpointReader, error) {
	// TODO: catchpoint
	return nil, nil
}

// MakeEncodedAccoutsBatchIter implements trackerdb.Reader
func (*reader) MakeEncodedAccoutsBatchIter() trackerdb.EncodedAccountsBatchIter {
	// TODO: catchpoint
	return nil
}

// MakeKVsIter implements trackerdb.Reader
func (*reader) MakeKVsIter(ctx context.Context) (trackerdb.KVsIter, error) {
	// TODO: catchpoint
	return nil, nil
}

type writer struct {
	primary   trackerdb.Writer
	secondary trackerdb.Writer
}

// MakeAccountsOptimizedWriter implements trackerdb.Writer
func (w *writer) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	primary, errP := w.primary.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	secondary, errS := w.secondary.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsWriter{primary, secondary}, nil
}

// MakeAccountsWriter implements trackerdb.Writer
func (w *writer) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	primary, errP := w.primary.MakeAccountsWriter()
	secondary, errS := w.secondary.MakeAccountsWriter()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsWriterExt{primary, secondary}, nil
}

// MakeOnlineAccountsOptimizedWriter implements trackerdb.Writer
func (w *writer) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (trackerdb.OnlineAccountsWriter, error) {
	primary, errP := w.primary.MakeOnlineAccountsOptimizedWriter(hasAccounts)
	secondary, errS := w.secondary.MakeOnlineAccountsOptimizedWriter(hasAccounts)
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &onlineAccountsWriter{primary, secondary}, nil
}

// MakeSpVerificationCtxWriter implements trackerdb.Writer
func (w *writer) MakeSpVerificationCtxWriter() trackerdb.SpVerificationCtxWriter {
	primary := w.primary.MakeSpVerificationCtxWriter()
	secondary := w.secondary.MakeSpVerificationCtxWriter()
	return &stateproofWriter{primary, secondary}
}

// Testing implements trackerdb.Writer
func (w *writer) Testing() trackerdb.WriterTestExt {
	primary := w.primary.Testing()
	secondary := w.secondary.Testing()
	return &writerForTesting{primary, secondary}
}

type catchpoint struct {
	primary   trackerdb.Catchpoint
	secondary trackerdb.Catchpoint
}

// MakeCatchpointReaderWriter implements trackerdb.Catchpoint
func (*catchpoint) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
	// TODO: catchpoint
	return nil, nil
}

// MakeCatchpointWriter implements trackerdb.Catchpoint
func (*catchpoint) MakeCatchpointWriter() (trackerdb.CatchpointWriter, error) {
	// TODO: catchpoint
	return nil, nil
}

// MakeMerkleCommitter implements trackerdb.Catchpoint
func (*catchpoint) MakeMerkleCommitter(staging bool) (trackerdb.MerkleCommitter, error) {
	// TODO: catchpoint
	return nil, nil
}

// MakeOrderedAccountsIter implements trackerdb.Catchpoint
func (*catchpoint) MakeOrderedAccountsIter(accountCount int) trackerdb.OrderedAccountsIter {
	// TODO: catchpoint
	return nil
}

type batch struct {
	primary   trackerdb.Batch
	secondary trackerdb.Batch
	trackerdb.Writer
}

// ResetTransactionWarnDeadline implements trackerdb.Batch
func (b *batch) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	_, _ = b.primary.ResetTransactionWarnDeadline(ctx, deadline)
	_, _ = b.secondary.ResetTransactionWarnDeadline(ctx, deadline)
	// ignore results, this is very engine specific
	return
}

// Commit implements trackerdb.Batch
func (b *batch) Commit() error {
	errP := b.primary.Commit()
	errS := b.secondary.Commit()
	// errors are unlikely to match between engines
	return coalesceErrors(errP, errS)
}

// Close implements trackerdb.Batch
func (b *batch) Close() error {
	errP := b.primary.Close()
	errS := b.secondary.Close()
	// errors are unlikely to match between engines
	return coalesceErrors(errP, errS)
}

type transaction struct {
	primary   trackerdb.Transaction
	secondary trackerdb.Transaction
	trackerdb.Reader
	trackerdb.Writer
	trackerdb.Catchpoint
}

// ResetTransactionWarnDeadline implements trackerdb.Transaction
func (tx *transaction) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	_, _ = tx.primary.ResetTransactionWarnDeadline(ctx, deadline)
	_, _ = tx.secondary.ResetTransactionWarnDeadline(ctx, deadline)
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

// Commit implements trackerdb.Transaction
func (tx *transaction) Commit() error {
	errP := tx.primary.Commit()
	errS := tx.secondary.Commit()
	// errors are unlikely to match between engines
	return coalesceErrors(errP, errS)
}

// Close implements trackerdb.Transaction
func (tx *transaction) Close() error {
	errP := tx.primary.Close()
	errS := tx.secondary.Close()
	// errors are unlikely to match between engines
	return coalesceErrors(errP, errS)
}

type snapshot struct {
	primary   trackerdb.Snapshot
	secondary trackerdb.Snapshot
	trackerdb.Reader
}

// ResetTransactionWarnDeadline implements trackerdb.Snapshot
func (s *snapshot) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	_, _ = s.primary.ResetTransactionWarnDeadline(ctx, deadline)
	_, _ = s.secondary.ResetTransactionWarnDeadline(ctx, deadline)
	// ignore results, this is very engine specific
	return
}

// Close implements trackerdb.Snapshot
func (s *snapshot) Close() error {
	errP := s.primary.Close()
	errS := s.secondary.Close()
	// errors are unlikely to match between engines
	return coalesceErrors(errP, errS)
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
func (ref accountRef) String() string {
	return fmt.Sprintf("accountRef{primary: %s, secondary: %s}", ref.primary.String(), ref.secondary.String())
}

func coalesceAccountRefs(primary, secondary trackerdb.AccountRef) (trackerdb.AccountRef, error) {
	if primary != nil && secondary != nil {
		return accountRef{primary, secondary}, nil
	} else if primary == nil && secondary == nil {
		// all good, ref is nil
		return nil, nil
	}
	// ref mismatch
	return nil, ErrInconsistentResult
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
	}
	// ref mismatch
	return nil, ErrInconsistentResult
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
	if errP == nil && errS != nil {
		logging.Base().Error("secondary engine error, ", errS)
		return ErrInconsistentResult
	}
	if errP != nil && errS == nil {
		logging.Base().Error("primary engine error, ", errP)
		return ErrInconsistentResult
	}
	// happy case (no errors)
	if errP == nil && errS == nil {
		return nil
	}
	// happy case (both errored)
	return errP
}
