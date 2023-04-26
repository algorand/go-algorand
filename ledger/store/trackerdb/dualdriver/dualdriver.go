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
	errP := s.primary.BatchContext(ctx, fn)
	errS := s.secondary.BatchContext(ctx, fn)
	return coalesceErrors(errP, errS)
}

func (s *trackerStore) Snapshot(fn trackerdb.SnapshotFn) (err error) {
	return s.SnapshotContext(context.Background(), fn)
}

func (s *trackerStore) SnapshotContext(ctx context.Context, fn trackerdb.SnapshotFn) (err error) {
	errP := s.primary.SnapshotContext(ctx, fn)
	errS := s.secondary.SnapshotContext(ctx, fn)
	return coalesceErrors(errP, errS)
}

func (s *trackerStore) Transaction(fn trackerdb.TransactionFn) (err error) {
	return s.TransactionContext(context.Background(), fn)
}

func (s *trackerStore) TransactionContext(ctx context.Context, fn trackerdb.TransactionFn) (err error) {
	errP := s.primary.TransactionContext(ctx, fn)
	errS := s.secondary.TransactionContext(ctx, fn)
	return coalesceErrors(errP, errS)
}

func (s *trackerStore) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	primaryWriter, errP := s.primary.MakeAccountsWriter()
	secondaryWriter, errS := s.secondary.MakeAccountsWriter()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsWriterExt{primaryWriter, secondaryWriter}, nil
}

func (s *trackerStore) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	primaryReader, errP := s.primary.MakeAccountsReader()
	secondaryReader, errS := s.secondary.MakeAccountsReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsReaderExt{primaryReader, secondaryReader}, nil
}

func (s *trackerStore) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	primaryWriter, errP := s.primary.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	secondaryWriter, errS := s.secondary.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsWriter{primaryWriter, secondaryWriter}, nil
}

func (s *trackerStore) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	primaryReader, errP := s.primary.MakeAccountsOptimizedReader()
	secondaryReader, errS := s.secondary.MakeAccountsOptimizedReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &accountsReader{primaryReader, secondaryReader}, nil
}

func (s *trackerStore) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (trackerdb.OnlineAccountsWriter, error) {
	primaryWriter, errP := s.primary.MakeOnlineAccountsOptimizedWriter(hasAccounts)
	secondaryWriter, errS := s.secondary.MakeOnlineAccountsOptimizedWriter(hasAccounts)
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &onlineAccountsWriter{primaryWriter, secondaryWriter}, nil
}

func (s *trackerStore) MakeOnlineAccountsOptimizedReader() (trackerdb.OnlineAccountsReader, error) {
	primaryReader, errP := s.primary.MakeOnlineAccountsOptimizedReader()
	secondaryReader, errS := s.secondary.MakeOnlineAccountsOptimizedReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &onlineAccountsReader{primaryReader, secondaryReader}, nil
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
