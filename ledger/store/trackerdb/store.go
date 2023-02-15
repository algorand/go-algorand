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

package trackerdb

import (
	"context"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

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

// SnapshotScope is the read scope to the store.
type SnapshotScope interface {
	MakeAccountsReader() (AccountsReaderExt, error)
	MakeCatchpointReader() (CatchpointReader, error)

	MakeCatchpointPendingHashesIterator(hashCount int) CatchpointPendingHashesIterator
}

// TransactionScope is the read/write scope to the store.
type TransactionScope interface {
	MakeCatchpointReaderWriter() (CatchpointReaderWriter, error)
	MakeAccountsReaderWriter() (AccountsReaderWriter, error)
	MakeAccountsOptimizedReader() (AccountsReader, error)
	MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (AccountsWriter, error)
	MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (w OnlineAccountsWriter, err error)
	MakeOnlineAccountsOptimizedReader() (OnlineAccountsReader, error)

	MakeMerkleCommitter(staging bool) (MerkleCommitter, error)

	MakeOrderedAccountsIter(accountCount int) OrderedAccountsIter
	MakeKVsIter(ctx context.Context) (KVsIter, error)
	MakeEncodedAccoutsBatchIter() EncodedAccountsBatchIter

	RunMigrations(ctx context.Context, params TrackerDBParams, log logging.Logger, targetVersion int32) (mgr TrackerDBInitParams, err error)
	ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error)

	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error)
}

type BatchFn func(ctx context.Context, tx BatchScope) error
type SnapshotFn func(ctx context.Context, tx SnapshotScope) error
type TransactionFn func(ctx context.Context, tx TransactionScope) error

// TrackerStore is the interface for the tracker db.
type TrackerStore interface {
	SetLogger(log logging.Logger)
	SetSynchronousMode(ctx context.Context, mode db.SynchronousMode, fullfsync bool) (err error)
	IsSharedCacheConnection() bool

	Batch(fn BatchFn) (err error)
	BatchContext(ctx context.Context, fn BatchFn) (err error)

	Snapshot(fn SnapshotFn) (err error)
	SnapshotContext(ctx context.Context, fn SnapshotFn) (err error)

	Transaction(fn TransactionFn) (err error)
	TransactionContext(ctx context.Context, fn TransactionFn) (err error)

	MakeAccountsReader() (AccountsReader, error)
	MakeOnlineAccountsReader() (OnlineAccountsReader, error)

	MakeCatchpointReaderWriter() (CatchpointReaderWriter, error)

	Vacuum(ctx context.Context) (stats db.VacuumStats, err error)
	Close()
	CleanupTest(dbName string, inMemory bool)

	ResetToV6Test(ctx context.Context) error
}
