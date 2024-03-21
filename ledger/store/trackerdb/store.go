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

package trackerdb

import (
	"context"
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
)

// Store is the interface for the tracker db.
type Store interface {
	ReaderWriter
	// settings
	SetSynchronousMode(ctx context.Context, mode db.SynchronousMode, fullfsync bool) (err error)
	IsSharedCacheConnection() bool
	// batch support
	Batch(fn BatchFn) (err error)
	BatchContext(ctx context.Context, fn BatchFn) (err error)
	BeginBatch(ctx context.Context) (Batch, error)
	// snapshot support
	Snapshot(fn SnapshotFn) (err error)
	SnapshotContext(ctx context.Context, fn SnapshotFn) (err error)
	BeginSnapshot(ctx context.Context) (Snapshot, error)
	// transaction support
	Transaction(fn TransactionFn) (err error)
	TransactionContext(ctx context.Context, fn TransactionFn) (err error)
	BeginTransaction(ctx context.Context) (Transaction, error)
	// maintenance
	Vacuum(ctx context.Context) (stats db.VacuumStats, err error)
	// testing
	ResetToV6Test(ctx context.Context) error
	// cleanup
	Close()
}

// Reader is the interface for the trackerdb read operations.
type Reader interface {
	MakeAccountsReader() (AccountsReaderExt, error)
	MakeAccountsOptimizedReader() (AccountsReader, error)
	MakeOnlineAccountsOptimizedReader() (OnlineAccountsReader, error)
	MakeSpVerificationCtxReader() SpVerificationCtxReader
	// catchpoint
	// Note: BuildMerkleTrie() needs this on the reader handle in sqlite to not get locked by write txns
	MakeCatchpointPendingHashesIterator(hashCount int) CatchpointPendingHashesIter
	// Note: Catchpoint tracker needs this on the reader handle in sqlite to not get locked by write txns
	MakeCatchpointReader() (CatchpointReader, error)
	MakeEncodedAccoutsBatchIter() EncodedAccountsBatchIter
	MakeKVsIter(ctx context.Context) (KVsIter, error)
}

// Writer is the interface for the trackerdb write operations.
type Writer interface {
	// trackerdb
	MakeAccountsWriter() (AccountsWriterExt, error)
	MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (AccountsWriter, error)
	MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (OnlineAccountsWriter, error)
	MakeSpVerificationCtxWriter() SpVerificationCtxWriter
	// testing
	Testing() WriterTestExt
}

// Catchpoint is currently holding most of the methods related to catchpoint.
//
// TODO: we still need to do a refactoring pass on catchpoint
//
//	there are two distinct set of methods present:
//	- read/write ops for managing catchpoint data
//	- read/write ops on trackerdb to support building catchpoints
//	we should split these two sets of methods into two separate interfaces
type Catchpoint interface {
	// reader
	MakeOrderedAccountsIter(accountCount int) OrderedAccountsIter
	// writer
	MakeCatchpointWriter() (CatchpointWriter, error)
	// reader/writer
	MakeCatchpointReaderWriter() (CatchpointReaderWriter, error)
	MakeMerkleCommitter(staging bool) (MerkleCommitter, error)
}

// ReaderWriter is the interface for the trackerdb read/write operations.
//
// Some of the operatiosn available here might not be present in neither the Reader nor the Writer interfaces.
// This is because some operations might require to be able to read and write at the same time.
type ReaderWriter interface {
	Reader
	Writer
	// init
	RunMigrations(ctx context.Context, params Params, log logging.Logger, targetVersion int32) (mgr InitParams, err error)
	// Note: at the moment, catchpoint methods are only accesible via reader/writer
	Catchpoint
}

// BatchScope is an atomic write-only scope to the store.
type BatchScope interface {
	Writer
	ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error)
}

// Batch is an atomic write-only accecssor to the store.
type Batch interface {
	BatchScope
	Commit() error
	Close() error
}

// SnapshotScope is an atomic read-only scope to the store.
type SnapshotScope interface {
	Reader
	ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error)
}

// Snapshot is an atomic read-only accecssor to the store.
type Snapshot interface {
	SnapshotScope
	Close() error
}

// TransactionScope is an atomic read/write scope to the store.
type TransactionScope interface {
	ReaderWriter
	ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error)
}

// Transaction is an atomic read/write accecssor to the store.
type Transaction interface {
	TransactionScope
	Commit() error
	Close() error
}

// BatchFn is the callback lambda used in `Batch`.
type BatchFn func(ctx context.Context, tx BatchScope) error

// SnapshotFn is the callback lambda used in `Snapshot`.
type SnapshotFn func(ctx context.Context, tx SnapshotScope) error

// TransactionFn is the callback lambda used in `Transaction`.
type TransactionFn func(ctx context.Context, tx TransactionScope) error
