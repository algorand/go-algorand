// Copyright (C) 2019-2025 Algorand, Inc.
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

//go:build !arm

package pebbledbdriver

import (
	"context"
	"io"
	"runtime"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/generickv"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
	"github.com/cockroachdb/pebble/vfs"
)

const (
	// minCache is the minimum amount of memory in megabytes to allocate to pebble
	// read and write caching, split half and half.
	minCache = 16

	// minHandles is the minimum number of files handles to allocate to the open
	// database files.
	minHandles = 16
)

type trackerStore struct {
	kvs   kvstore
	proto config.ConsensusParams
	// use the generickv implementations
	trackerdb.Reader
	trackerdb.Writer
	trackerdb.Catchpoint
}

// Open opens a Pebble db database
func Open(dbdir string, inMem bool, proto config.ConsensusParams, log logging.Logger) (trackerdb.Store, error) {
	cache := 128 // this divided by 2 and by memTableLimit = 1GB /(2 * 16) = 32MB per memtable
	handles := 1000

	// Ensure we have some minimal caching and file guarantees
	if cache < minCache {
		cache = minCache
	}
	if handles < minHandles {
		handles = minHandles
	}

	// The max memtable size is limited by the uint32 offsets stored in
	// internal/arenaskl.node, DeferredBatchOp, and flushableBatchEntry.
	// Taken from https://github.com/cockroachdb/pebble/blob/master/open.go#L38
	maxMemTableSize := 4<<30 - 1 // Capped by 4 GB

	memTableLimit := 2 // default: 2
	memTableSize := min(cache*1024*1024/2/memTableLimit, maxMemTableSize)

	// configure pebbledb
	opts := &pebble.Options{
		// logging
		Logger: log,

		// Pebble has a single combined cache area and the write
		// buffers are taken from this too. Assign all available
		// memory allowance for cache.
		Cache:        pebble.NewCache(int64(cache * 1024 * 1024)), // default: 8 MB
		MaxOpenFiles: handles,                                     // default: 1000

		// The size of memory table(as well as the write buffer).
		// Note, there may have more than two memory tables in the system.
		MemTableSize: memTableSize, // default: 4MB

		// MemTableStopWritesThreshold places a hard limit on the size
		// of the existent MemTables(including the frozen one).
		// Note, this must be the number of tables not the size of all memtables
		// according to https://github.com/cockroachdb/pebble/blob/master/options.go#L738-L742
		// and to https://github.com/cockroachdb/pebble/blob/master/db.go#L1892-L1903.
		MemTableStopWritesThreshold: memTableLimit, // default: 2

		// Sync sstables periodically in order to smooth out writes to disk. This
		// option does not provide any persistency guarantee, but is used to avoid
		// latency spikes if the OS automatically decides to write out a large chunk
		// of dirty filesystem buffers. This option only controls SSTable syncs; WAL
		// syncs are controlled by WALBytesPerSync.
		BytesPerSync: 512 * 1024, // default: 512 KB

		// WALBytesPerSync sets the number of bytes to write to a WAL before calling
		// Sync on it in the background. Just like with BytesPerSync above, this
		// helps smooth out disk write latencies, and avoids cases where the OS
		// writes a lot of buffered data to disk at once. However, this is less
		// necessary with WALs, as many write operations already pass in
		// Sync = true.
		//
		// The default value is 0, i.e. no background syncing. This matches the
		// default behaviour in RocksDB.
		WALBytesPerSync: 0, // default: 0

		// The default compaction concurrency(1 thread),
		// Here use all available CPUs for faster compaction.
		MaxConcurrentCompactions: func() int { return runtime.NumCPU() }, // default: 1

		// The count of L0 files necessary to trigger an L0 compaction.
		L0CompactionFileThreshold: 500, // default: 500

		// The amount of L0 read-amplification necessary to trigger an L0 compaction
		L0CompactionThreshold: 4, // default: 4

		// Hard limit on L0 read-amplification, computed as the number of L0
		// sublevels. Writes are stopped when this threshold is reached.
		L0StopWritesThreshold: 12, // default: 12

		// The maximum number of bytes for LBase. The base level is the level which
		// L0 is compacted into. The base level is determined dynamically based on
		// the existing data in the LSM. The maximum number of bytes for other levels
		// is computed dynamically based on the base level's maximum size. When the
		// maximum number of bytes for a level is exceeded, compaction is requested.
		LBaseMaxBytes: 64 * 1024 * 1024, // default: 64 MB

		// Per-level options. Options for at least one level must be specified. The
		// options for the last level are used for all subsequent levels.
		Levels: make([]pebble.LevelOptions, 7),
	}

	// Disable seek compaction explicitly. Check https://github.com/ethereum/go-ethereum/pull/20130
	// for more details.
	opts.Experimental.ReadSamplingMultiplier = -1

	// The target file size for the level.
	// WARNING: unclear if this can be changed during the lifetime of the db
	//          if it can be changed, it might make things slower for a time
	opts.Levels[0].TargetFileSize = 2 * 1024 * 1024 // default: 4 MB

	// configure the levels
	for i := 0; i < len(opts.Levels); i++ {
		l := &opts.Levels[i]
		// BlockSize is the target uncompressed size in bytes of each table block.
		// WARNING: unclear if this can be changed during the lifetime of the db
		//          if it can be changed, it might make things slower for a time
		l.BlockSize = 4 * 1024 // default: 4 KB

		// IndexBlockSize is the target uncompressed size in bytes of each index
		// block. When the index block size is larger than this target, two-level
		// indexes are automatically enabled. Setting this option to a large value
		// (such as math.MaxInt32) disables the automatic creation of two-level
		// indexes.
		//
		// The default value is the value of BlockSize.
		// WARNING: unclear if this can be changed during the lifetime of the db
		//          if it can be changed, it might make things slower for a time
		l.IndexBlockSize = l.BlockSize

		// FilterPolicy defines a filter algorithm (such as a Bloom filter) that can
		// reduce disk reads for Get calls.
		//
		// One such implementation is bloom.FilterPolicy(10) from the pebble/bloom
		// package.
		//
		// The default value means to use no filter.
		// WARNING: unclear if this can be changed during the lifetime of the db
		//          if it can be changed, it might make things slower for a time
		l.FilterPolicy = bloom.FilterPolicy(10)

		// FilterType defines whether an existing filter policy is applied at a
		// block-level or table-level. Block-level filters use less memory to create,
		// but are slower to access as a check for the key in the index must first be
		// performed to locate the filter block. A table-level filter will require
		// memory proportional to the number of keys in an sstable to create, but
		// avoids the index lookup when determining if a key is present. Table-level
		// filters should be preferred except under constrained memory situations.
		// WARNING: unclear if this can be changed during the lifetime of the db
		//          if it can be changed, it might make things slower for a time
		l.FilterType = pebble.TableFilter

		// Compression defines the per-block compression to use.
		// WARNING: unclear if this can be changed during the lifetime of the db
		//          if it can be changed, it might make things slower for a time
		l.Compression = pebble.SnappyCompression // default: SnappyCompression

		if i > 0 {
			// The target file size for the level.
			// WARNING: unclear if this can be changed during the lifetime of the db
			//          if it can be changed, it might make things slower for a time
			l.TargetFileSize = opts.Levels[i-1].TargetFileSize
		}
	}

	if inMem {
		opts.FS = vfs.NewMem()
	}
	db, err := pebble.Open(dbdir+".pebbledb", opts)
	if err != nil {
		return nil, err
	}
	// no fsync
	wo := &pebble.WriteOptions{Sync: false}
	kvs := kvstore{Pdb: db, wo: wo}
	var store trackerdb.Store
	store = &trackerStore{
		kvs,
		proto,
		generickv.MakeReader(&kvs, proto),
		generickv.MakeWriter(store, &kvs, &kvs),
		generickv.MakeCatchpoint(),
	}
	return store, nil
}

// IsSharedCacheConnection implements trackerdb.Store
func (s *trackerStore) IsSharedCacheConnection() bool {
	return false
}

// SetSynchronousMode implements trackerdb.Store
func (s *trackerStore) SetSynchronousMode(ctx context.Context, mode db.SynchronousMode, fullfsync bool) (err error) {
	// TODO
	return nil
}

// RunMigrations implements trackerdb.Store
func (s *trackerStore) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	// create a anonym struct that impls the interface for the migration runner
	db := struct {
		*trackerStore
		*kvstore
	}{s, &s.kvs}
	return generickv.RunMigrations(ctx, db, params, targetVersion)
}

// Batch implements trackerdb.Store
func (s *trackerStore) Batch(fn trackerdb.BatchFn) (err error) {
	return s.BatchContext(context.Background(), fn)
}

// BatchContext implements trackerdb.Store
func (s *trackerStore) BatchContext(ctx context.Context, fn trackerdb.BatchFn) (err error) {
	handle, err := s.BeginBatch(ctx)
	if err != nil {
		return
	}
	defer handle.Close()

	// run the batch
	err = fn(ctx, handle)
	if err != nil {
		return
	}

	// commit the batch
	err = handle.Commit()
	if err != nil {
		return
	}

	return err
}

// BeginBatch implements trackerdb.Store
func (s *trackerStore) BeginBatch(ctx context.Context) (trackerdb.Batch, error) {
	scope := batchScope{store: s, wb: s.kvs.Pdb.NewBatch(), wo: s.kvs.wo, db: s.kvs.Pdb}

	return &struct {
		batchScope
		trackerdb.Writer
	}{scope, generickv.MakeWriter(s, &scope, &s.kvs)}, nil
}

// Snapshot implements trackerdb.Store
func (s *trackerStore) Snapshot(fn trackerdb.SnapshotFn) (err error) {
	return s.SnapshotContext(context.Background(), fn)
}

// SnapshotContext implements trackerdb.Store
func (s *trackerStore) SnapshotContext(ctx context.Context, fn trackerdb.SnapshotFn) (err error) {
	handle, err := s.BeginSnapshot(ctx)
	if err != nil {
		return
	}
	defer handle.Close()

	// run the snapshot
	err = fn(ctx, handle)
	if err != nil {
		return
	}

	return err
}

// BeginSnapshot implements trackerdb.Store
func (s *trackerStore) BeginSnapshot(ctx context.Context) (trackerdb.Snapshot, error) {
	scope := snapshotScope{db: s.kvs.Pdb, snap: s.kvs.Pdb.NewSnapshot()}
	return &struct {
		snapshotScope
		trackerdb.Reader
	}{scope, generickv.MakeReader(&scope, s.proto)}, nil
}

// Transaction implements trackerdb.Store
func (s *trackerStore) Transaction(fn trackerdb.TransactionFn) (err error) {
	return s.TransactionContext(context.Background(), fn)
}

// TransactionWithRetryClearFn implements trackerdb.Store
func (s *trackerStore) TransactionWithRetryClearFn(fn trackerdb.TransactionFn, rollbackFn trackerdb.RetryClearFn) (err error) {
	return s.TransactionContextWithRetryClearFn(context.Background(), fn, rollbackFn)
}

// TransactionContext implements trackerdb.Store
func (s *trackerStore) TransactionContext(ctx context.Context, fn trackerdb.TransactionFn) (err error) {
	handle, err := s.BeginTransaction(ctx)
	if err != nil {
		return
	}
	defer handle.Close()

	// run the transaction
	err = fn(ctx, handle)
	if err != nil {
		return
	}

	// commit the transaction
	err = handle.Commit()
	if err != nil {
		return
	}

	return err
}

// TransactionContextWithRetryClearFn implements trackerdb.Store.
// It ignores the RetryClearFn, since it does not need to retry
// transactions to work around SQLite issues like the sqlitedriver.
func (s *trackerStore) TransactionContextWithRetryClearFn(ctx context.Context, fn trackerdb.TransactionFn, _ trackerdb.RetryClearFn) error {
	return s.TransactionContext(ctx, fn)
}

// BeginTransaction implements trackerdb.Store
func (s *trackerStore) BeginTransaction(ctx context.Context) (trackerdb.Transaction, error) {
	scope := transactionScope{
		store: s,
		db:    s.kvs.Pdb,
		wo:    s.kvs.wo,
		snap:  s.kvs.Pdb.NewSnapshot(),
		wb:    s.kvs.Pdb.NewBatch(),
	}

	return &struct {
		transactionScope
		trackerdb.Reader
		trackerdb.Writer
		trackerdb.Catchpoint
	}{scope, generickv.MakeReader(&scope, s.proto), generickv.MakeWriter(s, &scope, &scope), generickv.MakeCatchpoint()}, nil
}

// Vacuum implements trackerdb.Store
func (s *trackerStore) Vacuum(ctx context.Context) (stats db.VacuumStats, err error) {
	// TODO
	return db.VacuumStats{}, nil
}

// ResetToV6Test implements trackerdb.Store
func (s *trackerStore) ResetToV6Test(ctx context.Context) error {
	// TODO
	return nil
}

// Close implements trackerdb.Store
func (s *trackerStore) Close() {
	s.kvs.Pdb.Close()
}

//
// generic impls
//

func mapPebbleErrors(err error) error {
	switch err {
	case pebble.ErrNotFound:
		return trackerdb.ErrNotFound
	default:
		return err
	}
}

type kvstore struct {
	Pdb *pebble.DB
	wo  *pebble.WriteOptions
}

func (s *kvstore) Set(key, value []byte) error {
	return s.Pdb.Set(key, value, s.wo)
}

func (s *kvstore) Get(key []byte) (value []byte, closer io.Closer, err error) {
	value, closer, err = s.Pdb.Get(key)
	err = mapPebbleErrors(err)
	return
}

func (s *kvstore) NewIter(low, high []byte, reverse bool) generickv.KvIter {
	opts := pebble.IterOptions{LowerBound: low, UpperBound: high}
	return newIter(s.Pdb.NewIter(&opts), reverse)
}

func (s *kvstore) Delete(key []byte) error {
	return s.Pdb.Delete(key, s.wo)
}

func (s *kvstore) DeleteRange(start, end []byte) error {
	return s.Pdb.DeleteRange(start, end, s.wo)
}

type batchScope struct {
	// Hack: we should tray to impl without this field
	store *trackerStore
	db    *pebble.DB
	wo    *pebble.WriteOptions
	wb    *pebble.Batch
}

func (bs batchScope) Set(key, value []byte) error {
	return bs.wb.Set(key, value, bs.wo)
}

func (bs batchScope) Delete(key []byte) error {
	return bs.wb.Delete(key, bs.wo)
}

func (bs batchScope) DeleteRange(start, end []byte) error {
	return bs.wb.DeleteRange(start, end, bs.wo)
}

func (bs batchScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	// noop
	return time.Now(), nil
}

func (bs batchScope) Commit() error {
	return bs.wb.Commit(bs.wo)
}

func (bs batchScope) Close() error {
	return bs.wb.Close()
}

type snapshotScope struct {
	db   *pebble.DB
	snap *pebble.Snapshot
}

func (ss snapshotScope) Get(key []byte) (value []byte, closer io.Closer, err error) {
	value, closer, err = ss.snap.Get(key)
	err = mapPebbleErrors(err)
	return
}

func (ss snapshotScope) NewIter(low, high []byte, reverse bool) generickv.KvIter {
	opts := pebble.IterOptions{LowerBound: low, UpperBound: high}
	return newIter(ss.snap.NewIter(&opts), reverse)
}

func (ss snapshotScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	// noop
	return time.Now(), nil
}

func (ss snapshotScope) Close() error {
	return ss.snap.Close()
}

type transactionScope struct {
	// Hack: we should tray to impl without this field
	store *trackerStore
	db    *pebble.DB
	wo    *pebble.WriteOptions
	snap  *pebble.Snapshot
	wb    *pebble.Batch
}

func (txs transactionScope) Set(key, value []byte) error {
	return txs.wb.Set(key, value, txs.wo)
}

func (txs transactionScope) Get(key []byte) (value []byte, closer io.Closer, err error) {
	value, closer, err = txs.snap.Get(key)
	err = mapPebbleErrors(err)
	return
}

func (txs transactionScope) NewIter(low, high []byte, reverse bool) generickv.KvIter {
	opts := pebble.IterOptions{LowerBound: low, UpperBound: high}
	return newIter(txs.snap.NewIter(&opts), reverse)
}

func (txs transactionScope) Delete(key []byte) error {
	return txs.wb.Delete(key, txs.wo)
}

func (txs transactionScope) DeleteRange(start, end []byte) error {
	return txs.wb.DeleteRange(start, end, txs.wo)
}

func (txs *transactionScope) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	// create a anonym struct that impls the interface for the migration runner
	db := struct {
		*trackerStore
		*kvstore
	}{txs.store, &txs.store.kvs}
	return generickv.RunMigrations(ctx, db, params, targetVersion)
}

func (txs transactionScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	// noop
	return time.Now(), nil
}

func (txs transactionScope) Commit() error {
	return txs.wb.Commit(txs.wo)
}

func (txs transactionScope) Close() error {
	txs.snap.Close() // ignore error
	return txs.wb.Close()
}

type pebbleIter struct {
	iter      *pebble.Iterator
	reverse   bool
	firstCall bool
}

func newIter(iter *pebble.Iterator, reverse bool) *pebbleIter {
	return &pebbleIter{iter, reverse, true}
}

func (i *pebbleIter) Next() bool {
	if i.firstCall {
		i.firstCall = false
		if i.reverse {
			return i.iter.Last()
		}
		return i.iter.First()
	}
	if i.reverse {
		return i.iter.Prev()
	}
	return i.iter.Next()
}
func (i *pebbleIter) Valid() bool { return i.iter.Valid() }
func (i *pebbleIter) Close()      { i.iter.Close() }

func (i *pebbleIter) Key() []byte {
	k := i.iter.Key()
	ret := make([]byte, len(k))
	copy(ret, k)
	return ret
}

func (i *pebbleIter) Value() ([]byte, error) {
	v := i.iter.Value()
	ret := make([]byte, len(v))
	copy(ret, v)
	return ret, nil
}

// KeySlice is a zero copy slice only valid until iter.Next() or iter.Close() is called.
func (i *pebbleIter) KeySlice() generickv.Slice { return pebbleSlice(i.iter.Key()) }

// ValueSlice is a zero copy slice only valid until iter.Next() or iter.Close() is called.
func (i *pebbleIter) ValueSlice() (generickv.Slice, error) { return pebbleSlice(i.iter.Value()), nil }

type pebbleSlice []byte

func (s pebbleSlice) Data() []byte { return s }
func (s pebbleSlice) Free()        {}
func (s pebbleSlice) Size() int    { return len(s) }
func (s pebbleSlice) Exists() bool { return s != nil }
