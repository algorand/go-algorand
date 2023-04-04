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

package pebbledbdriver

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/generickv"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
	"github.com/cockroachdb/pebble/vfs"
)

type trackerStore struct {
	Pdb   *pebble.DB
	wo    *pebble.WriteOptions
	proto config.ConsensusParams
}

type batchScope struct {
	// Hack: we should tray to impl without this field
	store *trackerStore
	db    *pebble.DB
	wo    *pebble.WriteOptions
	wb    *pebble.Batch
}

type snapshotScope struct {
	db    *pebble.DB
	snap  *pebble.Snapshot
	proto config.ConsensusParams
}

type transactionScope struct {
	// Hack: we should tray to impl without this field
	store *trackerStore
	db    *pebble.DB
	wo    *pebble.WriteOptions
	snap  *pebble.Snapshot
	wb    *pebble.Batch
	proto config.ConsensusParams
}

// OpenTrackerDB opens a Pebble db database
func OpenTrackerDB(dbdir string, inMem bool, proto config.ConsensusParams) (store *trackerStore, err error) {
	cache := pebble.NewCache(4 * 1024 * 1024)
	defer cache.Unref()
	// based on cockroach DB's DefaultPebbleOptions()
	opts := &pebble.Options{
		Cache:                       cache,
		L0CompactionThreshold:       2,
		L0StopWritesThreshold:       1000,
		LBaseMaxBytes:               64 << 20, // 64 MB
		Levels:                      make([]pebble.LevelOptions, 7),
		MaxConcurrentCompactions:    func() int { return 3 },
		MemTableSize:                64 << 20, // 64 MB
		MemTableStopWritesThreshold: 4,
	}
	opts.FlushDelayDeleteRange = 10 * time.Second
	opts.Experimental.MinDeletionRate = 128 << 20 // 128 MB
	opts.Experimental.ReadSamplingMultiplier = -1
	for i := 0; i < len(opts.Levels); i++ {
		l := &opts.Levels[i]
		l.BlockSize = 32 << 10       // 32 KB
		l.IndexBlockSize = 256 << 10 // 256 KB
		l.FilterPolicy = bloom.FilterPolicy(10)
		l.FilterType = pebble.TableFilter
		if i > 0 {
			l.TargetFileSize = opts.Levels[i-1].TargetFileSize * 2
		}
		l.EnsureDefaults()
	}
	opts.Levels[6].FilterPolicy = nil
	if inMem {
		opts.FS = vfs.NewMem()
	}
	db, err := pebble.Open(dbdir+".pebbledb", opts)
	if err != nil {
		return nil, err
	}
	wo := &pebble.WriteOptions{Sync: true}
	return &trackerStore{Pdb: db, wo: wo, proto: proto}, nil
}

func (s *trackerStore) SetLogger(log logging.Logger) {
	// TODO
}

func (s *trackerStore) SetSynchronousMode(ctx context.Context, mode db.SynchronousMode, fullfsync bool) (err error) {
	// TODO
	return nil
}

func (s *trackerStore) IsSharedCacheConnection() bool {
	// TODO
	return false
}

func (s *trackerStore) Batch(fn trackerdb.BatchFn) (err error) {
	return s.BatchContext(context.Background(), fn)
}

func (s *trackerStore) BatchContext(ctx context.Context, fn trackerdb.BatchFn) (err error) {
	scope := batchScope{store: s, wb: s.Pdb.NewBatch(), wo: s.wo, db: s.Pdb}
	defer scope.wb.Close()

	// run the batch
	err = fn(ctx, scope)
	if err != nil {
		return
	}

	// commit the batch
	err = scope.wb.Commit(s.wo)
	if err != nil {
		return
	}

	return fn(ctx, scope)
}

func (s *trackerStore) Snapshot(fn trackerdb.SnapshotFn) (err error) {
	return s.SnapshotContext(context.Background(), fn)
}

func (s *trackerStore) SnapshotContext(ctx context.Context, fn trackerdb.SnapshotFn) (err error) {
	scope := snapshotScope{db: s.Pdb, snap: s.Pdb.NewSnapshot(), proto: s.proto}
	defer scope.snap.Close()

	// run the scope
	return fn(ctx, scope)
}

func (s *trackerStore) Transaction(fn trackerdb.TransactionFn) (err error) {
	return s.TransactionContext(context.Background(), fn)
}

func (s *trackerStore) TransactionContext(ctx context.Context, fn trackerdb.TransactionFn) (err error) {
	scope := transactionScope{
		store: s,
		db:    s.Pdb,
		wo:    s.wo,
		snap:  s.Pdb.NewSnapshot(),
		wb:    s.Pdb.NewBatch(),
		proto: s.proto}
	defer scope.snap.Close()
	defer scope.wb.Close()

	// run the transaction
	err = fn(ctx, scope)
	if err != nil {
		return
	}

	// commit the transaction
	err = scope.wb.Commit(s.wo)
	if err != nil {
		return
	}

	return nil
}

func (s *trackerStore) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	return generickv.MakeAccountsWriter(s, s), nil
}

func (s *trackerStore) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	return generickv.MakeAccountsReader(s, s.proto), nil
}

func (s *trackerStore) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	return generickv.MakeAccountsWriter(s, s), nil
}

func (s *trackerStore) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	return generickv.MakeAccountsReader(s, s.proto), nil
}

func (s *trackerStore) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (trackerdb.OnlineAccountsWriter, error) {
	return generickv.MakeOnlineAccountsWriter(s), nil
}

func (s *trackerStore) MakeOnlineAccountsOptimizedReader() (trackerdb.OnlineAccountsReader, error) {
	return generickv.MakeAccountsReader(s, s.proto), nil
}

func (s *trackerStore) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
	// TODO
	return nil, nil
}

func (s *trackerStore) Vacuum(ctx context.Context) (stats db.VacuumStats, err error) {
	// TODO
	return db.VacuumStats{}, nil
}

func (s *trackerStore) CleanupTest(dbName string, inMemory bool) {
	// TODO
}

func (s *trackerStore) ResetToV6Test(ctx context.Context) error {
	// TODO
	return nil
}

func (s *trackerStore) Close() {
	// TODO
}

func (txs transactionScope) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
	return nil, nil
}

type accountsReaderWriter struct {
	trackerdb.AccountsReaderExt
	trackerdb.AccountsWriterExt
}

func (txs transactionScope) MakeAccountsReaderWriter() (trackerdb.AccountsReaderWriter, error) {
	return accountsReaderWriter{
		generickv.MakeAccountsReader(txs, txs.proto),
		generickv.MakeAccountsWriter(txs, txs),
	}, nil
}

func (txs transactionScope) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	return generickv.MakeAccountsReader(txs, txs.proto), nil
}

func (txs transactionScope) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	// Note: the arguments are for the SQL implementation, nothing to do about them here.
	return generickv.MakeAccountsWriter(txs, txs), nil
}

func (txs transactionScope) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (trackerdb.OnlineAccountsWriter, error) {
	return generickv.MakeOnlineAccountsWriter(txs), nil
}

func (txs transactionScope) MakeOnlineAccountsOptimizedReader() (trackerdb.OnlineAccountsReader, error) {
	return generickv.MakeAccountsReader(txs, txs.proto), nil
}

func (txs transactionScope) MakeMerkleCommitter(staging bool) (trackerdb.MerkleCommitter, error) {
	return nil, nil
}

func (txs transactionScope) MakeOrderedAccountsIter(accountCount int) trackerdb.OrderedAccountsIter {
	return nil
}

func (txs transactionScope) MakeKVsIter(ctx context.Context) (trackerdb.KVsIter, error) {
	return nil, nil
}

func (txs transactionScope) MakeEncodedAccoutsBatchIter() trackerdb.EncodedAccountsBatchIter {
	return nil
}

func (txs transactionScope) MakeSpVerificationCtxReaderWriter() trackerdb.SpVerificationCtxReaderWriter {
	return nil
}

func (txs transactionScope) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	// TODO: pass the scope down? this should also work with a reduced batch scope
	// this can be done by making the transaction scope be the batch scope + snapshot scope
	return generickv.RunMigrations(ctx, txs.store, params, targetVersion)
}

func (txs transactionScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return time.Now(), nil
}

func (txs transactionScope) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return true
}

func (txs transactionScope) AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error) {
	return true, nil
}

func (txs transactionScope) Testing() trackerdb.TestTransactionScope {
	return txs
}

func (bs batchScope) MakeCatchpointWriter() (trackerdb.CatchpointWriter, error) {
	return nil, nil
}

func (bs batchScope) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	return nil, nil
}

func (bs batchScope) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	// Note: the arguments are for the SQL implementation, nothing to do about them here.
	// TODO: not the safest to give the batch the store for reading
	return generickv.MakeAccountsWriter(bs, bs.store), nil
}

func (bs batchScope) MakeSpVerificationCtxWriter() trackerdb.SpVerificationCtxWriter {
	return nil
}

func (bs batchScope) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	// TODO: pass the scope down? this should also work with a reduced batch scope
	// this can be done by making the transaction scope be the batch scope + snapshot scope
	return generickv.RunMigrations(ctx, bs.store, params, targetVersion)
}

func (bs batchScope) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return time.Now(), nil
}

func (bs batchScope) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return false
}

func (bs batchScope) AccountsUpdateSchemaTest(ctx context.Context) (err error) {
	return nil
}

func (bs batchScope) ModifyAcctBaseTest() error {
	return nil
}

func (bs batchScope) Testing() trackerdb.TestBatchScope {
	return bs
}

func (ss snapshotScope) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	return generickv.MakeAccountsReader(ss, ss.proto), nil
}

func (ss snapshotScope) MakeCatchpointReader() (trackerdb.CatchpointReader, error) {
	return nil, nil
}

func (ss snapshotScope) MakeSpVerificationCtxReader() trackerdb.SpVerificationCtxReader {
	return nil
}

func (ss snapshotScope) MakeCatchpointPendingHashesIterator(hashCount int) trackerdb.CatchpointPendingHashesIter {
	return nil
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

func (s *trackerStore) Set(key, value []byte) error {
	return s.Pdb.Set(key, value, s.wo)
}

func (s *trackerStore) Get(key []byte) (value []byte, closer io.Closer, err error) {
	value, closer, err = s.Pdb.Get(key)
	err = mapPebbleErrors(err)
	return
}

func (s *trackerStore) NewIter(low, high []byte, reverse bool) generickv.KvIter {
	opts := pebble.IterOptions{LowerBound: low, UpperBound: high}
	return newIter(s.Pdb.NewIter(&opts), reverse)
}

func (s *trackerStore) Delete(key []byte) error {
	return s.Pdb.Delete(key, s.wo)
}

func (s *trackerStore) DeleteRange(start, end []byte) error {
	return s.Pdb.DeleteRange(start, end, s.wo)
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

func (ss snapshotScope) Get(key []byte) (value []byte, closer io.Closer, err error) {
	value, closer, err = ss.snap.Get(key)
	err = mapPebbleErrors(err)
	return
}

func (ss snapshotScope) NewIter(low, high []byte, reverse bool) generickv.KvIter {
	opts := pebble.IterOptions{LowerBound: low, UpperBound: high}
	return newIter(ss.snap.NewIter(&opts), reverse)
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
