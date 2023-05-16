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
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/generickv"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
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
	// use default options for now
	opts := &pebble.Options{
		Logger: log,
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
