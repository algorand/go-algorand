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

package testsuite

// A collection of utility functions and types to write the tests in this module.

import (
	"bytes"
	"context"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/generickv"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/stretchr/testify/require"
)

type customT struct {
	db    dbForTests
	proto config.ConsensusParams
	*testing.T
}

type dbForTests interface {
	// generickv.KvWrite
	// generickv.KvRead
	trackerdb.Store
}

type genericTestEntry struct {
	name string
	f    func(*customT)
}

// list of tests to be run on each KV DB implementation
var genericTests []genericTestEntry

// registerTest registers the given test with the suite
func registerTest(name string, f func(*customT)) {
	genericTests = append(genericTests, genericTestEntry{name, f})
}

// runGenericTestsWithDB runs a generic set of tests on the given database
func runGenericTestsWithDB(t *testing.T, dbFactory func(config.ConsensusParams) (db dbForTests)) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	for _, entry := range genericTests {
		// run each test defined in the suite using the Golang subtest
		t.Run(entry.name, func(t *testing.T) {
			partitiontest.PartitionTest(t)
			// instantiate a new db for each test
			entry.f(&customT{dbFactory(proto), proto, t})
		})
	}
}

func seedDb(t *testing.T, db dbForTests) {
	params := trackerdb.Params{InitProto: protocol.ConsensusCurrentVersion}
	_, err := db.RunMigrations(context.Background(), params, logging.TestingLog(t), trackerdb.AccountDBVersion)
	require.NoError(t, err)
}

// RandomAddress generates a random address
//
//	TODO: this method  is defined in ledgertesting, should be moved up to basics so it can be used in more places
func RandomAddress() basics.Address {
	var addr basics.Address
	crypto.RandBytes(addr[:])
	return addr
}

type mockDB struct {
	kvs   kvstore
	proto config.ConsensusParams
	// use the generickv implementations
	trackerdb.Reader
	trackerdb.Writer
	trackerdb.Catchpoint
}

func makeMockDB(proto config.ConsensusParams) trackerdb.Store {
	kvs := kvstore{data: make(map[string][]byte)}
	var db trackerdb.Store
	db = &mockDB{
		kvs,
		proto,
		generickv.MakeReader(&kvs, proto),
		generickv.MakeWriter(db, &kvs, &kvs),
		generickv.MakeCatchpoint(),
	}
	return db
}

func (db *mockDB) SetSynchronousMode(ctx context.Context, mode db.SynchronousMode, fullfsync bool) (err error) {
	// TODO
	return nil
}

func (db *mockDB) IsSharedCacheConnection() bool {
	return false
}

// RunMigrations implements trackerdb.Store
func (db *mockDB) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	// create a anonym struct that impls the interface for the migration runner
	aux := struct {
		*mockDB
		*kvstore
	}{db, &db.kvs}
	return generickv.RunMigrations(ctx, aux, params, targetVersion)
}

// Batch implements trackerdb.Store
func (db *mockDB) Batch(fn trackerdb.BatchFn) (err error) {
	return db.BatchContext(context.Background(), fn)
}

// BatchContext implements trackerdb.Store
func (db *mockDB) BatchContext(ctx context.Context, fn trackerdb.BatchFn) (err error) {
	handle, err := db.BeginBatch(ctx)
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
func (db *mockDB) BeginBatch(ctx context.Context) (trackerdb.Batch, error) {
	scope := mockBatch{db}
	return &struct {
		mockBatch
		trackerdb.Writer
	}{scope, generickv.MakeWriter(db, &scope, &db.kvs)}, nil
}

// Snapshot implements trackerdb.Store
func (db *mockDB) Snapshot(fn trackerdb.SnapshotFn) (err error) {
	return db.SnapshotContext(context.Background(), fn)
}

// SnapshotContext implements trackerdb.Store
func (db *mockDB) SnapshotContext(ctx context.Context, fn trackerdb.SnapshotFn) (err error) {
	handle, err := db.BeginSnapshot(ctx)
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
func (db *mockDB) BeginSnapshot(ctx context.Context) (trackerdb.Snapshot, error) {
	scope := mockSnapshot{db}
	return &struct {
		mockSnapshot
		trackerdb.Reader
	}{scope, generickv.MakeReader(&scope, db.proto)}, nil
}

// Transaction implements trackerdb.Store
func (db *mockDB) Transaction(fn trackerdb.TransactionFn) (err error) {
	return db.TransactionContext(context.Background(), fn)
}

// TransactionContext implements trackerdb.Store
func (db *mockDB) TransactionContext(ctx context.Context, fn trackerdb.TransactionFn) (err error) {
	handle, err := db.BeginTransaction(ctx)
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

// TransactionWithRetryClearFn implements trackerdb.Store but ignores the RetryClearFn
func (db *mockDB) TransactionWithRetryClearFn(fn trackerdb.TransactionFn, _ trackerdb.RetryClearFn) (err error) {
	return db.TransactionContext(context.Background(), fn)
}

// TransactionContextWithRetryClearFn implements trackerdb.Store but ignores the RetryClearFn
func (db *mockDB) TransactionContextWithRetryClearFn(ctx context.Context, fn trackerdb.TransactionFn, _ trackerdb.RetryClearFn) (err error) {
	return db.TransactionContext(ctx, fn)
}

// BeginTransaction implements trackerdb.Store
func (db *mockDB) BeginTransaction(ctx context.Context) (trackerdb.Transaction, error) {
	scope := mockTransaction{db, db.proto}

	return &struct {
		mockTransaction
		trackerdb.Reader
		trackerdb.Writer
		trackerdb.Catchpoint
	}{scope, generickv.MakeReader(&scope, db.proto), generickv.MakeWriter(db, &scope, &scope), generickv.MakeCatchpoint()}, nil
}

func (db *mockDB) Vacuum(ctx context.Context) (stats db.VacuumStats, err error) {
	// TODO
	return stats, nil
}

func (db *mockDB) ResetToV6Test(ctx context.Context) error {
	// TODO
	return nil
}

func (db *mockDB) Close() {
	// TODO
}

type kvstore struct {
	data map[string][]byte
}

func (kvs *kvstore) Set(key, value []byte) error {
	kvs.data[string(key)] = value
	return nil
}

func (kvs *kvstore) Get(key []byte) (data []byte, closer io.Closer, err error) {
	data, ok := kvs.data[string(key)]
	if !ok {
		err = trackerdb.ErrNotFound
		return
	}
	return data, io.NopCloser(bytes.NewReader(data)), nil
}

func (kvs *kvstore) NewIter(low, high []byte, reverse bool) generickv.KvIter {
	//
	var keys []string

	slow := string(low)
	shigh := string(high)

	for k := range kvs.data {
		if k > slow && k < shigh {
			keys = append(keys, k)
		}
	}

	sort.Strings(keys)
	if reverse {
		for i, j := 0, len(keys)-1; i < j; i, j = i+1, j-1 {
			keys[i], keys[j] = keys[j], keys[i]
		}
	}

	return &mockIter{kvs, keys, -1}
}

func (kvs *kvstore) Delete(key []byte) error {
	delete(kvs.data, string(key))
	return nil
}

func (kvs *kvstore) DeleteRange(start, end []byte) error {
	var toDelete []string
	for k := range kvs.data {
		if k > string(start) && k < string(end) {
			toDelete = append(toDelete, k)
		}
	}
	for i := range toDelete {
		delete(kvs.data, toDelete[i])
	}
	return nil
}

type mockSnapshot struct {
	db *mockDB
}

func (ss mockSnapshot) Get(key []byte) (value []byte, closer io.Closer, err error) {
	return ss.db.kvs.Get(key)
}

func (ss mockSnapshot) NewIter(low, high []byte, reverse bool) generickv.KvIter {
	return ss.db.kvs.NewIter(low, high, reverse)
}

func (ss mockSnapshot) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return time.Now(), nil
}

func (ss mockSnapshot) Close() error {
	return nil
}

type mockTransaction struct {
	db    *mockDB
	proto config.ConsensusParams
}

func (txs mockTransaction) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	// create a anonym struct that impls the interface for the migration runner
	aux := struct {
		*mockDB
		*kvstore
	}{txs.db, &txs.db.kvs}
	return generickv.RunMigrations(ctx, aux, params, targetVersion)
}

func (txs mockTransaction) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return time.Now(), nil
}

func (txs mockTransaction) Close() error {
	return nil
}

func (txs mockTransaction) Commit() error {
	return nil
}

func (txs mockTransaction) Set(key, value []byte) error {
	return txs.db.kvs.Set(key, value)
}

func (txs mockTransaction) Get(key []byte) (value []byte, closer io.Closer, err error) {
	return txs.db.kvs.Get(key)
}

func (txs mockTransaction) NewIter(low, high []byte, reverse bool) generickv.KvIter {
	return txs.db.kvs.NewIter(low, high, reverse)
}

func (txs mockTransaction) Delete(key []byte) error {
	return txs.db.kvs.Delete(key)
}

func (txs mockTransaction) DeleteRange(start, end []byte) error {
	return txs.db.kvs.DeleteRange(start, end)
}

type mockBatch struct {
	db *mockDB
}

func (bs mockBatch) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return time.Now(), nil
}

func (bs mockBatch) Close() error {
	return nil
}

func (bs mockBatch) Commit() error {
	return nil
}

func (bs mockBatch) Set(key, value []byte) error {
	return bs.db.kvs.Set(key, value)
}

func (bs mockBatch) Delete(key []byte) error {
	return bs.db.kvs.Delete(key)
}

func (bs mockBatch) DeleteRange(start, end []byte) error {
	return bs.db.kvs.DeleteRange(start, end)
}

type mockIter struct {
	kvs  *kvstore
	keys []string
	curr int
}

func (iter *mockIter) Next() bool {
	if iter.curr < len(iter.keys)-1 {
		iter.curr++
		return true
	}
	iter.curr = -1
	return false
}

func (iter *mockIter) Key() []byte {
	return []byte(iter.keys[iter.curr])
}

func (iter *mockIter) KeySlice() generickv.Slice {
	return nil
}

func (iter *mockIter) Value() ([]byte, error) {
	return iter.kvs.data[iter.keys[iter.curr]], nil
}

func (iter *mockIter) ValueSlice() (generickv.Slice, error) {
	return nil, nil
}

func (iter *mockIter) Valid() bool {
	return iter.curr != -1
}

func (iter *mockIter) Close() {}
