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
	trackerdb.TrackerStore
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
			// instantiate a new db for each test
			entry.f(&customT{dbFactory(proto), proto, t})
		})
	}
}

func seedDb(t *testing.T, db dbForTests) {
	err := db.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		_, err := tx.RunMigrations(ctx, trackerdb.Params{InitProto: protocol.ConsensusCurrentVersion}, logging.TestingLog(t), trackerdb.AccountDBVersion)
		if err != nil {
			return err
		}
		return nil
	})
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
	proto config.ConsensusParams
	data  map[string][]byte
}

type mockSnapshot struct {
	db *mockDB
}

type mockTransaction struct {
	db    *mockDB
	proto config.ConsensusParams
}

type mockBatch struct {
	db *mockDB
}

type mockIter struct {
	db   *mockDB
	keys []string
	curr int
}

func makeMockDB(proto config.ConsensusParams) *mockDB {
	return &mockDB{proto: proto, data: make(map[string][]byte)}
}

func (db *mockDB) SetLogger(log logging.Logger) {
	// TODO
}

func (db *mockDB) SetSynchronousMode(ctx context.Context, mode db.SynchronousMode, fullfsync bool) (err error) {
	// TODO
	return nil
}

func (db *mockDB) IsSharedCacheConnection() bool {
	// TODO
	return false
}

func (db *mockDB) Batch(fn trackerdb.BatchFn) (err error) {
	return db.BatchContext(context.Background(), fn)
}

func (db *mockDB) BatchContext(ctx context.Context, fn trackerdb.BatchFn) (err error) {
	return fn(ctx, mockBatch{db})
}

func (db *mockDB) BeginBatch(ctx context.Context) (trackerdb.Batch, error) {
	return &mockBatch{db}, nil
}

func (db *mockDB) Snapshot(fn trackerdb.SnapshotFn) (err error) {
	return db.SnapshotContext(context.Background(), fn)
}

func (db *mockDB) SnapshotContext(ctx context.Context, fn trackerdb.SnapshotFn) (err error) {
	return fn(ctx, mockSnapshot{db})
}

func (db *mockDB) BeginSnapshot(ctx context.Context) (trackerdb.Snapshot, error) {
	return &mockSnapshot{db}, nil
}

func (db *mockDB) Transaction(fn trackerdb.TransactionFn) (err error) {
	return db.TransactionContext(context.Background(), fn)
}

func (db *mockDB) TransactionContext(ctx context.Context, fn trackerdb.TransactionFn) (err error) {
	return fn(ctx, mockTransaction{db, db.proto})
}

func (db *mockDB) BeginTransaction(ctx context.Context) (trackerdb.Transaction, error) {
	return &mockTransaction{db, db.proto}, nil
}

func (db *mockDB) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	return generickv.MakeAccountsWriter(db, db), nil
}

func (db *mockDB) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	return generickv.MakeAccountsReader(db, db.proto), nil
}

func (db *mockDB) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	return generickv.MakeAccountsWriter(db, db), nil
}

func (db *mockDB) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	return generickv.MakeAccountsReader(db, db.proto), nil
}

func (db *mockDB) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (trackerdb.OnlineAccountsWriter, error) {
	return generickv.MakeOnlineAccountsWriter(db), nil
}

func (db *mockDB) MakeOnlineAccountsOptimizedReader() (trackerdb.OnlineAccountsReader, error) {
	return generickv.MakeAccountsReader(db, db.proto), nil
}

func (db *mockDB) MakeSpVerificationCtxWriter() trackerdb.SpVerificationCtxWriter {
	return generickv.MakeStateproofWriter(db)
}

func (db *mockDB) MakeSpVerificationCtxReader() trackerdb.SpVerificationCtxReader {
	return generickv.MakeStateproofReader(db)
}

func (db *mockDB) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
	// TODO
	return nil, nil
}

func (db *mockDB) Vacuum(ctx context.Context) (stats db.VacuumStats, err error) {
	// TODO
	return stats, nil
}

func (db *mockDB) CleanupTest(dbName string, inMemory bool) {
	// TODO
}

func (db *mockDB) ResetToV6Test(ctx context.Context) error {
	// TODO
	return nil
}

func (db *mockDB) Close() {
	// TODO
}

func (txs mockTransaction) MakeCatchpointReaderWriter() (trackerdb.CatchpointReaderWriter, error) {
	return nil, nil
}

func (txs mockTransaction) MakeAccountsReaderWriter() (trackerdb.AccountsReaderWriter, error) {
	return struct {
		trackerdb.AccountsReaderExt
		trackerdb.AccountsWriterExt
	}{generickv.MakeAccountsReader(txs, txs.proto), generickv.MakeAccountsWriter(txs, txs)}, nil
}

func (txs mockTransaction) MakeAccountsOptimizedReader() (trackerdb.AccountsReader, error) {
	return generickv.MakeAccountsReader(txs, txs.proto), nil
}

func (txs mockTransaction) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	// Note: the arguments are for the SQL implementation, nothing to do about them here.
	return generickv.MakeAccountsWriter(txs, txs), nil
}

func (txs mockTransaction) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (w trackerdb.OnlineAccountsWriter, err error) {
	return generickv.MakeOnlineAccountsWriter(txs), nil
}

func (txs mockTransaction) MakeOnlineAccountsOptimizedReader() (r trackerdb.OnlineAccountsReader, err error) {
	return generickv.MakeAccountsReader(txs, txs.proto), nil
}

func (txs mockTransaction) MakeMerkleCommitter(staging bool) (trackerdb.MerkleCommitter, error) {
	return nil, nil
}

func (txs mockTransaction) MakeOrderedAccountsIter(accountCount int) trackerdb.OrderedAccountsIter {
	return nil
}

func (txs mockTransaction) MakeKVsIter(ctx context.Context) (trackerdb.KVsIter, error) {
	return nil, nil
}

func (txs mockTransaction) MakeEncodedAccoutsBatchIter() trackerdb.EncodedAccountsBatchIter {
	return nil
}

func (txs mockTransaction) MakeSpVerificationCtxReaderWriter() trackerdb.SpVerificationCtxReaderWriter {
	return nil
}

func (txs mockTransaction) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	return generickv.RunMigrations(ctx, txs.db, params, targetVersion)
}

func (txs mockTransaction) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return time.Now(), nil
}

func (txs mockTransaction) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return true
}

func (txs mockTransaction) AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error) {
	return true, nil
}

func (txs mockTransaction) Testing() trackerdb.TestTransactionScope {
	return txs
}

func (txs mockTransaction) Close() error {
	return nil
}

func (txs mockTransaction) Commit() error {
	return nil
}

func (bs mockBatch) MakeCatchpointWriter() (trackerdb.CatchpointWriter, error) {
	return nil, nil
}

func (bs mockBatch) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	return generickv.MakeAccountsWriter(bs, bs.db), nil
}

func (bs mockBatch) MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	// Note: the arguments are for the SQL implementation, nothing to do about them here.
	return generickv.MakeAccountsWriter(bs, bs.db), nil
}

func (bs mockBatch) MakeSpVerificationCtxWriter() trackerdb.SpVerificationCtxWriter {
	return nil
}

func (bs mockBatch) RunMigrations(ctx context.Context, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	return generickv.RunMigrations(ctx, bs.db, params, targetVersion)
}

func (bs mockBatch) ResetTransactionWarnDeadline(ctx context.Context, deadline time.Time) (prevDeadline time.Time, err error) {
	return time.Now(), nil
}

func (bs mockBatch) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return false
}

func (bs mockBatch) AccountsUpdateSchemaTest(ctx context.Context) (err error) {
	return nil
}

func (bs mockBatch) ModifyAcctBaseTest() error {
	return nil
}

func (bs mockBatch) Testing() trackerdb.TestBatchScope {
	return bs
}

func (bs mockBatch) Close() error {
	return nil
}

func (bs mockBatch) Commit() error {
	return nil
}

func (ss mockSnapshot) MakeAccountsReader() (trackerdb.AccountsReaderExt, error) {
	return nil, nil
}

func (ss mockSnapshot) MakeCatchpointReader() (trackerdb.CatchpointReader, error) {
	return nil, nil
}

func (ss mockSnapshot) MakeSpVerificationCtxReader() trackerdb.SpVerificationCtxReader {
	return nil
}

func (ss mockSnapshot) MakeCatchpointPendingHashesIterator(hashCount int) trackerdb.CatchpointPendingHashesIter {
	return nil
}

func (ss mockSnapshot) Close() error {
	return nil
}

// kv impls

func (db *mockDB) Set(key, value []byte) error {
	db.data[string(key)] = value
	return nil
}

func (db *mockDB) Get(key []byte) (data []byte, closer io.Closer, err error) {
	data, ok := db.data[string(key)]
	if !ok {
		err = trackerdb.ErrNotFound
		return
	}
	return data, io.NopCloser(bytes.NewReader(data)), nil
}

func (db *mockDB) NewIter(low, high []byte, reverse bool) generickv.KvIter {
	//
	var keys []string

	slow := string(low)
	shigh := string(high)

	for k := range db.data {
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

	return &mockIter{db, keys, -1}
}

func (db *mockDB) Delete(key []byte) error {
	delete(db.data, string(key))
	return nil
}

func (db *mockDB) DeleteRange(start, end []byte) error {
	var toDelete []string
	for k := range db.data {
		if k > string(start) && k < string(end) {
			toDelete = append(toDelete, k)
		}
	}
	for i := range toDelete {
		delete(db.data, toDelete[i])
	}
	return nil
}

//

func (bs mockBatch) Set(key, value []byte) error {
	return bs.db.Set(key, value)
}

func (bs mockBatch) Delete(key []byte) error {
	return bs.db.Delete(key)
}

func (bs mockBatch) DeleteRange(start, end []byte) error {
	return bs.db.DeleteRange(start, end)
}

func (txs mockTransaction) Set(key, value []byte) error {
	return txs.db.Set(key, value)
}

func (txs mockTransaction) Get(key []byte) (value []byte, closer io.Closer, err error) {
	return txs.db.Get(key)
}

func (txs mockTransaction) NewIter(low, high []byte, reverse bool) generickv.KvIter {
	return txs.db.NewIter(low, high, reverse)
}

func (txs mockTransaction) Delete(key []byte) error {
	return txs.db.Delete(key)
}

func (txs mockTransaction) DeleteRange(start, end []byte) error {
	return txs.db.DeleteRange(start, end)
}

//

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
	return iter.db.data[iter.keys[iter.curr]], nil
}

func (iter *mockIter) ValueSlice() (generickv.Slice, error) {
	return nil, nil
}

func (iter *mockIter) Valid() bool {
	return iter.curr != -1
}

func (iter *mockIter) Close() {}
