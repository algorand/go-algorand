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

package generickv

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

type writer struct {
	// TODO: the need for the store here is quite broken
	//       this is due to exposing RunMigrations and AccountsInit on the writers
	//       the internals of this methods completly ignore the "writer" and recreate a transaction
	store trackerdb.Store
	KvWrite
	KvRead
}

// MakeWriter returns a trackerdb.Writer for a KV
func MakeWriter(store trackerdb.Store, kvw KvWrite, kvr KvRead) trackerdb.Writer {
	return &writer{store, kvw, kvr}
}

// MakeAccountsOptimizedWriter implements trackerdb.Writer
func (w *writer) MakeAccountsOptimizedWriter(hasAccounts bool, hasResources bool, hasKvPairs bool, hasCreatables bool) (trackerdb.AccountsWriter, error) {
	return MakeAccountsWriter(w, w), nil
}

// MakeAccountsWriter implements trackerdb.Writer
func (w *writer) MakeAccountsWriter() (trackerdb.AccountsWriterExt, error) {
	return MakeAccountsWriter(w, w), nil
}

// MakeOnlineAccountsOptimizedWriter implements trackerdb.Writer
func (w *writer) MakeOnlineAccountsOptimizedWriter(hasAccounts bool) (trackerdb.OnlineAccountsWriter, error) {
	return MakeOnlineAccountsWriter(w), nil
}

// MakeSpVerificationCtxWriter implements trackerdb.Writer
func (w *writer) MakeSpVerificationCtxWriter() trackerdb.SpVerificationCtxWriter {
	return MakeStateproofWriter(w)
}

// Testing implements trackerdb.Writer
func (w *writer) Testing() trackerdb.WriterTestExt {
	return &writerForTesting{w.store, w, w}
}

type writerForTesting struct {
	trackerdb.Store
	KvWrite
	KvRead
}

// AccountsInitLightTest implements trackerdb.WriterTestExt
func (w *writerForTesting) AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, rewardUnit uint64) (newDatabase bool, err error) {
	panic("unimplemented")
}

// AccountsInitTest implements trackerdb.WriterTestExt
func (w *writerForTesting) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return AccountsInitTest(tb, w, initAccounts, proto)
}

// AccountsUpdateSchemaTest implements trackerdb.WriterTestExt
func (w *writerForTesting) AccountsUpdateSchemaTest(ctx context.Context) (err error) {
	panic("unimplemented")
}

// ModifyAcctBaseTest implements trackerdb.WriterTestExt
func (w *writerForTesting) ModifyAcctBaseTest() error {
	panic("unimplemented")
}
