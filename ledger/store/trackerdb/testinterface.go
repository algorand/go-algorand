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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// testinterface.go contains interface extensions specific to testing
// testing interfaces should be made accessible by calling the Testing() method
// on the related interface. Example:
// testTx := tx.Testing()
// these can also be inlined:
// tx.Testing.AccountsInitTest(...)

// TestBatchScope is an interface to extend BatchScope with test-only methods
type TestBatchScope interface {
	BatchScope

	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsUpdateSchemaTest(ctx context.Context) (err error)
	RunMigrations(ctx context.Context, params Params, log logging.Logger, targetVersion int32) (mgr InitParams, err error)
	ModifyAcctBaseTest() error
}

// TestTransactionScope is an interface to extend TransactionScope with test-only methods
type TestTransactionScope interface {
	TransactionScope

	MakeOnlineAccountsOptimizedReader() (OnlineAccountsReader, error)
	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error)
}

// TestAccountsReaderExt is an interface to extend AccountsReaderExt with test-only methods
type TestAccountsReaderExt interface {
	AccountsReaderExt

	AccountsAllTest() (bals map[basics.Address]basics.AccountData, err error)
	CheckCreatablesTest(t *testing.T, iteration int, expectedDbImage map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
}
