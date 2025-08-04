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

package trackerdb

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// testinterface.go contains interface extensions specific to testing
// testing interfaces should be made accessible by calling the Testing() method
// on the related interface. Example:
// 		testTx := tx.Testing()
// these can also be inlined:
// 		tx.Testing.AccountsInitTest(...)

// WriterTestExt is an interface to extend Writer with test-only methods
type WriterTestExt interface {
	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, rewardUnit uint64) (newDatabase bool, err error)
	AccountsUpdateSchemaTest(ctx context.Context) (err error)
	ModifyAcctBaseTest() error
}

// AccountsReaderTestExt is an interface to extend AccountsReaderExt with test-only methods
type AccountsReaderTestExt interface {
	AccountsAllTest() (bals map[basics.Address]basics.AccountData, err error)
	CheckCreatablesTest(t *testing.T, iteration int, expectedDbImage map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
}
