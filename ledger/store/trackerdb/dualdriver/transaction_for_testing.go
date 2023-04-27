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

package dualdriver

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

type transactionForTesting struct {
	primary   trackerdb.TestTransactionScope
	secondary trackerdb.TestTransactionScope
}

// AccountsInitLightTest implements trackerdb.TestTransactionScope
func (tx *transactionForTesting) AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabse bool, err error) {
	newDatabaseP, errP := tx.primary.AccountsInitLightTest(tb, initAccounts, proto)
	newDatabaseS, errS := tx.secondary.AccountsInitLightTest(tb, initAccounts, proto)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if newDatabaseP != newDatabaseS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return newDatabaseP, nil
}

// AccountsInitTest implements trackerdb.TestTransactionScope
func (tx *transactionForTesting) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	newDatabaseP := tx.primary.AccountsInitTest(tb, initAccounts, proto)
	tx.secondary.AccountsInitTest(tb, initAccounts, proto)
	// return primary results
	return newDatabaseP
}

// MakeOnlineAccountsOptimizedReader implements trackerdb.TestTransactionScope
func (tx *transactionForTesting) MakeOnlineAccountsOptimizedReader() (trackerdb.OnlineAccountsReader, error) {
	primary, errP := tx.primary.MakeOnlineAccountsOptimizedReader()
	secondary, errS := tx.secondary.MakeOnlineAccountsOptimizedReader()
	err := coalesceErrors(errP, errS)
	if err != nil {
		return nil, err
	}
	return &onlineAccountsReader{primary, secondary}, nil
}
