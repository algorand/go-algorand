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

package testsuite

import (
	"context"

	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/stretchr/testify/require"
)

func init() {
	// register tests that will run on each KV implementation
	registerTest("db-semantics-transaction", CustomTestTransaction)
}

// This test will ensure that transaction semantics carry the same meaning across all engine implementations.
func CustomTestTransaction(t *customT) {
	aow, err := t.db.MakeAccountsOptimizedWriter(true, false, false, false)
	require.NoError(t, err)

	aor, err := t.db.MakeAccountsOptimizedReader()
	require.NoError(t, err)

	// generate some test data
	addrA := RandomAddress()
	dataA := trackerdb.BaseAccountData{
		RewardsBase: 1000,
	}

	// insert the account
	normBalanceA := dataA.NormalizedOnlineBalance(t.proto)
	refA, err := aow.InsertAccount(addrA, normBalanceA, dataA)
	require.NoError(t, err)

	//
	// test
	//

	err = t.db.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		// create a scoped writer
		aow, err := tx.MakeAccountsOptimizedWriter(true, false, false, false)
		require.NoError(t, err)

		// create a scoped reader
		aor, err := tx.MakeAccountsOptimizedReader()
		require.NoError(t, err)

		// read an account
		padA, err := aor.LookupAccount(addrA)
		require.NoError(t, err)
		require.Equal(t, refA, padA.Ref) // same ref as when we inserted it

		// update the account
		dataA.RewardsBase = 98287
		normBalanceA = dataA.NormalizedOnlineBalance(t.proto)
		_, err = aow.UpdateAccount(refA, normBalanceA, dataA)
		require.NoError(t, err)

		return nil
	})
	require.NoError(t, err)

	// read the updated record outside the transaction to make sure it was commited
	padA, err := aor.LookupAccount(addrA)
	require.NoError(t, err)
	require.Equal(t, uint64(98287), padA.AccountData.RewardsBase) // same updated data
}
