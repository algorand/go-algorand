// Copyright (C) 2019-2020 Algorand, Inc.
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

package ledger

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
)

type mockLedger struct {
	balanceMap map[basics.Address]basics.AccountData
}

func (ml *mockLedger) lookup(addr basics.Address) (basics.AccountData, error) {
	return ml.balanceMap[addr], nil
}

func (ml *mockLedger) isDup(firstValid, lastValid basics.Round, txn transactions.Txid, txl txlease) (bool, error) {
	return false, nil
}

func (ml *mockLedger) getAssetCreator(assetIdx basics.AssetIndex) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (ml *mockLedger) getAppCreator(appIdx basics.AppIndex) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (ml *mockLedger) getCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (ml *mockLedger) getStorageCounts(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	return basics.StateSchema{}, nil
}

func (ml *mockLedger) getStorageLimits(addr basics.Address, aidx basics.AppIndex, global bool) (basics.StateSchema, error) {
	return basics.StateSchema{}, nil
}

func (ml *mockLedger) Allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	return true, nil
}

func (ml *mockLedger) GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	return basics.TealValue{}, false, nil
}

func (ml *mockLedger) txnCounter() uint64 {
	return 0
}

func (ml *mockLedger) compactCertLast() basics.Round {
	return 0
}

func (ml *mockLedger) blockHdr(_ basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, nil
}

func checkCow(t *testing.T, cow *roundCowState, accts map[basics.Address]basics.AccountData) {
	for addr, data := range accts {
		d, err := cow.lookup(addr)
		require.NoError(t, err)
		require.Equal(t, d, data)
	}

	d, err := cow.lookup(randomAddress())
	require.NoError(t, err)
	require.Equal(t, d, basics.AccountData{})
}

func applyUpdates(cow *roundCowState, updates map[basics.Address]miniAccountDelta) {
	for addr, delta := range updates {
		cow.put(addr, delta.old, delta.new, nil, nil)
	}
}

func TestCowBalance(t *testing.T) {
	accts0 := randomAccounts(20, true)
	ml := mockLedger{balanceMap: accts0}

	c0 := makeRoundCowState(&ml, bookkeeping.BlockHeader{}, 0)
	checkCow(t, c0, accts0)

	c1 := c0.child()
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts0)

	updates1, accts1, _ := randomDeltas(10, accts0, 0)
	applyUpdates(c1, updates1)
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)

	c2 := c1.child()
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)
	checkCow(t, c2, accts1)

	updates2, accts2, _ := randomDeltas(10, accts1, 0)
	applyUpdates(c2, updates2)
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)
	checkCow(t, c2, accts2)

	c2.commitToParent()
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts2)

	c1.commitToParent()
	checkCow(t, c0, accts2)
}
