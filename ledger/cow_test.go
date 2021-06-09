// Copyright (C) 2019-2021 Algorand, Inc.
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
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

type mockLedger struct {
	balanceMap map[basics.Address]basics.AccountData
	blocks     map[basics.Round]bookkeeping.BlockHeader
	blockErr   map[basics.Round]error
}

func (ml *mockLedger) lookup(addr basics.Address) (ledgercore.PersistedAccountData, error) {
	return ledgercore.PersistedAccountData{AccountData: ml.balanceMap[addr]}, nil
}

func (ml *mockLedger) lookupCreatableData(addr basics.Address, locators []creatableDataLocator) (ledgercore.PersistedAccountData, error) {
	return ledgercore.PersistedAccountData{AccountData: ml.balanceMap[addr]}, nil
}

func (ml *mockLedger) checkDup(firstValid, lastValid basics.Round, txn transactions.Txid, txl ledgercore.Txlease) error {
	return nil
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

func (ml *mockLedger) allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	return true, nil
}

func (ml *mockLedger) getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error) {
	return basics.TealValue{}, false, nil
}

func (ml *mockLedger) txnCounter() uint64 {
	return 0
}

func (ml *mockLedger) compactCertNext() basics.Round {
	return 0
}

func (ml *mockLedger) blockHdr(rnd basics.Round) (bookkeeping.BlockHeader, error) {
	err, hit := ml.blockErr[rnd]
	if hit {
		return bookkeeping.BlockHeader{}, err
	}
	hdr := ml.blocks[rnd] // default struct is fine if nothing found
	return hdr, nil
}

func checkCow(t *testing.T, cow *roundCowState, accts map[basics.Address]basics.AccountData) {
	for addr, data := range accts {
		d, err := cow.lookup(addr)
		require.NoError(t, err)
		require.Equal(t, d.AccountData, data)
	}

	pad, err := cow.lookup(randomAddress())
	require.NoError(t, err)
	require.Equal(t, pad, ledgercore.PersistedAccountData{})
}

func applyUpdates(cow *roundCowState, updates ledgercore.AccountDeltas) {
	for i := 0; i < updates.Len(); i++ {
		addr, pad := updates.GetByIdx(i)
		cow.lookup(addr) // populate getPadCache
		cow.put(addr, pad.AccountData, nil, nil)
	}
}

func TestCowBalance(t *testing.T) {
	accts0 := randomAccounts(20, true)
	ml := mockLedger{balanceMap: accts0}

	c0 := makeRoundCowState(&ml, bookkeeping.BlockHeader{}, 0, 0)
	checkCow(t, c0, accts0)

	c1 := c0.child(0)
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts0)

	require.NotPanics(t, func() {
		c1.put(randomAddress(), basics.AccountData{}, nil, nil)
	})

	updates1, accts1, _ := randomDeltas(10, accts0, 0)
	applyUpdates(c1, updates1)
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)

	c2 := c1.child(0)
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
