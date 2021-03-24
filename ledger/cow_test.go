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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

type mockLedger struct {
	balanceMap map[basics.Address]basics.AccountData
}

func (ml *mockLedger) lookup(addr basics.Address) (basics.AccountData, error) {
	return ml.balanceMap[addr], nil
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

func (ml *mockLedger) getKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	return basics.TealValue{}, false, nil
}

func (ml *mockLedger) txnCounter() uint64 {
	return 0
}

func (ml *mockLedger) compactCertNext() basics.Round {
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

func applyUpdates(cow *roundCowState, updates ledgercore.AccountDeltas) {
	for i := 0; i < updates.Len(); i++ {
		addr, delta := updates.GetByIdx(i)
		cow.put(addr, delta, nil, nil)
	}
}

func TestCowBalance(t *testing.T) {
	accts0 := randomAccounts(20, true)
	ml := mockLedger{balanceMap: accts0}

	c0 := makeRoundCowState(&ml, bookkeeping.BlockHeader{}, 0, 0)
	checkCow(t, c0, accts0)

	c1 := c0.fullChild()
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts0)

	updates1, accts1, _ := randomDeltas(10, accts0, 0)
	applyUpdates(c1, updates1)
	checkCow(t, c0, accts0)
	checkCow(t, c1, accts1)

	c2 := c1.fullChild()
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
func BenchmarkRoundCowStateMemroyAllocations(b *testing.B) {
	accts0 := randomAccounts(2000, true)
	ml := mockLedger{balanceMap: accts0}
	addresses := make([]basics.Address, 0, len(accts0))
	for addr := range accts0 {
		addresses = append(addresses, addr)
	}

	transactionsCount := 10000

	txn := make([]transactions.Transaction, transactionsCount, transactionsCount)
	txid := make([]transactions.Txid, transactionsCount, transactionsCount)

	for i := 0; i < transactionsCount; i++ {
		txn[i].LastValid = basics.Round(i + 50)
		txn[i].Sender = addresses[i%len(addresses)]
		txn[i].Lease = crypto.Hash([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)})
		txid[i] = txn[i].ID()
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rcs := makeRoundCowState(&ml, bookkeeping.BlockHeader{}, 0, transactionsCount)
		for txIdx := 0; txIdx < transactionsCount; txIdx++ {
			child := rcs.child()
			child.addTx(txn[txIdx], txid[txIdx])
			child.commitToParent()
		}
	}
}

func mapCheckHelper(cs *roundCowState) {
	/*for k := range cs.mods.Txids {
		if int(k[0]) == 300 {
			k[0] = 1
		}
	}*/
	cs.commitToParent()
}
func BenchmarkMapRangeMemoryAllocs(b *testing.B) {
	transactionsCount := 10000
	cowStates := make([]*roundCowState, 0, transactionsCount)
	parent := &roundCowState{}
	parent.mods.Txids = make(map[transactions.Txid]basics.Round, transactionsCount)
	for i := 0; i < transactionsCount; i++ {
		txid := transactions.Txid(crypto.Hash([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}))
		cs := &roundCowState{}
		cs.mods.Txids = make(map[transactions.Txid]basics.Round, 1)
		cs.mods.Txids[txid] = basics.Round(i)
		cs.commitParent = parent
		cowStates = append(cowStates, cs)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for j := 0; j < len(cowStates); j++ {
			mapCheckHelper(cowStates[j])
		}
	}
	require.Equal(b, 10000, len(cowStates))
}

var _ = fmt.Printf
