// Copyright (C) 2019-2022 Algorand, Inc.
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

package internal

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type creatableLocator struct {
	cidx  basics.CreatableIndex
	ctype basics.CreatableType
}
type storeLocator struct {
	addr   basics.Address
	aidx   basics.AppIndex
	global bool
}
type mockCowForLogicLedger struct {
	rnd    basics.Round
	ts     int64
	cr     map[creatableLocator]basics.Address
	brs    map[basics.Address]basics.AccountData
	stores map[storeLocator]basics.TealKeyValue
	txc    uint64
}

func (c *mockCowForLogicLedger) Get(addr basics.Address, withPendingRewards bool) (ledgercore.AccountData, error) {
	acct, err := c.getAccount(addr, withPendingRewards)
	return ledgercore.ToAccountData(acct), err
}

func (c *mockCowForLogicLedger) getAccount(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	br, ok := c.brs[addr]
	if !ok {
		return basics.AccountData{}, fmt.Errorf("addr %s not in mock cow", addr.String())
	}
	return br, nil
}

func (c *mockCowForLogicLedger) MinBalance(addr basics.Address, proto *config.ConsensusParams) (res basics.MicroAlgos, err error) {
	br, ok := c.brs[addr]
	if !ok {
		return basics.MicroAlgos{}, fmt.Errorf("addr %s not in mock cow", addr.String())
	}
	return br.MinBalance(proto), nil
}

func (c *mockCowForLogicLedger) GetAppParams(addr basics.Address, aidx basics.AppIndex) (ret basics.AppParams, ok bool, err error) {
	acct, err := c.getAccount(addr, false)
	if err != nil {
		return
	}
	ret, ok = acct.AppParams[aidx]
	return
}
func (c *mockCowForLogicLedger) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (ret basics.AssetParams, ok bool, err error) {
	acct, err := c.getAccount(addr, false)
	if err != nil {
		return
	}
	ret, ok = acct.AssetParams[aidx]
	return
}
func (c *mockCowForLogicLedger) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (ret basics.AssetHolding, ok bool, err error) {
	acct, err := c.getAccount(addr, false)
	if err != nil {
		return
	}
	ret, ok = acct.Assets[aidx]
	return
}

func (c *mockCowForLogicLedger) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	addr, found := c.cr[creatableLocator{cidx, ctype}]
	return addr, found, nil
}

func (c *mockCowForLogicLedger) GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) (basics.TealValue, bool, error) {
	kv, ok := c.stores[storeLocator{addr, aidx, global}]
	if !ok {
		return basics.TealValue{}, false, fmt.Errorf("no store for (%s %d %v) in mock cow", addr.String(), aidx, global)
	}
	tv, found := kv[key]
	return tv, found, nil
}

func (c *mockCowForLogicLedger) BuildEvalDelta(aidx basics.AppIndex, txn *transactions.Transaction) (evalDelta transactions.EvalDelta, err error) {
	return transactions.EvalDelta{}, nil
}

func (c *mockCowForLogicLedger) SetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue, accountIdx uint64) error {
	kv, ok := c.stores[storeLocator{addr, aidx, global}]
	if !ok {
		return fmt.Errorf("no store for (%s %d %v) in mock cow", addr.String(), aidx, global)
	}
	kv[key] = value
	c.stores[storeLocator{addr, aidx, global}] = kv
	return nil
}

func (c *mockCowForLogicLedger) DelKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, accountIdx uint64) error {
	kv, ok := c.stores[storeLocator{addr, aidx, global}]
	if !ok {
		return fmt.Errorf("no store for (%s %d %v) in mock cow", addr.String(), aidx, global)
	}
	delete(kv, key)
	c.stores[storeLocator{addr, aidx, global}] = kv
	return nil
}

func (c *mockCowForLogicLedger) round() basics.Round {
	return c.rnd
}

func (c *mockCowForLogicLedger) prevTimestamp() int64 {
	return c.ts
}

func (c *mockCowForLogicLedger) allocated(addr basics.Address, aidx basics.AppIndex, global bool) (bool, error) {
	_, found := c.stores[storeLocator{addr, aidx, global}]
	return found, nil
}

func (c *mockCowForLogicLedger) txnCounter() uint64 {
	return c.txc
}

func (c *mockCowForLogicLedger) incTxnCount() {
	c.txc++
}

// No unit tests care about this yet, so this is a lame implementation
func (c *mockCowForLogicLedger) blockHdrCached(round basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{Round: round}, nil
}

func newCowMock(creatables []modsData) *mockCowForLogicLedger {
	var m mockCowForLogicLedger
	m.cr = make(map[creatableLocator]basics.Address, len(creatables))
	for _, e := range creatables {
		m.cr[creatableLocator{e.cidx, e.ctype}] = e.addr
	}
	return &m
}

func TestLogicLedgerMake(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	c := &mockCowForLogicLedger{}
	l := newLogicLedger(c)
	a.NotNil(l)
	a.Equal(c, l.cow)
}

func TestLogicLedgerBalances(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	c := newCowMock(nil)
	l := newLogicLedger(c)
	a.NotNil(l)

	addr1 := ledgertesting.RandomAddress()
	ble := basics.MicroAlgos{Raw: 100}
	c.brs = map[basics.Address]basics.AccountData{addr1: {MicroAlgos: ble}}
	acct, err := l.AccountData(addr1)
	a.NoError(err)
	a.Equal(ble, acct.MicroAlgos)
}

func TestLogicLedgerGetters(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})
	l := newLogicLedger(c)
	a.NotNil(l)

	round := basics.Round(1234)
	c.rnd = round
	ts := int64(11223344)
	c.ts = ts

	addr1 := ledgertesting.RandomAddress()
	c.stores = map[storeLocator]basics.TealKeyValue{{addr1, aidx, false}: {}}
	a.Equal(round, l.Round())
	a.Equal(ts, l.LatestTimestamp())
	a.True(l.OptedIn(addr1, aidx))
	a.False(l.OptedIn(addr, aidx))
}

func TestLogicLedgerAsset(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	addr1 := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	assetIdx := basics.AssetIndex(2)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
		{addr1, basics.CreatableIndex(assetIdx), basics.AssetCreatable},
	})
	l := newLogicLedger(c)
	a.NotNil(l)

	_, _, err := l.AssetParams(basics.AssetIndex(aidx))
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("asset %d does not exist", aidx))

	c.brs = map[basics.Address]basics.AccountData{
		addr1: {AssetParams: map[basics.AssetIndex]basics.AssetParams{assetIdx: {Total: 1000}}},
	}

	ap, creator, err := l.AssetParams(assetIdx)
	a.NoError(err)
	a.Equal(addr1, creator)
	a.Equal(uint64(1000), ap.Total)

	_, err = l.AssetHolding(addr1, assetIdx)
	a.Error(err)
	a.Contains(err.Error(), "has not opted in to asset")

	c.brs = map[basics.Address]basics.AccountData{
		addr1: {
			AssetParams: map[basics.AssetIndex]basics.AssetParams{assetIdx: {Total: 1000}},
			Assets:      map[basics.AssetIndex]basics.AssetHolding{assetIdx: {Amount: 99}},
		},
	}

	ah, err := l.AssetHolding(addr1, assetIdx)
	a.NoError(err)
	a.Equal(uint64(99), ah.Amount)
}

func TestLogicLedgerGetKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	addr1 := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	assetIdx := basics.AssetIndex(2)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
		{addr1, basics.CreatableIndex(assetIdx), basics.AssetCreatable},
	})
	l := newLogicLedger(c)
	a.NotNil(l)

	_, ok, err := l.GetGlobal(basics.AppIndex(assetIdx), "gkey")
	a.Error(err)
	a.False(ok)
	a.Contains(err.Error(), fmt.Sprintf("app %d does not exist", assetIdx))

	tv := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx + 1, true}: {"gkey": tv}}
	val, ok, err := l.GetGlobal(aidx, "gkey")
	a.Error(err)
	a.False(ok)
	a.Contains(err.Error(), fmt.Sprintf("no store for (%s %d %v) in mock cow", addr, aidx, true))

	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, true}: {"gkey": tv}}
	val, ok, err = l.GetGlobal(aidx, "gkey")
	a.NoError(err)
	a.True(ok)
	a.Equal(tv, val)

	// check local
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, false}: {"lkey": tv}}
	val, ok, err = l.GetLocal(addr, aidx, "lkey", 0)
	a.NoError(err)
	a.True(ok)
	a.Equal(tv, val)
}

func TestLogicLedgerSetKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	l := newLogicLedger(c)
	a.NotNil(l)

	tv := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	err := l.SetGlobal(aidx, "gkey", tv)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("no store for (%s %d %v) in mock cow", addr, aidx, true))

	tv2 := basics.TealValue{Type: basics.TealUintType, Uint: 2}
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, true}: {"gkey": tv}}
	err = l.SetGlobal(aidx, "gkey", tv2)
	a.NoError(err)

	// check local
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, false}: {"lkey": tv}}
	err = l.SetLocal(addr, aidx, "lkey", tv2, 0)
	a.NoError(err)
}

func TestLogicLedgerDelKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	addr := ledgertesting.RandomAddress()
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	l := newLogicLedger(c)
	a.NotNil(l)

	err := l.DelGlobal(aidx, "gkey")
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("no store for (%s %d %v) in mock cow", addr, aidx, true))

	tv := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, true}: {"gkey": tv}}
	err = l.DelGlobal(aidx, "gkey")
	a.NoError(err)

	addr1 := ledgertesting.RandomAddress()
	c.stores = map[storeLocator]basics.TealKeyValue{{addr1, aidx, false}: {"lkey": tv}}
	err = l.DelLocal(addr1, aidx, "lkey", 0)
	a.NoError(err)
}
