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
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

func getRandomAddress(a *require.Assertions) basics.Address {
	const rl = 16
	b := make([]byte, rl)
	n, err := rand.Read(b)
	a.NoError(err)
	a.Equal(rl, n)

	address := crypto.Hash(b)
	return basics.Address(address)
}

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
}

func (c *mockCowForLogicLedger) Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	br, ok := c.brs[addr]
	if !ok {
		return basics.AccountData{}, fmt.Errorf("addr %s not in mock cow", addr.String())
	}
	return br, nil
}

func (c *mockCowForLogicLedger) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	addr, found := c.cr[creatableLocator{cidx, ctype}]
	return addr, found, nil
}

func (c *mockCowForLogicLedger) GetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) (basics.TealValue, bool, error) {
	kv, ok := c.stores[storeLocator{addr, aidx, global}]
	if !ok {
		return basics.TealValue{}, false, fmt.Errorf("no store for (%s %d %v) in mock cow", addr.String(), aidx, global)
	}
	tv, found := kv[key]
	return tv, found, nil
}

func (c *mockCowForLogicLedger) BuildEvalDelta(aidx basics.AppIndex, txn *transactions.Transaction) (evalDelta basics.EvalDelta, err error) {
	return basics.EvalDelta{}, nil
}

func (c *mockCowForLogicLedger) SetKey(addr basics.Address, aidx basics.AppIndex, global bool, key string, value basics.TealValue) error {
	kv, ok := c.stores[storeLocator{addr, aidx, global}]
	if !ok {
		return fmt.Errorf("no store for (%s %d %v) in mock cow", addr.String(), aidx, global)
	}
	kv[key] = value
	c.stores[storeLocator{addr, aidx, global}] = kv
	return nil
}

func (c *mockCowForLogicLedger) DelKey(addr basics.Address, aidx basics.AppIndex, global bool, key string) error {
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

func newCowMock(creatables []modsData) *mockCowForLogicLedger {
	var m mockCowForLogicLedger
	m.cr = make(map[creatableLocator]basics.Address, len(creatables))
	for _, e := range creatables {
		m.cr[creatableLocator{e.cidx, e.ctype}] = e.addr
	}
	return &m
}

func TestLogicLedgerMake(t *testing.T) {
	a := require.New(t)

	_, err := newLogicLedger(nil, 0)
	a.Error(err)
	a.Contains(err.Error(), "cannot make logic ledger for app index 0")

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)

	c := &mockCowForLogicLedger{}
	_, err = newLogicLedger(c, 0)
	a.Error(err)
	a.Contains(err.Error(), "cannot make logic ledger for app index 0")

	_, err = newLogicLedger(c, aidx)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("app %d does not exist", aidx))

	c = newCowMock([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)
	a.Equal(aidx, l.aidx)
	a.Equal(c, l.cow)
}

func TestLogicLedgerBalances(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	addr1 := getRandomAddress(a)
	ble := basics.MicroAlgos{Raw: 100}
	c.brs = map[basics.Address]basics.AccountData{addr1: {MicroAlgos: ble}}
	bla, err := l.Balance(addr1)
	a.NoError(err)
	a.Equal(ble, bla)
}

func TestLogicLedgerGetters(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	round := basics.Round(1234)
	c.rnd = round
	ts := int64(11223344)
	c.ts = ts

	addr1 := getRandomAddress(a)
	c.stores = map[storeLocator]basics.TealKeyValue{{addr1, aidx, false}: {}}
	a.Equal(aidx, l.ApplicationID())
	a.Equal(round, l.Round())
	a.Equal(ts, l.LatestTimestamp())
	a.True(l.OptedIn(addr1, 0))
	a.True(l.OptedIn(addr1, aidx))
	a.False(l.OptedIn(addr, 0))
	a.False(l.OptedIn(addr, aidx))
}

func TestLogicLedgerAsset(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	addr1 := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	assetIdx := basics.AssetIndex(2)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
		{addr1, basics.CreatableIndex(assetIdx), basics.AssetCreatable},
	})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	_, err = l.AssetParams(basics.AssetIndex(aidx))
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("asset %d does not exist", aidx))

	c.brs = map[basics.Address]basics.AccountData{
		addr1: {AssetParams: map[basics.AssetIndex]basics.AssetParams{assetIdx: {Total: 1000}}},
	}
	ap, err := l.AssetParams(assetIdx)
	a.NoError(err)
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
	a := require.New(t)

	addr := getRandomAddress(a)
	addr1 := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	assetIdx := basics.AssetIndex(2)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
		{addr1, basics.CreatableIndex(assetIdx), basics.AssetCreatable},
	})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
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
	val, ok, err = l.GetLocal(addr, aidx, "lkey")
	a.NoError(err)
	a.True(ok)
	a.Equal(tv, val)
}

func TestLogicLedgerSetKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	tv := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	err = l.SetGlobal("gkey", tv)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("no store for (%s %d %v) in mock cow", addr, aidx, true))

	tv2 := basics.TealValue{Type: basics.TealUintType, Uint: 2}
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, true}: {"gkey": tv}}
	err = l.SetGlobal("gkey", tv2)
	a.NoError(err)

	// check local
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, false}: {"lkey": tv}}
	err = l.SetLocal(addr, "lkey", tv2)
	a.NoError(err)
}

func TestLogicLedgerDelKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := newCowMock([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	l, err := newLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	err = l.DelGlobal("gkey")
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("no store for (%s %d %v) in mock cow", addr, aidx, true))

	tv := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	c.stores = map[storeLocator]basics.TealKeyValue{{addr, aidx, true}: {"gkey": tv}}
	err = l.DelGlobal("gkey")
	a.NoError(err)

	addr1 := getRandomAddress(a)
	c.stores = map[storeLocator]basics.TealKeyValue{{addr1, aidx, false}: {"lkey": tv}}
	err = l.DelLocal(addr1, "lkey")
	a.NoError(err)
}
