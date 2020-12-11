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
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
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

type modsData struct {
	addr  basics.Address
	cidx  basics.CreatableIndex
	ctype basics.CreatableType
}

func getCow(creatables []modsData) *roundCowState {
	cs := &roundCowState{
		mods: StateDelta{
			creatables: make(map[basics.CreatableIndex]modifiedCreatable),
			hdr:        &bookkeeping.BlockHeader{},
		},
		proto: config.Consensus[protocol.ConsensusCurrentVersion],
	}
	for _, e := range creatables {
		cs.mods.creatables[e.cidx] = modifiedCreatable{ctype: e.ctype, creator: e.addr, created: true}
	}
	return cs
}

func TestLogicLedgerMake(t *testing.T) {
	a := require.New(t)

	_, err := makeLogicLedger(nil, 0)
	a.Error(err)
	a.Contains(err.Error(), "cannot make logic ledger for app index 0")

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})

	_, err = makeLogicLedger(c, 0)
	a.Error(err)
	a.Contains(err.Error(), "cannot make logic ledger for app index 0")

	l, err := makeLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)
	a.Equal(aidx, l.aidx)
	a.Equal(c, l.cow)
}

func TestLogicLedgerBalances(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})
	l, err := makeLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	addr1 := getRandomAddress(a)
	ble := basics.MicroAlgos{Raw: 100}
	c.mods.accts = map[basics.Address]accountDelta{addr1: {new: basics.AccountData{MicroAlgos: ble}}}
	bla, err := l.Balance(addr1)
	a.NoError(err)
	a.Equal(ble, bla)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { l.Balance(getRandomAddress(a)) })
}

func TestLogicLedgerGetters(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{{addr, basics.CreatableIndex(aidx), basics.AppCreatable}})
	l, err := makeLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	round := basics.Round(1234)
	c.mods.hdr.Round = round
	ts := int64(11223344)
	c.mods.prevTimestamp = ts

	addr1 := getRandomAddress(a)
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr1: {storagePtr{aidx, false}: &storageDelta{action: allocAction}},
	}

	a.Equal(aidx, l.ApplicationID())
	a.Equal(round, l.Round())
	a.Equal(ts, l.LatestTimestamp())
	a.True(l.OptedIn(addr1, aidx))

	// ensure other requests go down to roundCowParent
	a.Panics(func() { l.OptedIn(getRandomAddress(a), aidx) })
}

func TestLogicLedgerAsset(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	addr1 := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	assetIdx := basics.AssetIndex(2)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
		{addr1, basics.CreatableIndex(assetIdx), basics.AssetCreatable},
	})
	l, err := makeLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	_, err = l.AssetParams(basics.AssetIndex(aidx))
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("asset %d does not exist", aidx))

	c.mods.accts = map[basics.Address]accountDelta{
		addr1: {
			new: basics.AccountData{
				AssetParams: map[basics.AssetIndex]basics.AssetParams{assetIdx: {Total: 1000}},
			},
		},
	}
	ap, err := l.AssetParams(assetIdx)
	a.NoError(err)
	a.Equal(uint64(1000), ap.Total)

	_, err = l.AssetHolding(addr1, assetIdx)
	a.Error(err)
	a.Contains(err.Error(), "has not opted in to asset")

	c.mods.accts = map[basics.Address]accountDelta{
		addr1: {
			new: basics.AccountData{
				AssetParams: map[basics.AssetIndex]basics.AssetParams{assetIdx: {Total: 1000}},
				Assets:      map[basics.AssetIndex]basics.AssetHolding{assetIdx: {Amount: 99}},
			},
		},
	}

	ah, err := l.AssetHolding(addr1, assetIdx)
	a.NoError(err)
	a.Equal(uint64(99), ah.Amount)

	// ensure other requests go down to roundCowParent
	a.Panics(func() { l.AssetHolding(getRandomAddress(a), assetIdx) })
	a.Panics(func() { l.AssetParams(assetIdx + 1) })
}

func TestLogicLedgerGetKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	addr1 := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	assetIdx := basics.AssetIndex(2)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
		{addr1, basics.CreatableIndex(assetIdx), basics.AssetCreatable},
	})
	l, err := makeLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	_, ok, err := l.GetGlobal(basics.AppIndex(assetIdx), "gkey")
	a.Error(err)
	a.False(ok)
	a.Contains(err.Error(), fmt.Sprintf("app %d does not exist", assetIdx))

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: deallocAction}},
	}
	_, ok, err = l.GetGlobal(aidx, "gkey")
	a.Error(err)
	a.False(ok)
	a.Contains(err.Error(), "cannot fetch key")

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: allocAction}},
	}
	_, ok, err = l.GetGlobal(aidx, "gkey")
	a.NoError(err)
	a.False(ok)
	_, ok, err = l.GetGlobal(0, "gkey")
	a.NoError(err)
	a.False(ok)

	tv := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action: allocAction,
				kvCow:  stateDelta{"gkey": valueDelta{new: tv, newExists: false}},
			},
		},
	}
	val, ok, err := l.GetGlobal(aidx, "gkey")
	a.NoError(err)
	a.False(ok)

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action: allocAction,
				kvCow:  stateDelta{"gkey": valueDelta{new: tv, newExists: true}},
			},
		},
	}
	val, ok, err = l.GetGlobal(aidx, "gkey")
	a.NoError(err)
	a.True(ok)
	a.Equal(tv, val)

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action: remainAllocAction,
				kvCow:  stateDelta{"gkey": valueDelta{new: tv, newExists: true}},
			},
		},
	}

	// check local
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, false}: &storageDelta{
				action: allocAction,
				kvCow:  stateDelta{"lkey": valueDelta{new: tv, newExists: true}},
			},
		},
	}

	val, ok, err = l.GetLocal(addr, aidx, "lkey")
	a.NoError(err)
	a.True(ok)
	a.Equal(tv, val)
}

func TestLogicLedgerSetKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	l, err := makeLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	key := strings.Repeat("key", 100)
	val := "val"
	tv := basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err = l.SetGlobal(key, tv)
	a.Error(err)
	a.Contains(err.Error(), "key too long")

	key = "key"
	val = strings.Repeat("val", 100)
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	err = l.SetGlobal(key, tv)
	a.Error(err)
	a.Contains(err.Error(), "value too long")

	val = "val"
	tv = basics.TealValue{Type: basics.TealBytesType, Bytes: val}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: deallocAction}},
	}
	err = l.SetGlobal(key, tv)
	a.Error(err)
	a.Contains(err.Error(), "cannot set key")

	counts := basics.StateSchema{}
	maxCounts := basics.StateSchema{}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action:    allocAction,
				kvCow:     make(stateDelta),
				counts:    &counts,
				maxCounts: &maxCounts,
			},
		},
	}
	err = l.SetGlobal(key, tv)
	a.Error(err)
	a.Contains(err.Error(), "exceeds schema bytes")

	counts = basics.StateSchema{NumUint: 1}
	maxCounts = basics.StateSchema{NumByteSlice: 1}
	err = l.SetGlobal(key, tv)
	a.Error(err)
	a.Contains(err.Error(), "exceeds schema integer")

	tv2 := basics.TealValue{Type: basics.TealUintType, Uint: 1}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action:    allocAction,
				kvCow:     stateDelta{key: valueDelta{new: tv2, newExists: true}},
				counts:    &counts,
				maxCounts: &maxCounts,
			},
		},
	}
	err = l.SetGlobal(key, tv)
	a.NoError(err)

	counts = basics.StateSchema{NumUint: 1}
	maxCounts = basics.StateSchema{NumByteSlice: 1, NumUint: 1}
	err = l.SetGlobal(key, tv)
	a.NoError(err)

	// check local
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, false}: &storageDelta{
				action:    allocAction,
				kvCow:     stateDelta{key: valueDelta{new: tv2, newExists: true}},
				counts:    &counts,
				maxCounts: &maxCounts,
			},
		},
	}
	err = l.SetLocal(addr, key, tv)
	a.NoError(err)
}

func TestLogicLedgerDelKey(t *testing.T) {
	a := require.New(t)

	addr := getRandomAddress(a)
	aidx := basics.AppIndex(1)
	c := getCow([]modsData{
		{addr, basics.CreatableIndex(aidx), basics.AppCreatable},
	})
	l, err := makeLogicLedger(c, aidx)
	a.NoError(err)
	a.NotNil(l)

	key := "key"
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {storagePtr{aidx, true}: &storageDelta{action: deallocAction}},
	}
	err = l.DelGlobal(key)
	a.Error(err)
	a.Contains(err.Error(), "cannot del key")

	counts := basics.StateSchema{}
	maxCounts := basics.StateSchema{}
	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, true}: &storageDelta{
				action:    allocAction,
				kvCow:     make(stateDelta),
				counts:    &counts,
				maxCounts: &maxCounts,
			},
		},
	}
	err = l.DelGlobal(key)
	a.NoError(err)

	c.sdeltas = map[basics.Address]map[storagePtr]*storageDelta{
		addr: {
			storagePtr{aidx, false}: &storageDelta{
				action:    allocAction,
				kvCow:     make(stateDelta),
				counts:    &counts,
				maxCounts: &maxCounts,
			},
		},
	}
	err = l.DelLocal(addr, key)
	a.NoError(err)
}
