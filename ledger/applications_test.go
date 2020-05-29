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
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/stretchr/testify/require"
)

type testBalances struct {
	appCreators map[basics.AppIndex]basics.Address
	balances    map[basics.Address]basics.AccountData
}

type testBalancesPass struct {
	testBalances
}

const appIdxError basics.AppIndex = 0x11223344
const appIdxOk basics.AppIndex = 1

func (b *testBalances) Get(addr basics.Address, withPendingRewards bool) (basics.BalanceRecord, error) {
	ad, ok := b.balances[addr]
	if !ok {
		return basics.BalanceRecord{}, fmt.Errorf("mock balance not found")
	}
	return basics.BalanceRecord{Addr: addr, AccountData: ad}, nil
}

func (b *testBalances) Put(record basics.BalanceRecord) error {
	return nil
}

func (b *testBalances) PutWithCreatables(record basics.BalanceRecord, newCreatables []basics.CreatableLocator, deletedCreatables []basics.CreatableLocator) error {
	return nil
}

func (b *testBalances) GetAssetCreator(aidx basics.AssetIndex) (basics.Address, bool, error) {
	return basics.Address{}, false, nil
}

func (b *testBalances) GetAppCreator(aidx basics.AppIndex) (basics.Address, bool, error) {
	if aidx == appIdxError { // magic for test
		return basics.Address{}, false, fmt.Errorf("mock synthetic error")
	}

	creator, ok := b.appCreators[aidx]
	return creator, ok, nil
}

func (b *testBalances) Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards *basics.MicroAlgos, dstRewards *basics.MicroAlgos) error {
	return nil
}

func (b *testBalancesPass) Get(addr basics.Address, withPendingRewards bool) (basics.BalanceRecord, error) {
	ad, ok := b.balances[addr]
	if !ok {
		return basics.BalanceRecord{}, fmt.Errorf("mock balance not found")
	}
	return basics.BalanceRecord{Addr: addr, AccountData: ad}, nil
}

func (b *testBalancesPass) Put(record basics.BalanceRecord) error {
	return nil
}

func (b *testBalancesPass) PutWithCreatables(record basics.BalanceRecord, newCreatables []basics.CreatableLocator, deletedCreatables []basics.CreatableLocator) error {
	return nil
}

func (b *testBalances) ConsensusParams() config.ConsensusParams {
	return config.ConsensusParams{}
}

func getRandomAddress(a *require.Assertions) basics.Address {
	const rl = 16
	b := make([]byte, rl)
	n, err := rand.Read(b)
	a.NoError(err)
	a.Equal(rl, n)

	address := crypto.Hash(b)
	return basics.Address(address)
}

func TestNewAppLedger(t *testing.T) {
	a := require.New(t)

	_, err := newAppLedger(nil, nil, nil, 0, AppTealGlobals{})
	a.Error(err)
	a.Contains(err.Error(), "nil balances")

	b := testBalances{}
	_, err = newAppLedger(&b, nil, nil, 0, AppTealGlobals{})
	a.Error(err)
	a.Contains(err.Error(), "should at least include txn sender")

	acc := []basics.Address{getRandomAddress(a)}
	_, err = newAppLedger(&b, acc, nil, 0, AppTealGlobals{})
	a.Error(err)
	a.Contains(err.Error(), "should at least include this appIdx")

	app := []basics.AppIndex{0}
	_, err = newAppLedger(&b, acc, app, 0, AppTealGlobals{})
	a.Error(err)
	a.Contains(err.Error(), "cannot create appLedger for appIdx 0")

	appIdx := basics.AppIndex(1)
	_, err = newAppLedger(&b, acc, app, appIdx, AppTealGlobals{})
	a.Error(err)
	a.Contains(err.Error(), "cannot whitelist appIdx 0")

	app = []basics.AppIndex{1}
	l, err := newAppLedger(&b, acc, app, appIdx, AppTealGlobals{})
	a.NoError(err)
	a.NotNil(l)
	a.Equal(appIdx, l.appIdx)
	a.NotNil(l.balances)
	a.Equal(1, len(l.addresses))
	a.Equal(1, len(l.apps))

	dl, err := MakeDebugAppLedger(&b, acc, app, appIdx, AppTealGlobals{})
	a.NoError(err)
	a.NotNil(dl)
}

func TestAppLedgerBalances(t *testing.T) {
	a := require.New(t)

	b := testBalances{}
	addr1 := getRandomAddress(a)
	addr2 := getRandomAddress(a)
	acc := []basics.Address{addr1}
	app := []basics.AppIndex{appIdxOk}
	appIdx := appIdxOk

	l, err := newAppLedger(&b, acc, app, appIdx, AppTealGlobals{})
	a.NoError(err)
	a.NotNil(l)

	_, err = l.Balance(addr2)
	a.Error(err)
	a.Contains(err.Error(), "not sender or in txn.Addresses")

	_, err = l.Balance(addr1)
	a.Error(err)
	a.NotContains(err.Error(), "not sender or in txn.Addresses")

	ble := basics.MicroAlgos{Raw: 100}
	b.balances = map[basics.Address]basics.AccountData{addr1: {MicroAlgos: ble}}
	bla, err := l.Balance(addr1)
	a.NoError(err)
	a.Equal(ble, bla)
}

func TestAppLedgerGetters(t *testing.T) {
	a := require.New(t)

	b := testBalances{}
	addr1 := getRandomAddress(a)
	acc := []basics.Address{addr1}
	app := []basics.AppIndex{appIdxOk}
	appIdx := appIdxOk
	round := basics.Round(1234)
	ts := int64(11223344)
	globals := AppTealGlobals{round, ts}

	l, err := newAppLedger(&b, acc, app, appIdx, globals)
	a.NoError(err)
	a.NotNil(l)

	a.Equal(appIdx, l.ApplicationID())
	a.Equal(round, l.Round())
	a.Equal(ts, l.LatestTimestamp())

	// check there no references/pointers
	globals = AppTealGlobals{101, 102}
	a.Equal(round, l.Round())
	a.Equal(ts, l.LatestTimestamp())
}

func TestAppLedgerAsset(t *testing.T) {
	a := require.New(t)

	b := testBalances{}
	addr1 := getRandomAddress(a)
	addr2 := getRandomAddress(a)
	acc := []basics.Address{addr1}
	app := []basics.AppIndex{appIdxOk}
	appIdx := appIdxOk

	l, err := newAppLedger(&b, acc, app, appIdx, AppTealGlobals{})
	a.NoError(err)
	a.NotNil(l)

	assetIdx := basics.AssetIndex(2)
	_, err = l.AssetParams(addr2, assetIdx)
	a.Error(err)
	a.Contains(err.Error(), "not sender or in txn.Addresses")

	_, err = l.AssetParams(addr1, assetIdx)
	a.Error(err)
	a.NotContains(err.Error(), "not sender or in txn.Addresses")

	b.balances = map[basics.Address]basics.AccountData{addr1: {}}
	_, err = l.AssetParams(addr1, assetIdx)
	a.Error(err)
	a.Contains(err.Error(), "has not created asset")

	b.balances[addr1] = basics.AccountData{
		AssetParams: map[basics.AssetIndex]basics.AssetParams{assetIdx: {Total: 1000}},
	}
	ap, err := l.AssetParams(addr1, assetIdx)
	a.NoError(err)
	a.Equal(uint64(1000), ap.Total)
	delete(b.balances, addr1)

	_, err = l.AssetHolding(addr2, assetIdx)
	a.Error(err)
	a.Contains(err.Error(), "not sender or in txn.Addresses")

	_, err = l.AssetHolding(addr1, assetIdx)
	a.Error(err)
	a.NotContains(err.Error(), "not sender or in txn.Addresses")

	b.balances = map[basics.Address]basics.AccountData{addr1: {}}
	_, err = l.AssetHolding(addr1, assetIdx)
	a.Error(err)
	a.Contains(err.Error(), "has not opted in to asset")

	b.balances[addr1] = basics.AccountData{
		Assets: map[basics.AssetIndex]basics.AssetHolding{assetIdx: {Amount: 99}},
	}
	ah, err := l.AssetHolding(addr1, assetIdx)
	a.NoError(err)
	a.Equal(uint64(99), ah.Amount)
}

func TestAppLedgerAppGlobalState(t *testing.T) {
	a := require.New(t)

	b := testBalances{}
	addr1 := getRandomAddress(a)
	acc := []basics.Address{addr1}
	app := []basics.AppIndex{appIdxOk, appIdxError}
	appIdx := appIdxOk

	l, err := newAppLedger(&b, acc, app, appIdx, AppTealGlobals{})
	a.NoError(err)
	a.NotNil(l)

	_, err = l.AppGlobalState(2)
	a.Error(err)
	a.Contains(err.Error(), "cannot access global state")

	_, err = l.AppGlobalState(appIdx)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("app %d does not exist", appIdx))

	_, err = l.AppGlobalState(0)
	a.Error(err)
	a.Contains(err.Error(), fmt.Sprintf("app %d does not exist", appIdx))

	_, err = l.AppGlobalState(appIdxError)
	a.Error(err)
	a.NotContains(err.Error(), "cannot access global state")
	a.NotContains(err.Error(), fmt.Sprintf("app %d does not exist", appIdxError))

	b.appCreators = map[basics.AppIndex]basics.Address{appIdx: addr1}
	_, err = l.AppGlobalState(appIdx)
	a.Error(err)
	a.NotContains(err.Error(), fmt.Sprintf("app %d does not exist", appIdx))

	b.balances = map[basics.Address]basics.AccountData{addr1: {}}
	_, err = l.AppGlobalState(appIdx)
	a.Error(err)
	a.Contains(err.Error(), "not found in account")

	b.balances[addr1] = basics.AccountData{AppParams: map[basics.AppIndex]basics.AppParams{appIdx: {}}}
	kv, err := l.AppGlobalState(appIdx)
	a.NoError(err)
	a.NotNil(kv)
}

func TestAppLedgerAppLocalState(t *testing.T) {
	a := require.New(t)

	b := testBalances{}
	addr1 := getRandomAddress(a)
	addr2 := getRandomAddress(a)
	acc := []basics.Address{addr1}
	app := []basics.AppIndex{appIdxOk, appIdxError}
	appIdx := basics.AppIndex(100) // not in app

	l, err := newAppLedger(&b, acc, app, appIdx, AppTealGlobals{})
	a.NoError(err)
	a.NotNil(l)

	_, err = l.AppLocalState(addr2, appIdx)
	a.Error(err)
	a.Contains(err.Error(), "cannot access local state")

	_, err = l.AppLocalState(addr1, appIdx)
	a.Error(err)
	a.NotContains(err.Error(), "cannot access global state")

	b.balances = map[basics.Address]basics.AccountData{addr1: {}}
	_, err = l.AppLocalState(addr1, appIdx)
	a.Error(err)
	a.Contains(err.Error(), "not opted in to app")

	b.balances[addr1] = basics.AccountData{AppLocalStates: map[basics.AppIndex]basics.AppLocalState{appIdx: {}}}
	kv, err := l.AppLocalState(addr1, appIdx)
	a.NoError(err)
	a.NotNil(kv)
}
