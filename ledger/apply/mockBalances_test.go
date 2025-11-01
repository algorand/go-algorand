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

package apply

import (
	"fmt"
	"maps"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

type mockBalances struct {
	protocol.ConsensusVersion
	b map[basics.Address]basics.AccountData
	mockCreatableBalances
}

// makeMockBalances takes a ConsensusVersion and returns a mocked balances with an Address to AccountData map
func makeMockBalances(cv protocol.ConsensusVersion) *mockBalances {
	ret := &mockBalances{
		ConsensusVersion: cv,
		b:                map[basics.Address]basics.AccountData{},
	}
	ret.mockCreatableBalances = mockCreatableBalances{access: ret}
	return ret
}

// makeMockBalancesWithAccounts takes a ConsensusVersion and a map of Address to AccountData and returns a mocked
// balances.
func makeMockBalancesWithAccounts(cv protocol.ConsensusVersion, b map[basics.Address]basics.AccountData) *mockBalances {
	ret := &mockBalances{
		ConsensusVersion: cv,
		b:                b,
	}
	ret.mockCreatableBalances = mockCreatableBalances{access: ret}
	return ret
}

func (balances mockBalances) Round() basics.Round {
	return basics.Round(8675309)
}

func (balances mockBalances) AllocateApp(basics.Address, basics.AppIndex, bool, basics.StateSchema) error {
	return nil
}

func (balances mockBalances) DeallocateApp(basics.Address, basics.AppIndex, bool) error {
	return nil
}

func (balances mockBalances) AllocateAsset(addr basics.Address, index basics.AssetIndex, global bool) error {
	return nil
}

func (balances mockBalances) DeallocateAsset(addr basics.Address, index basics.AssetIndex, global bool) error {
	return nil
}

func (balances mockBalances) StatefulEval(int, *logic.EvalParams, basics.AppIndex, []byte) (bool, transactions.EvalDelta, error) {
	return false, transactions.EvalDelta{}, nil
}

func (balances mockBalances) Get(addr basics.Address, withPendingRewards bool) (ledgercore.AccountData, error) {
	acct, err := balances.getAccount(addr, withPendingRewards)
	return ledgercore.ToAccountData(acct), err
}

func (balances mockBalances) getAccount(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	return balances.b[addr], nil
}

func (balances mockBalances) GetCreator(idx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return basics.Address{}, true, nil
}

func (balances mockBalances) Put(addr basics.Address, acct ledgercore.AccountData) error {
	a := balances.b[addr]
	ledgercore.AssignAccountData(&a, acct)
	return balances.putAccount(addr, a)
}

func (balances mockBalances) putAccount(addr basics.Address, ad basics.AccountData) error {
	balances.b[addr] = ad
	return nil
}

func (balances mockBalances) CloseAccount(addr basics.Address) error {
	return balances.putAccount(addr, basics.AccountData{})
}

func (balances mockBalances) Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards, dstRewards *basics.MicroAlgos) error {
	return nil
}

func (balances mockBalances) ConsensusParams() config.ConsensusParams {
	return config.Consensus[balances.ConsensusVersion]
}

// mockCreatableBalances provides extra creatable access methods for the
// testBalances, testBalancesPass, and mockBalances implementations of apply.Balances
type mockCreatableBalances struct {
	access accountDataAccessor

	putAppParams, deleteAppParams         int
	putAppLocalState, deleteAppLocalState int
	putAssetHolding, deleteAssetHolding   int
	putAssetParams, deleteAssetParams     int
}

type accountDataAccessor interface {
	putAccount(addr basics.Address, ad basics.AccountData) error
	getAccount(addr basics.Address, withRewards bool) (basics.AccountData, error)
}

func (b *mockCreatableBalances) GetAppParams(addr basics.Address, aidx basics.AppIndex) (ret basics.AppParams, ok bool, err error) {
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return
	}
	ret, ok = acct.AppParams[aidx]
	return
}
func (b *mockCreatableBalances) GetAppLocalState(addr basics.Address, aidx basics.AppIndex) (ret basics.AppLocalState, ok bool, err error) {
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return
	}
	ret, ok = acct.AppLocalStates[aidx]
	return
}

// SetAppGlobalSchema is supposed set the running schema limits in the
// evaluation, but the mockCreatableBalances does not enforce those limits.
func (b *mockCreatableBalances) SetAppGlobalSchema(addr basics.Address, aidx basics.AppIndex, limits basics.StateSchema) error {
	return nil
}

func (b *mockCreatableBalances) GetAssetHolding(addr basics.Address, aidx basics.AssetIndex) (ret basics.AssetHolding, ok bool, err error) {
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return
	}
	ret, ok = acct.Assets[aidx]
	return
}
func (b *mockCreatableBalances) GetAssetParams(addr basics.Address, aidx basics.AssetIndex) (ret basics.AssetParams, ok bool, err error) {
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return
	}
	ret, ok = acct.AssetParams[aidx]
	return
}

// mapWith returns a new map with the given key and value added to it.
// maps.Clone would keep nil inputs as nil, so we make() then map.Copy().
func mapWith[M ~map[K]V, K comparable, V any](m M, k K, v V) M {
	newMap := make(M, len(m)+1)
	maps.Copy(newMap, m)
	newMap[k] = v
	return newMap
}

func (b *mockCreatableBalances) PutAppParams(addr basics.Address, aidx basics.AppIndex, params basics.AppParams) error {
	b.putAppParams++
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return err
	}
	acct.AppParams = mapWith(acct.AppParams, aidx, params)
	return b.access.putAccount(addr, acct)
}
func (b *mockCreatableBalances) PutAppLocalState(addr basics.Address, aidx basics.AppIndex, state basics.AppLocalState) error {
	b.putAppLocalState++
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return err
	}
	acct.AppLocalStates = mapWith(acct.AppLocalStates, aidx, state)
	return b.access.putAccount(addr, acct)
}
func (b *mockCreatableBalances) PutAssetHolding(addr basics.Address, aidx basics.AssetIndex, data basics.AssetHolding) error {
	b.putAssetHolding++
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return err
	}
	acct.Assets = mapWith(acct.Assets, aidx, data)
	return b.access.putAccount(addr, acct)
}
func (b *mockCreatableBalances) PutAssetParams(addr basics.Address, aidx basics.AssetIndex, data basics.AssetParams) error {
	b.putAssetParams++
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return err
	}
	acct.AssetParams = mapWith(acct.AssetParams, aidx, data)
	return b.access.putAccount(addr, acct)
}

func (b *mockCreatableBalances) DeleteAppParams(addr basics.Address, aidx basics.AppIndex) error {
	b.deleteAppParams++
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return err
	}
	m := maps.Clone(acct.AppParams)
	delete(m, aidx)
	acct.AppParams = m
	return b.access.putAccount(addr, acct)
}
func (b *mockCreatableBalances) DeleteAppLocalState(addr basics.Address, aidx basics.AppIndex) error {
	b.deleteAppLocalState++
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return err
	}
	m := maps.Clone(acct.AppLocalStates)
	delete(m, aidx)
	acct.AppLocalStates = m
	return b.access.putAccount(addr, acct)
}
func (b *mockCreatableBalances) DeleteAssetHolding(addr basics.Address, aidx basics.AssetIndex) error {
	b.deleteAssetHolding++
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return err
	}
	m := maps.Clone(acct.Assets)
	delete(m, aidx)
	acct.Assets = m
	return b.access.putAccount(addr, acct)
}
func (b *mockCreatableBalances) DeleteAssetParams(addr basics.Address, aidx basics.AssetIndex) error {
	b.deleteAssetParams++
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return err
	}
	m := maps.Clone(acct.AssetParams)
	delete(m, aidx)
	acct.AssetParams = m
	return b.access.putAccount(addr, acct)
}

func (b *mockCreatableBalances) HasAppLocalState(addr basics.Address, aidx basics.AppIndex) (ok bool, err error) {
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return
	}
	_, ok = acct.AppLocalStates[aidx]
	return
}

func (b *mockCreatableBalances) HasAssetParams(addr basics.Address, aidx basics.AssetIndex) (ok bool, err error) {
	acct, err := b.access.getAccount(addr, false)
	if err != nil {
		return
	}
	_, ok = acct.AssetParams[aidx]
	return
}

type mockHeaders struct {
	perRound map[basics.Round]bookkeeping.BlockHeader
	fallback *bookkeeping.BlockHeader
}

// makeMockHeaders takes a bunch of BlockHeaders and returns a HdrProivder for them.
func makeMockHeaders(hdrs ...bookkeeping.BlockHeader) mockHeaders {
	b := make(map[basics.Round]bookkeeping.BlockHeader)
	for _, hdr := range hdrs {
		b[hdr.Round] = hdr
	}
	return mockHeaders{perRound: b}
}

func (m mockHeaders) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	if hdr, ok := m.perRound[r]; ok {
		return hdr, nil
	}
	if m.fallback != nil {
		copy := *m.fallback
		copy.Round = r
		return copy, nil
	}
	return bookkeeping.BlockHeader{}, fmt.Errorf("round %v is not present", r)
}

func (m *mockHeaders) setFallback(hdr bookkeeping.BlockHeader) {
	m.fallback = &hdr
}
