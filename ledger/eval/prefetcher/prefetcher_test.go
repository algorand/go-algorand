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

package prefetcher_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/eval/prefetcher"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func makeAddressPtr(seed int) (o *basics.Address) {
	o = new(basics.Address)
	o[0] = byte(seed)
	o[1] = byte(seed >> 8)
	o[2] = byte(seed >> 16)
	return
}

func makeAddress(addressSeed int) (o basics.Address) {
	t := *makeAddressPtr(addressSeed)
	copy(o[:], t[:])
	return
}

// It would be nice to test current and future, but until that change is made,
// it's better to test future, as that's likely to catch mistakes made while
// developing something new (and likely to catch changes that affect current)
const proto = protocol.ConsensusFuture

type lookupError struct{}

func (le lookupError) Error() string {
	return "lookup error"
}

type assetLookupError struct{}

func (ale assetLookupError) Error() string {
	return "asset lookup error"
}

type getCreatorError struct{}

func (gce getCreatorError) Error() string {
	return "get creator error"
}

type prefetcherTestLedger struct {
	round               basics.Round
	balances            map[basics.Address]ledgercore.AccountData
	creators            map[basics.CreatableIndex]basics.Address
	errorTriggerAddress map[basics.Address]bool
}

const errorTriggerCreatableIndex = 1000001
const errorTriggerAssetIndex = 1000002

func (l *prefetcherTestLedger) BlockHdr(basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, nil
}
func (l *prefetcherTestLedger) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	return nil
}
func (l *prefetcherTestLedger) LookupWithoutRewards(rnd basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	if _, has := l.errorTriggerAddress[addr]; has {
		return ledgercore.AccountData{}, l.round, lookupError{}
	}
	if data, has := l.balances[addr]; has {
		return data, l.round, nil
	}
	return ledgercore.AccountData{}, l.round, nil
}
func (l *prefetcherTestLedger) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	return ledgercore.AppResource{}, nil
}
func (l *prefetcherTestLedger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	if aidx == errorTriggerAssetIndex {
		return ledgercore.AssetResource{}, assetLookupError{}
	}
	return ledgercore.AssetResource{}, nil
}
func (l *prefetcherTestLedger) GetCreatorForRound(_ basics.Round, cidx basics.CreatableIndex, _ basics.CreatableType) (basics.Address, bool, error) {
	if cidx == errorTriggerCreatableIndex {
		return basics.Address{}, false, getCreatorError{}
	}
	if addr, has := l.creators[cidx]; has {
		return addr, true, nil
	}
	return basics.Address{}, false, nil
}
func (l *prefetcherTestLedger) GenesisHash() crypto.Digest {
	return crypto.Digest{}
}
func (l *prefetcherTestLedger) GenesisProto() config.ConsensusParams {
	return config.Consensus[proto]
}
func (l *prefetcherTestLedger) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	return l.round, ledgercore.AccountTotals{}, nil
}
func (l *prefetcherTestLedger) VotersForStateProof(basics.Round) (*ledgercore.VotersForRound, error) {
	return nil, nil
}

type loadedAccountDataEntryKey struct {
	addressExists bool
	address       basics.Address
}

func convertLoadedAccountDataEntries(entries []prefetcher.LoadedAccountDataEntry) map[loadedAccountDataEntryKey]*ledgercore.AccountData {
	res := make(map[loadedAccountDataEntryKey]*ledgercore.AccountData)

	for _, e := range entries {
		var key loadedAccountDataEntryKey
		if e.Address != nil {
			key.addressExists = true
			key.address = *e.Address
		}

		res[key] = e.Data
	}

	return res
}

func compareLoadedAccountDataEntries(t *testing.T, expected []prefetcher.LoadedAccountDataEntry, actual []prefetcher.LoadedAccountDataEntry) {
	expectedForTest := convertLoadedAccountDataEntries(expected)
	actualForTest := convertLoadedAccountDataEntries(actual)
	require.Equal(t, expectedForTest, actualForTest)
}

type loadedResourcesEntryKey struct {
	addressExists  bool
	address        basics.Address
	creatableIndex basics.CreatableIndex
	creatableType  basics.CreatableType
}

func convertLoadedResourcesEntries(entries []prefetcher.LoadedResourcesEntry) map[loadedResourcesEntryKey]*ledgercore.AccountResource {
	res := make(map[loadedResourcesEntryKey]*ledgercore.AccountResource)

	for _, e := range entries {
		key := loadedResourcesEntryKey{
			creatableIndex: e.CreatableIndex,
			creatableType:  e.CreatableType,
		}
		if e.Address != nil {
			key.addressExists = true
			key.address = *e.Address
		}

		res[key] = e.Resource
	}

	return res
}

func compareLoadedResourcesEntries(t *testing.T, expected []prefetcher.LoadedResourcesEntry, actual []prefetcher.LoadedResourcesEntry) {
	expectedForTest := convertLoadedResourcesEntries(expected)
	actualForTest := convertLoadedResourcesEntries(actual)
	require.Equal(t, expectedForTest, actualForTest)
}

func getPrefetcherTestLedger(rnd basics.Round) *prefetcherTestLedger {

	var ledger = &prefetcherTestLedger{
		round:               rnd,
		balances:            make(map[basics.Address]ledgercore.AccountData),
		creators:            make(map[basics.CreatableIndex]basics.Address),
		errorTriggerAddress: make(map[basics.Address]bool),
	}
	ledger.balances[makeAddress(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}
	ledger.creators[1001] = makeAddress(2)
	ledger.creators[2001] = makeAddress(15)

	return ledger
}

func TestEvaluatorPrefetcher(t *testing.T) {
	partitiontest.PartitionTest(t)

	rnd := basics.Round(5)
	var feeSinkAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	ledger := getPrefetcherTestLedger(rnd)
	type testCase struct {
		name      string
		skip      bool
		signedTxn transactions.SignedTxn
		accounts  []prefetcher.LoadedAccountDataEntry
		resources []prefetcher.LoadedResourcesEntry
	}

	testCases := []testCase{
		{
			name: "payment transaction",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender: makeAddress(1),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver:         makeAddress(2),
						CloseRemainderTo: makeAddress(3),
					},
				},
			},
			accounts: []prefetcher.LoadedAccountDataEntry{
				{
					Address: &feeSinkAddr,
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					Address: makeAddressPtr(1),
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
				{
					Address: makeAddressPtr(2),
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					Address: makeAddressPtr(3),
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
			},
		},
		{
			name: "asset config transaction for a non-existing asset",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetConfigTx,
					Header: transactions.Header{
						Sender: makeAddress(1),
					},
					AssetConfigTxnFields: transactions.AssetConfigTxnFields{
						ConfigAsset: 1000,
					},
				},
			},
			accounts: []prefetcher.LoadedAccountDataEntry{
				{
					Address: &feeSinkAddr,
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					Address: makeAddressPtr(1),
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
			},
			resources: []prefetcher.LoadedResourcesEntry{
				{
					Address:        nil,
					CreatableIndex: 1000,
					CreatableType:  basics.AssetCreatable,
					Resource:       nil,
				},
			},
		},
		{
			name: "asset config transaction for an existing asset",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetConfigTx,
					Header: transactions.Header{
						Sender: makeAddress(1),
					},
					AssetConfigTxnFields: transactions.AssetConfigTxnFields{
						ConfigAsset: 1001,
					},
				},
			},
			accounts: []prefetcher.LoadedAccountDataEntry{
				{
					Address: &feeSinkAddr,
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					Address: makeAddressPtr(1),
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
			},
			resources: []prefetcher.LoadedResourcesEntry{
				{
					Address:        makeAddressPtr(2),
					CreatableIndex: 1001,
					CreatableType:  basics.AssetCreatable,
					Resource:       &ledgercore.AccountResource{},
				},
			},
		},
		{
			name: "asset transfer transaction",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetTransferTx,
					Header: transactions.Header{
						Sender: makeAddress(1),
					},
					AssetTransferTxnFields: transactions.AssetTransferTxnFields{
						XferAsset:     1001,
						AssetAmount:   1,
						AssetSender:   makeAddress(2),
						AssetReceiver: makeAddress(3),
						AssetCloseTo:  makeAddress(4),
					},
				},
			},
			accounts: []prefetcher.LoadedAccountDataEntry{
				{
					Address: &feeSinkAddr,
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					Address: makeAddressPtr(1),
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
			},
			resources: []prefetcher.LoadedResourcesEntry{
				{
					Address:        makeAddressPtr(2),
					CreatableIndex: 1001,
					CreatableType:  basics.AssetCreatable,
					Resource:       &ledgercore.AccountResource{},
				},
				{
					Address:        makeAddressPtr(3),
					CreatableIndex: 1001,
					CreatableType:  basics.AssetCreatable,
					Resource:       &ledgercore.AccountResource{},
				},
				{
					Address:        makeAddressPtr(4),
					CreatableIndex: 1001,
					CreatableType:  basics.AssetCreatable,
					Resource:       &ledgercore.AccountResource{},
				},
			},
		},
		{
			name: "asset transfer transaction zero amount",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetTransferTx,
					Header: transactions.Header{
						Sender: makeAddress(1),
					},
					AssetTransferTxnFields: transactions.AssetTransferTxnFields{
						XferAsset:     1001,
						AssetSender:   makeAddress(2),
						AssetReceiver: makeAddress(3),
						AssetCloseTo:  makeAddress(4),
					},
				},
			},
			accounts: []prefetcher.LoadedAccountDataEntry{
				{
					Address: &feeSinkAddr,
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					Address: makeAddressPtr(1),
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
			},
			resources: []prefetcher.LoadedResourcesEntry{
				{
					Address:        makeAddressPtr(2),
					CreatableIndex: 1001,
					CreatableType:  basics.AssetCreatable,
					Resource:       &ledgercore.AccountResource{},
				},
				{
					Address:        makeAddressPtr(4),
					CreatableIndex: 1001,
					CreatableType:  basics.AssetCreatable,
					Resource:       &ledgercore.AccountResource{},
				},
			},
		},
		{
			name: "asset freeze transaction",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetFreezeTx,
					Header: transactions.Header{
						Sender: makeAddress(1),
					},
					AssetFreezeTxnFields: transactions.AssetFreezeTxnFields{
						FreezeAccount: makeAddress(3),
						FreezeAsset:   1001,
					},
				},
			},
			accounts: []prefetcher.LoadedAccountDataEntry{
				{
					Address: &feeSinkAddr,
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					Address: makeAddressPtr(1),
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
				{
					Address: makeAddressPtr(3),
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
			},
			resources: []prefetcher.LoadedResourcesEntry{
				{
					Address:        makeAddressPtr(2),
					CreatableIndex: 1001,
					CreatableType:  basics.AssetCreatable,
					Resource:       &ledgercore.AccountResource{},
				},
				{
					Address:        makeAddressPtr(3),
					CreatableIndex: 1001,
					CreatableType:  basics.AssetCreatable,
					Resource:       &ledgercore.AccountResource{},
				},
			},
		},
		{
			name: "application transaction",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.ApplicationCallTx,
					Header: transactions.Header{
						Sender: makeAddress(1),
					},
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: 10,
						Accounts: []basics.Address{
							makeAddress(4),
							makeAddress(5),
						},
						ForeignApps: []basics.AppIndex{
							2001,
							2002,
						},
						ForeignAssets: []basics.AssetIndex{
							1001,
						},
					},
				},
			},
			accounts: []prefetcher.LoadedAccountDataEntry{
				{
					Address: &feeSinkAddr,
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					Address: makeAddressPtr(1),
					Data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
				/*
					{
						Address: makeAddressPtr(4),
						Data: &ledgercore.AccountData{
							AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
						},
					},
					{
						Address: makeAddressPtr(5),
						Data: &ledgercore.AccountData{
							AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
						},
					},
				*/
			},
			resources: []prefetcher.LoadedResourcesEntry{
				/* - if we'll decide that we want to prefetch the foreign apps/assets, then this should be enabled
				{
					Address:        makeAddressPtr(2),
					CreatableIndex: 1001,
					CreatableType:  basics.AssetCreatable,
					Resource:       &ledgercore.AccountResource{},
				},
				{
					Address:        makeAddressPtr(15),
					CreatableIndex: 2001,
					CreatableType:  basics.AppCreatable,
					Resource:       &ledgercore.AccountResource{},
				},
				{
					Address:        nil,
					CreatableIndex: 2002,
					CreatableType:  basics.AppCreatable,
					Resource:       nil,
				},
				*/
				/* - if we'll decide that we want to prefetch the account local state, then this should be enabled.
				{
					address:        acctAddrPtr(1),
					creatableIndex: 10,
					creatableType:  basics.AppCreatable,
					resource:       &ledgercore.AccountResource{},
				},*/
				{
					Address:        nil,
					CreatableIndex: 10,
					CreatableType:  basics.AppCreatable,
					Resource:       nil,
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.skip {
				t.Skip()
			}
			groups := make([][]transactions.SignedTxnWithAD, 1)
			groups[0] = make([]transactions.SignedTxnWithAD, 1)
			groups[0][0].SignedTxn = testCase.signedTxn

			preloadedTxnGroupsCh := prefetcher.PrefetchAccounts(context.Background(), ledger, rnd, groups, feeSinkAddr, config.Consensus[proto])

			loadedTxnGroup, ok := <-preloadedTxnGroupsCh
			require.True(t, ok)
			require.Nil(t, loadedTxnGroup.Err)
			compareLoadedAccountDataEntries(t, testCase.accounts, loadedTxnGroup.Accounts)
			compareLoadedResourcesEntries(t, testCase.resources, loadedTxnGroup.Resources)

			_, ok = <-preloadedTxnGroupsCh
			require.False(t, ok)
		})
	}
}

// Test for error from LookupAsset
func TestAssetLookupError(t *testing.T) {
	partitiontest.PartitionTest(t)

	rnd := basics.Round(5)
	var feeSinkAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ledger := getPrefetcherTestLedger(rnd)
	assetTransferTxn :=
		transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.AssetTransferTx,
				Header: transactions.Header{
					Sender: makeAddress(1),
				},
				AssetTransferTxnFields: transactions.AssetTransferTxnFields{
					XferAsset:     1001,
					AssetSender:   makeAddress(2),
					AssetReceiver: makeAddress(2),
					AssetCloseTo:  makeAddress(2),
				},
			},
		}

	errorReceived := false
	const numGroups = 5
	const txnPerGroup = 2
	groups := make([][]transactions.SignedTxnWithAD, numGroups)
	for i := 0; i < numGroups; i++ {
		groups[i] = make([]transactions.SignedTxnWithAD, txnPerGroup)
		for j := 0; j < txnPerGroup; j++ {
			groups[i][j].SignedTxn = assetTransferTxn
			if i == 2 {
				// force error in asset lookup in the second txn group only
				groups[i][j].SignedTxn.Txn.AssetTransferTxnFields.XferAsset = errorTriggerAssetIndex
			}
		}
	}

	preloadedTxnGroupsCh := prefetcher.PrefetchAccounts(context.Background(), ledger, rnd+100, groups, feeSinkAddr, config.Consensus[proto])

	receivedNumGroups := 0
	for loadedTxnGroup := range preloadedTxnGroupsCh {
		receivedNumGroups++
		if loadedTxnGroup.Err != nil {
			errorReceived = true
			require.Equal(t, int64(2), loadedTxnGroup.Err.GroupIdx)
			require.ErrorIs(t, loadedTxnGroup.Err, assetLookupError{})
			require.Equal(t, makeAddress(2), *loadedTxnGroup.Err.Address)
			require.Equal(t, errorTriggerAssetIndex, int(loadedTxnGroup.Err.CreatableIndex))
			require.Equal(t, basics.AssetCreatable, loadedTxnGroup.Err.CreatableType)
		}
		require.Equal(t, txnPerGroup, len(loadedTxnGroup.TxnGroup))
	}
	require.True(t, errorReceived)
	require.Equal(t, numGroups, receivedNumGroups)
}

// Test for error from GetCreatorForRound
func TestGetCreatorForRoundError(t *testing.T) {
	partitiontest.PartitionTest(t)

	rnd := basics.Round(5)
	var feeSinkAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ledger := getPrefetcherTestLedger(rnd)

	createAssetTxn :=
		transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.AssetConfigTx,
				Header: transactions.Header{
					Sender: makeAddress(1),
				},
				AssetConfigTxnFields: transactions.AssetConfigTxnFields{
					ConfigAsset: 101,
				},
			},
		}
	createAssetFailedTxn := createAssetTxn
	createAssetFailedTxn.Txn.ConfigAsset = errorTriggerCreatableIndex

	errorReceived := false

	const numGroups = 5
	const txnPerGroup = 10
	groups := make([][]transactions.SignedTxnWithAD, numGroups)
	for i := 0; i < numGroups; i++ {
		groups[i] = make([]transactions.SignedTxnWithAD, txnPerGroup)
		for j := 0; j < txnPerGroup; j++ {
			groups[i][j].SignedTxn = createAssetTxn
			// fail only the first txn in the first group
			if i == 0 && j == 0 {
				groups[i][j].SignedTxn = createAssetFailedTxn
			}
		}
	}
	preloadedTxnGroupsCh := prefetcher.PrefetchAccounts(context.Background(), ledger, rnd+100, groups, feeSinkAddr, config.Consensus[proto])

	receivedNumGroups := 0
	for loadedTxnGroup := range preloadedTxnGroupsCh {
		receivedNumGroups++
		if loadedTxnGroup.Err != nil {
			errorReceived = true
			require.ErrorIs(t, loadedTxnGroup.Err, getCreatorError{})
			require.Nil(t, loadedTxnGroup.Err.Address)
			require.Equal(t, errorTriggerCreatableIndex, int(loadedTxnGroup.Err.CreatableIndex))
			require.Equal(t, basics.AssetCreatable, loadedTxnGroup.Err.CreatableType)
		}
		require.Equal(t, txnPerGroup, len(loadedTxnGroup.TxnGroup))
	}
	require.True(t, errorReceived)
	require.Equal(t, numGroups, receivedNumGroups)
}

// Test for error from LookupWithoutRewards
func TestLookupWithoutRewards(t *testing.T) {
	partitiontest.PartitionTest(t)

	rnd := basics.Round(5)
	var feeSinkAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ledger := getPrefetcherTestLedger(rnd)

	createAssetTxn :=
		transactions.SignedTxn{
			Txn: transactions.Transaction{
				Type: protocol.AssetConfigTx,
				Header: transactions.Header{
					Sender: makeAddress(1),
				},
				AssetConfigTxnFields: transactions.AssetConfigTxnFields{
					ConfigAsset: 1001,
				},
			},
		}
	createAssetFailedTxn := createAssetTxn
	createAssetFailedTxn.Txn.Sender = makeAddress(10)

	errorReceived := false

	const numGroups = 5
	const txnPerGroup = 10
	groups := make([][]transactions.SignedTxnWithAD, numGroups)
	for i := 0; i < numGroups; i++ {
		groups[i] = make([]transactions.SignedTxnWithAD, txnPerGroup)
		for j := 0; j < txnPerGroup; j++ {
			groups[i][j].SignedTxn = createAssetTxn
			// fail only last txn in the first group
			if i == 0 && j == txnPerGroup-1 {
				groups[i][j].SignedTxn = createAssetFailedTxn
			}
		}
	}
	ledger.errorTriggerAddress[createAssetFailedTxn.Txn.Sender] = true
	preloadedTxnGroupsCh := prefetcher.PrefetchAccounts(context.Background(), ledger, rnd+100, groups, feeSinkAddr, config.Consensus[proto])

	receivedNumGroups := 0
	for loadedTxnGroup := range preloadedTxnGroupsCh {
		receivedNumGroups++
		if loadedTxnGroup.Err != nil {
			errorReceived = true
			require.ErrorIs(t, loadedTxnGroup.Err, lookupError{})
			require.Equal(t, makeAddress(10), *loadedTxnGroup.Err.Address)
			require.Equal(t, 0, int(loadedTxnGroup.Err.CreatableIndex))
			require.Equal(t, basics.AssetCreatable, loadedTxnGroup.Err.CreatableType)
		}
		require.Equal(t, txnPerGroup, len(loadedTxnGroup.TxnGroup))
	}
	require.True(t, errorReceived)
	require.Equal(t, numGroups, receivedNumGroups)
}

func TestEvaluatorPrefetcherQueueExpansion(t *testing.T) {
	partitiontest.PartitionTest(t)

	rnd := basics.Round(5)
	var feeSinkAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	var ledger = &prefetcherTestLedger{
		round:    rnd,
		balances: make(map[basics.Address]ledgercore.AccountData),
		creators: make(map[basics.CreatableIndex]basics.Address),
	}
	ledger.balances[makeAddress(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}
	type testTransactionCases struct {
		signedTxn transactions.SignedTxn
		accounts  []prefetcher.LoadedAccountDataEntry
		resources []prefetcher.LoadedResourcesEntry
	}

	txnGroups := make([][]transactions.SignedTxnWithAD, 20000)
	addr := 1
	for i := range txnGroups {
		txnGroups[i] = make([]transactions.SignedTxnWithAD, 16)
		for k := range txnGroups[i] {
			txnGroups[i][k].SignedTxn = transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender: makeAddress(1),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver:         makeAddress(addr),
						CloseRemainderTo: makeAddress(addr + 1),
					},
				},
			}
			addr += 2
		}
	}
	preloadedTxnGroupsCh := prefetcher.PrefetchAccounts(context.Background(), ledger, rnd, txnGroups, feeSinkAddr, config.Consensus[proto])
	groupsCount := 0
	addressCount := 0
	uniqueAccounts := make(map[basics.Address]bool)
	for k := range preloadedTxnGroupsCh {
		addressCount += len(k.Accounts)
		for _, acct := range k.Accounts {
			uniqueAccounts[*acct.Address] = true
		}
		require.Equal(t, txnGroups[groupsCount], k.TxnGroup)
		groupsCount++
	}
	require.Equal(t, len(txnGroups), groupsCount)
	// the +1 below is for the fee sink address.
	require.Equal(t, len(txnGroups)*16*3+1, addressCount)
	require.Equal(t, len(txnGroups)*16*2+1, len(uniqueAccounts))
}

func BenchmarkPrefetcherApps(b *testing.B) {
	txnGroupLen := 16
	groups := make([][]transactions.SignedTxnWithAD, 1+b.N/txnGroupLen)
	for grpIdx := range groups {
		groups[grpIdx] = make([]transactions.SignedTxnWithAD, txnGroupLen)
		for txnIdx := range groups[grpIdx] {
			groups[grpIdx][txnIdx].SignedTxn = transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.ApplicationCallTx,
					Header: transactions.Header{
						Sender: makeAddress(grpIdx + txnIdx),
					},
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: 10,
						Accounts: []basics.Address{
							makeAddress(grpIdx + txnIdx + 1),
							makeAddress(grpIdx + txnIdx + 1),
						},
						ForeignApps: []basics.AppIndex{
							2001,
							2002,
						},
						ForeignAssets: []basics.AssetIndex{
							1001,
						},
					},
				},
			}
		}
	}
	rnd := basics.Round(5)
	var feeSinkAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	var ledger = &prefetcherTestLedger{
		round:    rnd,
		balances: make(map[basics.Address]ledgercore.AccountData),
		creators: make(map[basics.CreatableIndex]basics.Address),
	}
	ledger.balances[makeAddress(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}

	b.ResetTimer()
	preloadedTxnGroupsCh := prefetcher.PrefetchAccounts(context.Background(), ledger, rnd, groups, feeSinkAddr, config.Consensus[proto])
	for k := range preloadedTxnGroupsCh {
		require.NoError(b, k.Err)
	}
}

func BenchmarkPrefetcherPayment(b *testing.B) {
	txnGroupLen := 16
	groups := make([][]transactions.SignedTxnWithAD, 1+b.N/txnGroupLen)
	for grpIdx := range groups {
		groups[grpIdx] = make([]transactions.SignedTxnWithAD, txnGroupLen)
		for txnIdx := range groups[grpIdx] {
			groups[grpIdx][txnIdx].SignedTxn = transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender: makeAddress(grpIdx + txnIdx),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver:         makeAddress(grpIdx + txnIdx + 1),
						CloseRemainderTo: makeAddress(grpIdx + txnIdx + 2),
					},
				},
			}
		}
	}
	rnd := basics.Round(5)
	var feeSinkAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	var ledger = &prefetcherTestLedger{
		round:    rnd,
		balances: make(map[basics.Address]ledgercore.AccountData),
		creators: make(map[basics.CreatableIndex]basics.Address),
	}
	ledger.balances[makeAddress(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}

	b.ResetTimer()
	preloadedTxnGroupsCh := prefetcher.PrefetchAccounts(context.Background(), ledger, rnd, groups, feeSinkAddr, config.Consensus[proto])
	for k := range preloadedTxnGroupsCh {
		require.NoError(b, k.Err)
	}
}
