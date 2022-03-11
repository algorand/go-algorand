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
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func makeTestingAddressPtr(addressSeed int) (o *basics.Address) {
	o = new(basics.Address)
	o[0] = byte(addressSeed)
	o[1] = byte(addressSeed >> 8)
	o[2] = byte(addressSeed >> 16)
	return
}

func makeTestingAddress(addressSeed int) (o basics.Address) {
	t := *makeTestingAddressPtr(addressSeed)
	copy(o[:], t[:])
	return
}

const proto = protocol.ConsensusCurrentVersion

type prefetcherTestLedger struct {
	round    basics.Round
	balances map[basics.Address]ledgercore.AccountData
	creators map[basics.CreatableIndex]basics.Address
}

func (l *prefetcherTestLedger) BlockHdr(basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, nil
}
func (l *prefetcherTestLedger) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	return nil
}
func (l *prefetcherTestLedger) LookupWithoutRewards(_ basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	if data, has := l.balances[addr]; has {
		return data, l.round, nil
	}
	return ledgercore.AccountData{}, l.round, nil
}
func (l *prefetcherTestLedger) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	return ledgercore.AppResource{}, nil
}
func (l *prefetcherTestLedger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	return ledgercore.AssetResource{}, nil
}
func (l *prefetcherTestLedger) GetCreatorForRound(_ basics.Round, cidx basics.CreatableIndex, _ basics.CreatableType) (basics.Address, bool, error) {
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
func (l *prefetcherTestLedger) CompactCertVoters(basics.Round) (*ledgercore.VotersForRound, error) {
	return nil, nil
}

type loadedAccountDataEntryKey struct {
	addressExists bool
	address       basics.Address
}

func convertLoadedAccountDataEntries(entries []loadedAccountDataEntry) map[loadedAccountDataEntryKey]*ledgercore.AccountData {
	res := make(map[loadedAccountDataEntryKey]*ledgercore.AccountData)

	for _, e := range entries {
		var key loadedAccountDataEntryKey
		if e.address != nil {
			key.addressExists = true
			key.address = *e.address
		}

		res[key] = e.data
	}

	return res
}

func compareLoadedAccountDataEntries(t *testing.T, expected []loadedAccountDataEntry, actual []loadedAccountDataEntry) {
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

func convertLoadedResourcesEntries(entries []loadedResourcesEntry) map[loadedResourcesEntryKey]*ledgercore.AccountResource {
	res := make(map[loadedResourcesEntryKey]*ledgercore.AccountResource)

	for _, e := range entries {
		key := loadedResourcesEntryKey{
			creatableIndex: e.creatableIndex,
			creatableType:  e.creatableType,
		}
		if e.address != nil {
			key.addressExists = true
			key.address = *e.address
		}

		res[key] = e.resource
	}

	return res
}

func compareLoadedResourcesEntries(t *testing.T, expected []loadedResourcesEntry, actual []loadedResourcesEntry) {
	expectedForTest := convertLoadedResourcesEntries(expected)
	actualForTest := convertLoadedResourcesEntries(actual)
	require.Equal(t, expectedForTest, actualForTest)
}

func TestEvaluatorPrefetcher(t *testing.T) {
	partitiontest.PartitionTest(t)

	rnd := basics.Round(5)
	var feeSinkAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	var ledger = &prefetcherTestLedger{
		round:    rnd,
		balances: make(map[basics.Address]ledgercore.AccountData),
		creators: make(map[basics.CreatableIndex]basics.Address),
	}
	ledger.balances[makeTestingAddress(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}
	ledger.creators[1001] = makeTestingAddress(2)
	ledger.creators[2001] = makeTestingAddress(15)

	type testCase struct {
		name      string
		signedTxn transactions.SignedTxn
		accounts  []loadedAccountDataEntry
		resources []loadedResourcesEntry
	}

	testCases := []testCase{
		{
			name: "payment transaction",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender: makeTestingAddress(1),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver:         makeTestingAddress(2),
						CloseRemainderTo: makeTestingAddress(3),
					},
				},
			},
			accounts: []loadedAccountDataEntry{
				{
					address: &feeSinkAddr,
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: makeTestingAddressPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
				{
					address: makeTestingAddressPtr(2),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: makeTestingAddressPtr(3),
					data: &ledgercore.AccountData{
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
						Sender: makeTestingAddress(1),
					},
					AssetConfigTxnFields: transactions.AssetConfigTxnFields{
						ConfigAsset: 1000,
					},
				},
			},
			accounts: []loadedAccountDataEntry{
				{
					address: &feeSinkAddr,
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: makeTestingAddressPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
			},
			resources: []loadedResourcesEntry{
				{
					address:        nil,
					creatableIndex: 1000,
					creatableType:  basics.AssetCreatable,
					resource:       nil,
				},
			},
		},
		{
			name: "asset config transaction for an existing asset",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetConfigTx,
					Header: transactions.Header{
						Sender: makeTestingAddress(1),
					},
					AssetConfigTxnFields: transactions.AssetConfigTxnFields{
						ConfigAsset: 1001,
					},
				},
			},
			accounts: []loadedAccountDataEntry{
				{
					address: &feeSinkAddr,
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: makeTestingAddressPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
			},
			resources: []loadedResourcesEntry{
				{
					address:        makeTestingAddressPtr(2),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
			},
		},
		{
			name: "asset transfer transaction",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetTransferTx,
					Header: transactions.Header{
						Sender: makeTestingAddress(1),
					},
					AssetTransferTxnFields: transactions.AssetTransferTxnFields{
						XferAsset:     1001,
						AssetSender:   makeTestingAddress(2),
						AssetReceiver: makeTestingAddress(3),
						AssetCloseTo:  makeTestingAddress(4),
					},
				},
			},
			accounts: []loadedAccountDataEntry{
				{
					address: &feeSinkAddr,
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: makeTestingAddressPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
			},
			resources: []loadedResourcesEntry{
				{
					address:        makeTestingAddressPtr(2),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
				{
					address:        makeTestingAddressPtr(3),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
				{
					address:        makeTestingAddressPtr(4),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
			},
		},
		{
			name: "asset freeze transaction",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetFreezeTx,
					Header: transactions.Header{
						Sender: makeTestingAddress(1),
					},
					AssetFreezeTxnFields: transactions.AssetFreezeTxnFields{
						FreezeAccount: makeTestingAddress(3),
						FreezeAsset:   1001,
					},
				},
			},
			accounts: []loadedAccountDataEntry{
				{
					address: &feeSinkAddr,
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: makeTestingAddressPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
				{
					address: makeTestingAddressPtr(3),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
			},
			resources: []loadedResourcesEntry{
				{
					address:        makeTestingAddressPtr(2),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
				{
					address:        makeTestingAddressPtr(3),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
			},
		},
		{
			name: "application transaction",
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.ApplicationCallTx,
					Header: transactions.Header{
						Sender: makeTestingAddress(1),
					},
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: 10,
						Accounts: []basics.Address{
							makeTestingAddress(4),
							makeTestingAddress(5),
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
			accounts: []loadedAccountDataEntry{
				{
					address: &feeSinkAddr,
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: makeTestingAddressPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
				{
					address: makeTestingAddressPtr(4),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: makeTestingAddressPtr(5),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
			},
			resources: []loadedResourcesEntry{
				{
					address:        makeTestingAddressPtr(2),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
				{
					address:        makeTestingAddressPtr(15),
					creatableIndex: 2001,
					creatableType:  basics.AppCreatable,
					resource:       &ledgercore.AccountResource{},
				},
				{
					address:        nil,
					creatableIndex: 2002,
					creatableType:  basics.AppCreatable,
					resource:       nil,
				},
				/* - if we'll decide that we want to perfetch the account local state, then this should be enabled.
				{
					address:        acctAddrPtr(1),
					creatableIndex: 10,
					creatableType:  basics.AppCreatable,
					resource:       &ledgercore.AccountResource{},
				},*/
				{
					address:        nil,
					creatableIndex: 10,
					creatableType:  basics.AppCreatable,
					resource:       nil,
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			groups := make([][]transactions.SignedTxnWithAD, 1)
			groups[0] = make([]transactions.SignedTxnWithAD, 1)
			groups[0][0].SignedTxn = testCase.signedTxn

			preloadedTxnGroupsCh := prefetchAccounts(context.Background(), ledger, rnd, groups, feeSinkAddr, config.Consensus[proto])

			loadedTxnGroup, ok := <-preloadedTxnGroupsCh
			require.True(t, ok)
			require.NoError(t, loadedTxnGroup.err)
			compareLoadedAccountDataEntries(t, testCase.accounts, loadedTxnGroup.accounts)
			compareLoadedResourcesEntries(t, testCase.resources, loadedTxnGroup.resources)

			_, ok = <-preloadedTxnGroupsCh
			require.False(t, ok)
		})
	}
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
	ledger.balances[makeTestingAddress(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}
	type testTransactionCases struct {
		signedTxn transactions.SignedTxn
		accounts  []loadedAccountDataEntry
		resources []loadedResourcesEntry
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
						Sender: makeTestingAddress(1),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver:         makeTestingAddress(addr),
						CloseRemainderTo: makeTestingAddress(addr + 1),
					},
				},
			}
			addr += 2
		}
	}
	preloadedTxnGroupsCh := prefetchAccounts(context.Background(), ledger, rnd, txnGroups, feeSinkAddr, config.Consensus[proto])
	groupsCount := 0
	addressCount := 0
	uniqueAccounts := make(map[basics.Address]bool)
	for k := range preloadedTxnGroupsCh {
		addressCount += len(k.accounts)
		for _, acct := range k.accounts {
			uniqueAccounts[*acct.address] = true
		}
		require.Equal(t, txnGroups[groupsCount], k.txnGroup)
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
						Sender: makeTestingAddress(grpIdx + txnIdx),
					},
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: 10,
						Accounts: []basics.Address{
							makeTestingAddress(grpIdx + txnIdx + 1),
							makeTestingAddress(grpIdx + txnIdx + 1),
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
	ledger.balances[makeTestingAddress(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}

	b.ResetTimer()
	preloadedTxnGroupsCh := prefetchAccounts(context.Background(), ledger, rnd, groups, feeSinkAddr, config.Consensus[proto])
	for k := range preloadedTxnGroupsCh {
		require.NoError(b, k.err)
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
						Sender: makeTestingAddress(grpIdx + txnIdx),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver:         makeTestingAddress(grpIdx + txnIdx + 1),
						CloseRemainderTo: makeTestingAddress(grpIdx + txnIdx + 2),
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
	ledger.balances[makeTestingAddress(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}

	b.ResetTimer()
	preloadedTxnGroupsCh := prefetchAccounts(context.Background(), ledger, rnd, groups, feeSinkAddr, config.Consensus[proto])
	for k := range preloadedTxnGroupsCh {
		require.NoError(b, k.err)
	}
}
func BenchmarkChannelWrites(b *testing.B) {
	b.Run("groupTaskDone", func(b *testing.B) {
		c := make(chan groupTaskDone, b.N)
		for i := 0; i < b.N; i++ {
			c <- groupTaskDone{groupIdx: i}
		}
	})

	b.Run("int64", func(b *testing.B) {
		c := make(chan int64, b.N)
		for i := int64(0); i < int64(b.N); i++ {
			c <- i
		}
	})
}
