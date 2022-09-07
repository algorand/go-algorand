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
func (l *prefetcherTestLedger) LookupResource(basics.Round, basics.Address, basics.CreatableIndex, basics.CreatableType) (ledgercore.AccountResource, error) {
	return ledgercore.AccountResource{}, nil
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
	return config.Consensus[protocol.ConsensusCurrentVersion]
}
func (l *prefetcherTestLedger) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	return l.round, ledgercore.AccountTotals{}, nil
}
func (l *prefetcherTestLedger) CompactCertVoters(basics.Round) (*ledgercore.VotersForRound, error) {
	return nil, nil
}

func TestEvaluatorPrefetcher(t *testing.T) {
	partitiontest.PartitionTest(t)

	acctAddrPtr := func(i int) (o *basics.Address) {
		o = new(basics.Address)
		o[0] = byte(i)
		o[1] = byte(i >> 8)
		o[2] = byte(i >> 16)
		return
	}
	acctAddr := func(i int) (o basics.Address) {
		t := *acctAddrPtr(i)
		copy(o[:], t[:])
		return
	}

	rnd := basics.Round(5)
	var feeSinkAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	var ledger = &prefetcherTestLedger{
		round:    rnd,
		balances: make(map[basics.Address]ledgercore.AccountData),
		creators: make(map[basics.CreatableIndex]basics.Address),
	}
	ledger.balances[acctAddr(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}
	ledger.creators[1001] = acctAddr(2)
	ledger.creators[2001] = acctAddr(15)

	type testTransactionCases struct {
		signedTxn transactions.SignedTxn
		accounts  []loadedAccountDataEntry
		resources []loadedResourcesEntry
	}

	testTransactions := []testTransactionCases{
		// payment transaction
		{
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender: acctAddr(1),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver:         acctAddr(2),
						CloseRemainderTo: acctAddr(3),
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
					address: acctAddrPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
				{
					address: acctAddrPtr(2),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: acctAddrPtr(3),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
			},
		},
		// asset config transaction for a non-existing asset
		{
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetConfigTx,
					Header: transactions.Header{
						Sender: acctAddr(1),
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
					address: acctAddrPtr(1),
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
		// asset config transaction for an existing asset
		{
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetConfigTx,
					Header: transactions.Header{
						Sender: acctAddr(1),
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
					address: acctAddrPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
			},
			resources: []loadedResourcesEntry{
				{
					address:        acctAddrPtr(2),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
			},
		},
		// asset transfer transaction
		{
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetTransferTx,
					Header: transactions.Header{
						Sender: acctAddr(1),
					},
					AssetTransferTxnFields: transactions.AssetTransferTxnFields{
						XferAsset:     1001,
						AssetSender:   acctAddr(2),
						AssetReceiver: acctAddr(3),
						AssetCloseTo:  acctAddr(4),
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
					address: acctAddrPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
				{
					address: acctAddrPtr(2),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: acctAddrPtr(3),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: acctAddrPtr(4),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
			},
			resources: []loadedResourcesEntry{
				{
					address:        acctAddrPtr(1),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
				{
					address:        acctAddrPtr(2),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
				{
					address:        acctAddrPtr(3),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
				{
					address:        acctAddrPtr(4),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
			},
		},
		// asset freeze transaction
		{
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.AssetFreezeTx,
					Header: transactions.Header{
						Sender: acctAddr(1),
					},
					AssetFreezeTxnFields: transactions.AssetFreezeTxnFields{
						FreezeAccount: acctAddr(3),
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
					address: acctAddrPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
				{
					address: acctAddrPtr(3),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
			},
			resources: []loadedResourcesEntry{
				{
					address:        acctAddrPtr(2),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
				{
					address:        acctAddrPtr(3),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
			},
		},
		// application transaction
		{
			signedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.ApplicationCallTx,
					Header: transactions.Header{
						Sender: acctAddr(1),
					},
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: 10,
						Accounts: []basics.Address{
							acctAddr(4),
							acctAddr(5),
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
					address: acctAddrPtr(1),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
					},
				},
				{
					address: acctAddrPtr(4),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
				{
					address: acctAddrPtr(5),
					data: &ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 0}},
					},
				},
			},
			resources: []loadedResourcesEntry{
				{
					address:        acctAddrPtr(2),
					creatableIndex: 1001,
					creatableType:  basics.AssetCreatable,
					resource:       &ledgercore.AccountResource{},
				},
				{
					address:        acctAddrPtr(15),
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

	for _, txn := range testTransactions {
		groups := make([][]transactions.SignedTxnWithAD, 1)
		groups[0] = make([]transactions.SignedTxnWithAD, 1)
		groups[0][0].SignedTxn = txn.signedTxn

		preloadedTxnGroupsCh := prefetchAccounts(context.Background(), ledger, rnd, groups, feeSinkAddr, config.Consensus[protocol.ConsensusCurrentVersion])

		for loadedTxnGroup := range preloadedTxnGroupsCh {
			require.NoError(t, loadedTxnGroup.err)

			// compare the txn.accounts and loadedTxnGroup.accounts in order agnostic way.
			require.Equal(t, len(txn.accounts), len(loadedTxnGroup.accounts))
			for _, acct := range txn.accounts {
				// make sure we find it in loadedTxnGroup.accounts
				found := false
				require.NotNil(t, acct.address)
				for k, loadedAcct := range loadedTxnGroup.accounts {
					require.NotNilf(t, loadedAcct.address, "index: %d\nexpected %#v\nactual %#v", k, acct, loadedAcct)
					if *acct.address != *loadedAcct.address {
						continue
					}
					require.Equal(t, *acct.data, *loadedAcct.data)
					found = true
					break
				}
				require.Truef(t, found, "missing account %#v", acct)
			}

			// compare the txn.resources and loadedTxnGroup.resources in order agnostic way
			require.Equalf(t, len(txn.resources), len(loadedTxnGroup.resources), "mismatching resources count; actual : %v", loadedTxnGroup.resources)
			for _, res := range txn.resources {
				// make sure we find it in loadedTxnGroup.resources
				found := false
				for _, loadedRes := range loadedTxnGroup.resources {
					if res.creatableIndex != loadedRes.creatableIndex {
						continue
					}
					require.Equal(t, res.creatableType, loadedRes.creatableType)
					if res.address == nil {
						require.Nil(t, loadedRes.address)
					} else {
						if loadedRes.address == nil || *res.address != *loadedRes.address {
							continue
						}
					}
					if res.resource == nil {
						require.Nil(t, loadedRes.resource)
					} else {
						require.NotNil(t, loadedRes.resource)
						require.Equal(t, *res.resource, *loadedRes.resource)
					}
					found = true
					break
				}
				require.Truef(t, found, "failed to find resource %#v", res)
			}
		}
	}
}

func TestEvaluatorPrefetcherQueueExpansion(t *testing.T) {
	partitiontest.PartitionTest(t)

	acctAddrPtr := func(i int) (o *basics.Address) {
		o = new(basics.Address)
		o[0] = byte(i)
		o[1] = byte(i >> 8)
		o[2] = byte(i >> 16)
		return
	}
	acctAddr := func(i int) (o basics.Address) {
		t := *acctAddrPtr(i)
		copy(o[:], t[:])
		return
	}

	rnd := basics.Round(5)
	var feeSinkAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	var ledger = &prefetcherTestLedger{
		round:    rnd,
		balances: make(map[basics.Address]ledgercore.AccountData),
		creators: make(map[basics.CreatableIndex]basics.Address),
	}
	ledger.balances[acctAddr(1)] = ledgercore.AccountData{
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
						Sender: acctAddr(1),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver:         acctAddr(addr),
						CloseRemainderTo: acctAddr(addr + 1),
					},
				},
			}
			addr += 2
		}
	}
	preloadedTxnGroupsCh := prefetchAccounts(context.Background(), ledger, rnd, txnGroups, feeSinkAddr, config.Consensus[protocol.ConsensusCurrentVersion])
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
	acctAddrPtr := func(i int) (o *basics.Address) {
		o = new(basics.Address)
		o[0] = byte(i)
		o[1] = byte(i >> 8)
		o[2] = byte(i >> 16)
		return
	}
	acctAddr := func(i int) (o basics.Address) {
		t := *acctAddrPtr(i)
		copy(o[:], t[:])
		return
	}

	txnGroupLen := 16
	groups := make([][]transactions.SignedTxnWithAD, 1+b.N/txnGroupLen)
	for grpIdx := range groups {
		groups[grpIdx] = make([]transactions.SignedTxnWithAD, txnGroupLen)
		for txnIdx := range groups[grpIdx] {
			groups[grpIdx][txnIdx].SignedTxn = transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.ApplicationCallTx,
					Header: transactions.Header{
						Sender: acctAddr(grpIdx + txnIdx),
					},
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: 10,
						Accounts: []basics.Address{
							acctAddr(grpIdx + txnIdx + 1),
							acctAddr(grpIdx + txnIdx + 1),
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
	ledger.balances[acctAddr(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}

	b.ResetTimer()
	preloadedTxnGroupsCh := prefetchAccounts(context.Background(), ledger, rnd, groups, feeSinkAddr, config.Consensus[protocol.ConsensusCurrentVersion])
	for k := range preloadedTxnGroupsCh {
		require.NoError(b, k.err)
	}
}

func BenchmarkPrefetcherPayment(b *testing.B) {
	acctAddrPtr := func(i int) (o *basics.Address) {
		o = new(basics.Address)
		o[0] = byte(i)
		o[1] = byte(i >> 8)
		o[2] = byte(i >> 16)
		return
	}
	acctAddr := func(i int) (o basics.Address) {
		t := *acctAddrPtr(i)
		copy(o[:], t[:])
		return
	}

	txnGroupLen := 16
	groups := make([][]transactions.SignedTxnWithAD, 1+b.N/txnGroupLen)
	for grpIdx := range groups {
		groups[grpIdx] = make([]transactions.SignedTxnWithAD, txnGroupLen)
		for txnIdx := range groups[grpIdx] {
			groups[grpIdx][txnIdx].SignedTxn = transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender: acctAddr(grpIdx + txnIdx),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver:         acctAddr(grpIdx + txnIdx + 1),
						CloseRemainderTo: acctAddr(grpIdx + txnIdx + 2),
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
	ledger.balances[acctAddr(1)] = ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{MicroAlgos: basics.MicroAlgos{Raw: 100000000}},
	}

	b.ResetTimer()
	preloadedTxnGroupsCh := prefetchAccounts(context.Background(), ledger, rnd, groups, feeSinkAddr, config.Consensus[protocol.ConsensusCurrentVersion])
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
