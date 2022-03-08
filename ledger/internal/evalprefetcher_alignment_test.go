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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-deadlock"
)

func genesisHash() crypto.Digest {
	var res crypto.Digest
	res[0] = 255
	return res
}

func feeSink() basics.Address {
	return acctAddr(100)
}

func rewardsPool() basics.Address {
	return acctAddr(101)
}

func genesisBlock() (bookkeeping.Block, error) {
	block, err := bookkeeping.MakeGenesisBlock(
		proto,
		bookkeeping.MakeGenesisBalances(nil, feeSink(), rewardsPool()),
		"test", genesisHash())
	if err != nil {
		return bookkeeping.Block{}, err
	}

	return block, nil
}

type prefetcherAlignmentTestLedger struct {
	balances map[basics.Address]ledgercore.AccountData
	apps     map[basics.Address]map[basics.AppIndex]ledgercore.AppResource
	assets   map[basics.Address]map[basics.AssetIndex]ledgercore.AssetResource
	creators map[basics.CreatableIndex]basics.Address

	requestedBalances map[basics.Address]struct{}
	requestedApps     map[basics.Address]map[basics.AppIndex]struct{}
	requestedAssets   map[basics.Address]map[basics.AssetIndex]struct{}
	requestedCreators map[creatable]struct{}

	// Protects requested* variables.
	mu deadlock.Mutex
}

func (l *prefetcherAlignmentTestLedger) BlockHdr(round basics.Round) (bookkeeping.BlockHeader, error) {
	if round == 0 {
		block, err := genesisBlock()
		if err != nil {
			return bookkeeping.BlockHeader{}, fmt.Errorf("BlockHdr() err: %w", err)
		}
		return block.BlockHeader, nil
	}
	return bookkeeping.BlockHeader{},
		fmt.Errorf("BlockHdr() round %d not supported", round)
}
func (l *prefetcherAlignmentTestLedger) CheckDup(config.ConsensusParams, basics.Round, basics.Round, basics.Round, transactions.Txid, ledgercore.Txlease) error {
	return nil
}
func (l *prefetcherAlignmentTestLedger) LookupWithoutRewards(_ basics.Round, addr basics.Address) (ledgercore.AccountData, basics.Round, error) {
	l.mu.Lock()
	if l.requestedBalances == nil {
		l.requestedBalances = make(map[basics.Address]struct{})
	}
	l.requestedBalances[addr] = struct{}{}
	l.mu.Unlock()

	if data, has := l.balances[addr]; has {
		return data, 0, nil
	}
	return ledgercore.AccountData{}, 0, nil
}
func (l *prefetcherAlignmentTestLedger) LookupApplication(rnd basics.Round, addr basics.Address, aidx basics.AppIndex) (ledgercore.AppResource, error) {
	l.mu.Lock()
	if l.requestedApps == nil {
		l.requestedApps = make(map[basics.Address]map[basics.AppIndex]struct{})
	}
	c, ok := l.requestedApps[addr]
	if !ok {
		c = make(map[basics.AppIndex]struct{})
		l.requestedApps[addr] = c
	}
	c[aidx] = struct{}{}
	l.mu.Unlock()

	return l.apps[addr][aidx], nil
}
func (l *prefetcherAlignmentTestLedger) LookupAsset(rnd basics.Round, addr basics.Address, aidx basics.AssetIndex) (ledgercore.AssetResource, error) {
	l.mu.Lock()
	if l.requestedAssets == nil {
		l.requestedAssets = make(map[basics.Address]map[basics.AssetIndex]struct{})
	}
	c, ok := l.requestedAssets[addr]
	if !ok {
		c = make(map[basics.AssetIndex]struct{})
		l.requestedAssets[addr] = c
	}
	c[aidx] = struct{}{}
	l.mu.Unlock()

	return l.assets[addr][aidx], nil
}
func (l *prefetcherAlignmentTestLedger) GetCreatorForRound(_ basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	l.mu.Lock()
	if l.requestedCreators == nil {
		l.requestedCreators = make(map[creatable]struct{})
	}
	l.requestedCreators[creatable{cindex: cidx, ctype: ctype}] = struct{}{}
	l.mu.Unlock()

	if addr, has := l.creators[cidx]; has {
		return addr, true, nil
	}
	return basics.Address{}, false, nil
}
func (l *prefetcherAlignmentTestLedger) GenesisHash() crypto.Digest {
	return crypto.Digest{}
}
func (l *prefetcherAlignmentTestLedger) GenesisProto() config.ConsensusParams {
	return config.Consensus[proto]
}
func (l *prefetcherAlignmentTestLedger) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	return 0, ledgercore.AccountTotals{}, nil
}
func (l *prefetcherAlignmentTestLedger) CompactCertVoters(basics.Round) (*ledgercore.VotersForRound, error) {
	return nil, nil
}

func parseLoadedAccountDataEntries(loadedAccountDataEntries []loadedAccountDataEntry) map[basics.Address]struct{} {
	if len(loadedAccountDataEntries) == 0 {
		return nil
	}

	res := make(map[basics.Address]struct{})
	for _, e := range loadedAccountDataEntries {
		res[*e.address] = struct{}{}
	}
	return res
}

func parseLoadedResourcesEntries(loadedResourcesEntries []loadedResourcesEntry) (apps map[basics.Address]map[basics.AppIndex]struct{}, assets map[basics.Address]map[basics.AssetIndex]struct{}, creators map[creatable]struct{}) {
	for _, e := range loadedResourcesEntries {
		cr := creatable{
			cindex: e.creatableIndex,
			ctype:  e.creatableType,
		}
		if e.address == nil {
			if creators == nil {
				creators = make(map[creatable]struct{})
			}
			creators[cr] = struct{}{}
		} else {
			if e.creatableType == basics.AppCreatable {
				if apps == nil {
					apps = make(map[basics.Address]map[basics.AppIndex]struct{})
				}
				c, ok := apps[*e.address]
				if !ok {
					c = make(map[basics.AppIndex]struct{})
					apps[*e.address] = c
				}
				c[basics.AppIndex(e.creatableIndex)] = struct{}{}

				if e.resource.AppParams != nil {
					if creators == nil {
						creators = make(map[creatable]struct{})
					}
					creators[cr] = struct{}{}
				}
			} else {
				if assets == nil {
					assets = make(map[basics.Address]map[basics.AssetIndex]struct{})
				}
				c, ok := assets[*e.address]
				if !ok {
					c = make(map[basics.AssetIndex]struct{})
					assets[*e.address] = c
				}
				c[basics.AssetIndex(e.creatableIndex)] = struct{}{}

				if e.resource.AssetParams != nil {
					if creators == nil {
						creators = make(map[creatable]struct{})
					}
					creators[cr] = struct{}{}
				}
			}
		}
	}

	return
}

func makeGroupFromTxn(txn transactions.Transaction) []transactions.SignedTxnWithAD {
	return []transactions.SignedTxnWithAD{
		{
			SignedTxn: transactions.SignedTxn{
				Txn: txn,
			},
			ApplyData: transactions.ApplyData{},
		},
	}
}

func prefetch(t *testing.T, l *prefetcherAlignmentTestLedger, txn transactions.Transaction) (map[basics.Address]struct{} /*accounts*/, map[basics.Address]map[basics.AppIndex]struct{} /*apps*/, map[basics.Address]map[basics.AssetIndex]struct{} /*assets*/, map[creatable]struct{} /*creators*/) {
	group := makeGroupFromTxn(txn)

	ch := prefetchAccounts(
		context.Background(), l, 1,
		[][]transactions.SignedTxnWithAD{group},
		feeSink(), config.Consensus[proto])
	loaded, ok := <-ch
	require.True(t, ok)

	require.NoError(t, loaded.err)
	require.Equal(t, group, loaded.txnGroup)

	_, ok = <-ch
	require.False(t, ok)

	accounts := parseLoadedAccountDataEntries(loaded.accounts)
	apps, assets, creators := parseLoadedResourcesEntries(loaded.resources)
	return accounts, apps, assets, creators
}

func runEval(t *testing.T, l *prefetcherAlignmentTestLedger, txn transactions.Transaction) {
	genesisBlockHeader, err := l.BlockHdr(0)
	require.NoError(t, err)
	block := bookkeeping.MakeBlock(genesisBlockHeader)

	eval, err := StartEvaluator(l, block.BlockHeader, EvaluatorOptions{})
	require.NoError(t, err)

	err = eval.TransactionGroup(makeGroupFromTxn(txn))
	require.NoError(t, err)
}

func TestEvaluatorPrefetcherAlignmentPayment(t *testing.T) {
	partitiontest.PartitionTest(t)

	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000001},
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
			acctAddr(3): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000003},
				},
			},
		},
	}

	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      acctAddr(1),
			GenesisHash: genesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         acctAddr(2),
			CloseRemainderTo: acctAddr(3),
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentCreateAsset(t *testing.T) {
	partitiontest.PartitionTest(t)

	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000001},
				},
			},
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      acctAddr(1),
			GenesisHash: genesisHash(),
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	// Only one (non-existing) asset is requested. Ignore it.
	require.Len(t, l.requestedAssets, 1)
	require.Len(t, l.requestedAssets[acctAddr(1)], 1)
	require.Nil(t, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentReconfigAsset(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr := acctAddr(1)
	assetID := basics.AssetIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			addr: {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:       basics.MicroAlgos{Raw: 1000001},
					TotalAssets:      1,
					TotalAssetParams: 1,
				},
			},
		},
		assets: map[basics.Address]map[basics.AssetIndex]ledgercore.AssetResource{
			addr: {
				assetID: {
					AssetParams: &basics.AssetParams{
						Manager: addr,
					},
					AssetHolding: &basics.AssetHolding{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(assetID): addr,
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      acctAddr(1),
			GenesisHash: genesisHash(),
		},
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			ConfigAsset: 5,
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentAssetOptIn(t *testing.T) {
	partitiontest.PartitionTest(t)

	assetID := basics.AssetIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:       basics.MicroAlgos{Raw: 1000001},
					TotalAssets:      1,
					TotalAssetParams: 1,
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
		},
		assets: map[basics.Address]map[basics.AssetIndex]ledgercore.AssetResource{
			acctAddr(1): {
				assetID: {
					AssetParams:  &basics.AssetParams{},
					AssetHolding: &basics.AssetHolding{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(assetID): acctAddr(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      acctAddr(2),
			GenesisHash: genesisHash(),
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     assetID,
			AssetReceiver: acctAddr(2),
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentAssetTransfer(t *testing.T) {
	partitiontest.PartitionTest(t)

	assetID := basics.AssetIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:       basics.MicroAlgos{Raw: 1000001},
					TotalAssets:      1,
					TotalAssetParams: 1,
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
			acctAddr(3): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000003},
				},
			},
			acctAddr(4): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000004},
				},
			},
		},
		assets: map[basics.Address]map[basics.AssetIndex]ledgercore.AssetResource{
			acctAddr(1): {
				assetID: {
					AssetParams:  &basics.AssetParams{},
					AssetHolding: &basics.AssetHolding{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(assetID): acctAddr(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      acctAddr(2),
			GenesisHash: genesisHash(),
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     assetID,
			AssetReceiver: acctAddr(2),
			AssetCloseTo:  acctAddr(3),
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentAssetClawback(t *testing.T) {
	partitiontest.PartitionTest(t)

	assetID := basics.AssetIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:       basics.MicroAlgos{Raw: 1000001},
					TotalAssets:      1,
					TotalAssetParams: 1,
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
			acctAddr(3): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000003},
				},
			},
			acctAddr(4): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000003},
				},
			},
		},
		assets: map[basics.Address]map[basics.AssetIndex]ledgercore.AssetResource{
			acctAddr(1): {
				assetID: {
					AssetParams: &basics.AssetParams{
						Clawback: acctAddr(2),
					},
					AssetHolding: &basics.AssetHolding{},
				},
			},
			acctAddr(3): {
				assetID: {
					AssetHolding: &basics.AssetHolding{
						Amount: 345,
					},
				},
			},
			acctAddr(4): {
				assetID: {
					AssetHolding: &basics.AssetHolding{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(assetID): acctAddr(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      acctAddr(2),
			GenesisHash: genesisHash(),
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     assetID,
			AssetAmount:   1,
			AssetSender:   acctAddr(3),
			AssetReceiver: acctAddr(4),
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentAssetFreeze(t *testing.T) {
	partitiontest.PartitionTest(t)

	assetID := basics.AssetIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:       basics.MicroAlgos{Raw: 1000001},
					TotalAssets:      1,
					TotalAssetParams: 1,
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
			acctAddr(3): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000003},
				},
			},
		},
		assets: map[basics.Address]map[basics.AssetIndex]ledgercore.AssetResource{
			acctAddr(1): {
				assetID: {
					AssetParams: &basics.AssetParams{
						Freeze: acctAddr(2),
					},
					AssetHolding: &basics.AssetHolding{},
				},
			},
			acctAddr(3): {
				assetID: {
					AssetHolding: &basics.AssetHolding{
						Amount: 345,
					},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(assetID): acctAddr(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      acctAddr(2),
			GenesisHash: genesisHash(),
		},
		AssetFreezeTxnFields: transactions.AssetFreezeTxnFields{
			FreezeAccount: acctAddr(3),
			FreezeAsset:   assetID,
			AssetFrozen:   true,
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentKeyreg(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr := acctAddr(1)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			addr: {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000001},
				},
			},
		},
	}

	var votePK crypto.OneTimeSignatureVerifier
	votePK[0] = 1
	var selectionPK crypto.VRFVerifier
	selectionPK[0] = 2
	var stateProofPK merklesignature.Verifier
	stateProofPK[0] = 3

	txn := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:      acctAddr(1),
			GenesisHash: genesisHash(),
		},
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK:          votePK,
			SelectionPK:     selectionPK,
			StateProofPK:    stateProofPK,
			VoteLast:        9,
			VoteKeyDilution: 10,
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentCreateApplication(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr := acctAddr(1)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			addr: {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000001},
				},
			},
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      addr,
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
			ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	// Only one (non-existing) app is requested. Ignore it.
	require.Len(t, l.requestedApps, 1)
	require.Len(t, l.requestedApps[addr], 1)
	require.Nil(t, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentDeleteApplication(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr := acctAddr(1)
	appID := basics.AppIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			addr: {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			addr: {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): addr,
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      addr,
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			OnCompletion:  transactions.DeleteApplicationOC,
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentApplicationOptIn(t *testing.T) {
	partitiontest.PartitionTest(t)

	appID := basics.AppIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			acctAddr(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): acctAddr(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      acctAddr(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			OnCompletion:  transactions.OptInOC,
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentApplicationCloseOut(t *testing.T) {
	partitiontest.PartitionTest(t)

	appID := basics.AppIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000002},
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			acctAddr(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
			acctAddr(2): {
				appID: {
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): acctAddr(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      acctAddr(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			OnCompletion:  transactions.CloseOutOC,
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentApplicationClearState(t *testing.T) {
	partitiontest.PartitionTest(t)

	appID := basics.AppIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000002},
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			acctAddr(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
			acctAddr(2): {
				appID: {
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): acctAddr(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      acctAddr(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			OnCompletion:  transactions.ClearStateOC,
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentApplicationCallAccountsDeclaration(t *testing.T) {
	partitiontest.PartitionTest(t)

	appID := basics.AppIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000002},
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			acctAddr(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
			acctAddr(2): {
				appID: {
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): acctAddr(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      acctAddr(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			Accounts:      []basics.Address{acctAddr(5), acctAddr(0), acctAddr(3)},
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentApplicationCallForeignAppsDeclaration(t *testing.T) {
	partitiontest.PartitionTest(t)

	appID := basics.AppIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000002},
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			acctAddr(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
			acctAddr(2): {
				appID: {
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): acctAddr(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      acctAddr(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			ForeignApps:   []basics.AppIndex{6, 8},
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentApplicationCallForeignAssetsDeclaration(t *testing.T) {
	partitiontest.PartitionTest(t)

	appID := basics.AppIndex(5)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			acctAddr(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			acctAddr(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000002},
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			acctAddr(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
			acctAddr(2): {
				appID: {
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): acctAddr(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      acctAddr(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			ForeignAssets: []basics.AssetIndex{6, 8},
		},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}

func TestEvaluatorPrefetcherAlignmentCompactCert(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr := acctAddr(1)
	l := &prefetcherAlignmentTestLedger{
		balances: map[basics.Address]ledgercore.AccountData{
			rewardsPool(): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1234567890},
				},
			},
			addr: {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000001},
				},
			},
		},
	}

	txn := transactions.Transaction{
		Type: protocol.CompactCertTx,
		Header: transactions.Header{
			Sender:      addr,
			GenesisHash: genesisHash(),
		},
		CompactCertTxnFields: transactions.CompactCertTxnFields{},
	}

	accounts, apps, assets, creators := prefetch(t, l, txn)
	runEval(t, l, txn)

	accounts[rewardsPool()] = struct{}{}
	require.Equal(t, l.requestedBalances, accounts)
	require.Equal(t, l.requestedApps, apps)
	require.Equal(t, l.requestedAssets, assets)
	require.Equal(t, l.requestedCreators, creators)
}
