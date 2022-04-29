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

package prefetcher_test

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
	"github.com/algorand/go-algorand/ledger/internal"
	"github.com/algorand/go-algorand/ledger/internal/prefetcher"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-deadlock"
)

type creatable struct {
	cindex basics.CreatableIndex
	ctype  basics.CreatableType
}

func genesisHash() crypto.Digest {
	var res crypto.Digest
	res[0] = 255
	return res
}

func feeSink() basics.Address {
	return makeAddress(100)
}

func rewardsPool() basics.Address {
	return makeAddress(101)
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
func (l *prefetcherAlignmentTestLedger) LookupKv(rnd basics.Round, key string) (*string, error) {
	panic("not implemented")
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

func parseLoadedAccountDataEntries(loadedAccountDataEntries []prefetcher.LoadedAccountDataEntry) map[basics.Address]struct{} {
	if len(loadedAccountDataEntries) == 0 {
		return nil
	}

	res := make(map[basics.Address]struct{})
	for _, e := range loadedAccountDataEntries {
		res[*e.Address] = struct{}{}
	}
	return res
}

func parseLoadedResourcesEntries(loadedResourcesEntries []prefetcher.LoadedResourcesEntry) (apps map[basics.Address]map[basics.AppIndex]struct{}, assets map[basics.Address]map[basics.AssetIndex]struct{}, creators map[creatable]struct{}) {
	for _, e := range loadedResourcesEntries {
		cr := creatable{
			cindex: e.CreatableIndex,
			ctype:  e.CreatableType,
		}
		if e.Address == nil {
			if creators == nil {
				creators = make(map[creatable]struct{})
			}
			creators[cr] = struct{}{}
		} else {
			if e.CreatableType == basics.AppCreatable {
				if apps == nil {
					apps = make(map[basics.Address]map[basics.AppIndex]struct{})
				}
				c, ok := apps[*e.Address]
				if !ok {
					c = make(map[basics.AppIndex]struct{})
					apps[*e.Address] = c
				}
				c[basics.AppIndex(e.CreatableIndex)] = struct{}{}

				if e.Resource.AppParams != nil {
					if creators == nil {
						creators = make(map[creatable]struct{})
					}
					creators[cr] = struct{}{}
				}
			} else {
				if assets == nil {
					assets = make(map[basics.Address]map[basics.AssetIndex]struct{})
				}
				c, ok := assets[*e.Address]
				if !ok {
					c = make(map[basics.AssetIndex]struct{})
					assets[*e.Address] = c
				}
				c[basics.AssetIndex(e.CreatableIndex)] = struct{}{}

				if e.Resource.AssetParams != nil {
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

type ledgerData struct {
	Accounts map[basics.Address]struct{}
	Apps     map[basics.Address]map[basics.AppIndex]struct{}
	Assets   map[basics.Address]map[basics.AssetIndex]struct{}
	Creators map[creatable]struct{}
}

func prefetch(t *testing.T, l prefetcher.Ledger, txn transactions.Transaction) ledgerData {
	group := makeGroupFromTxn(txn)

	ch := prefetcher.PrefetchAccounts(
		context.Background(), l, 1,
		[][]transactions.SignedTxnWithAD{group},
		feeSink(), config.Consensus[proto])
	loaded, ok := <-ch
	require.True(t, ok)

	require.Nil(t, loaded.Err)
	require.Equal(t, group, loaded.TxnGroup)

	_, ok = <-ch
	require.False(t, ok)

	accounts := parseLoadedAccountDataEntries(loaded.Accounts)
	apps, assets, creators := parseLoadedResourcesEntries(loaded.Resources)

	return ledgerData{
		Accounts: accounts,
		Apps:     apps,
		Assets:   assets,
		Creators: creators,
	}
}

func runEval(t *testing.T, l *prefetcherAlignmentTestLedger, txn transactions.Transaction) {
	genesisBlockHeader, err := l.BlockHdr(0)
	require.NoError(t, err)
	block := bookkeeping.MakeBlock(genesisBlockHeader)

	eval, err := internal.StartEvaluator(l, block.BlockHeader, internal.EvaluatorOptions{})
	require.NoError(t, err)

	err = eval.TransactionGroup(makeGroupFromTxn(txn))
	require.NoError(t, err)
}

func run(t *testing.T, l *prefetcherAlignmentTestLedger, txn transactions.Transaction) (ledgerData /*requested*/, ledgerData /*prefetched*/) {
	prefetched := prefetch(t, l, txn)

	l.requestedBalances = nil
	l.requestedApps = nil
	l.requestedAssets = nil
	l.requestedCreators = nil

	runEval(t, l, txn)
	requestedData := ledgerData{
		Accounts: l.requestedBalances,
		Apps:     l.requestedApps,
		Assets:   l.requestedAssets,
		Creators: l.requestedCreators,
	}

	return requestedData, prefetched
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000001},
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
			makeAddress(3): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000003},
				},
			},
		},
	}

	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      makeAddress(1),
			GenesisHash: genesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         makeAddress(2),
			CloseRemainderTo: makeAddress(3),
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000001},
				},
			},
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      makeAddress(1),
			GenesisHash: genesisHash(),
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	// Only one (non-existing) asset is requested. Ignore it.
	require.Len(t, requested.Assets, 1)
	require.Len(t, requested.Assets[makeAddress(1)], 1)
	requested.Assets = nil
	require.Equal(t, requested, prefetched)
}

func TestEvaluatorPrefetcherAlignmentReconfigAsset(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr := makeAddress(1)
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
			Sender:      makeAddress(1),
			GenesisHash: genesisHash(),
		},
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			ConfigAsset: 5,
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:       basics.MicroAlgos{Raw: 1000001},
					TotalAssets:      1,
					TotalAssetParams: 1,
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
		},
		assets: map[basics.Address]map[basics.AssetIndex]ledgercore.AssetResource{
			makeAddress(1): {
				assetID: {
					AssetParams:  &basics.AssetParams{},
					AssetHolding: &basics.AssetHolding{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(assetID): makeAddress(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      makeAddress(2),
			GenesisHash: genesisHash(),
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     assetID,
			AssetReceiver: makeAddress(2),
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:       basics.MicroAlgos{Raw: 1000001},
					TotalAssets:      1,
					TotalAssetParams: 1,
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
			makeAddress(3): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000003},
				},
			},
			makeAddress(4): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000004},
				},
			},
		},
		assets: map[basics.Address]map[basics.AssetIndex]ledgercore.AssetResource{
			makeAddress(1): {
				assetID: {
					AssetParams:  &basics.AssetParams{},
					AssetHolding: &basics.AssetHolding{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(assetID): makeAddress(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      makeAddress(2),
			GenesisHash: genesisHash(),
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     assetID,
			AssetReceiver: makeAddress(2),
			AssetCloseTo:  makeAddress(3),
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:       basics.MicroAlgos{Raw: 1000001},
					TotalAssets:      1,
					TotalAssetParams: 1,
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
			makeAddress(3): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000003},
				},
			},
			makeAddress(4): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000003},
				},
			},
		},
		assets: map[basics.Address]map[basics.AssetIndex]ledgercore.AssetResource{
			makeAddress(1): {
				assetID: {
					AssetParams: &basics.AssetParams{
						Clawback: makeAddress(2),
					},
					AssetHolding: &basics.AssetHolding{},
				},
			},
			makeAddress(3): {
				assetID: {
					AssetHolding: &basics.AssetHolding{
						Amount: 345,
					},
				},
			},
			makeAddress(4): {
				assetID: {
					AssetHolding: &basics.AssetHolding{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(assetID): makeAddress(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      makeAddress(2),
			GenesisHash: genesisHash(),
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     assetID,
			AssetAmount:   1,
			AssetSender:   makeAddress(3),
			AssetReceiver: makeAddress(4),
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:       basics.MicroAlgos{Raw: 1000001},
					TotalAssets:      1,
					TotalAssetParams: 1,
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
			makeAddress(3): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000003},
				},
			},
		},
		assets: map[basics.Address]map[basics.AssetIndex]ledgercore.AssetResource{
			makeAddress(1): {
				assetID: {
					AssetParams: &basics.AssetParams{
						Freeze: makeAddress(2),
					},
					AssetHolding: &basics.AssetHolding{},
				},
			},
			makeAddress(3): {
				assetID: {
					AssetHolding: &basics.AssetHolding{
						Amount: 345,
					},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(assetID): makeAddress(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      makeAddress(2),
			GenesisHash: genesisHash(),
		},
		AssetFreezeTxnFields: transactions.AssetFreezeTxnFields{
			FreezeAccount: makeAddress(3),
			FreezeAsset:   assetID,
			AssetFrozen:   true,
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
}

func TestEvaluatorPrefetcherAlignmentKeyreg(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr := makeAddress(1)
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
			Sender:      makeAddress(1),
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

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
}

func TestEvaluatorPrefetcherAlignmentCreateApplication(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr := makeAddress(1)
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

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	// Only one (non-existing) asset is requested. Ignore it.
	require.Len(t, requested.Apps, 1)
	require.Len(t, requested.Apps[makeAddress(1)], 1)
	requested.Apps = nil
	require.Equal(t, requested, prefetched)
}

func TestEvaluatorPrefetcherAlignmentDeleteApplication(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr := makeAddress(1)
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

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000002},
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			makeAddress(1): {
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
			basics.CreatableIndex(appID): makeAddress(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      makeAddress(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			OnCompletion:  transactions.OptInOC,
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000002},
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			makeAddress(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
			makeAddress(2): {
				appID: {
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): makeAddress(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      makeAddress(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			OnCompletion:  transactions.CloseOutOC,
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000002},
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			makeAddress(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
			makeAddress(2): {
				appID: {
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): makeAddress(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      makeAddress(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			OnCompletion:  transactions.ClearStateOC,
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000002},
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			makeAddress(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
			makeAddress(2): {
				appID: {
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): makeAddress(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      makeAddress(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			Accounts:      []basics.Address{makeAddress(5), makeAddress(0), makeAddress(3)},
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	// Loading accounts depends on the smart contract program. Ignore the addresses
	// not requested.
	requested.Accounts[makeAddress(5)] = struct{}{}
	requested.Accounts[makeAddress(3)] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000002},
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			makeAddress(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
			makeAddress(2): {
				appID: {
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): makeAddress(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      makeAddress(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			ForeignApps:   []basics.AppIndex{6, 8},
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	// Loading foreign apps depends on the smart contract program. Ignore the apps
	// not requested.
	requested.Creators[creatable{cindex: 6, ctype: basics.AppCreatable}] = struct{}{}
	requested.Creators[creatable{cindex: 8, ctype: basics.AppCreatable}] = struct{}{}
	require.Equal(t, requested, prefetched)
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
			makeAddress(1): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000001},
					TotalAppParams:      1,
					TotalAppLocalStates: 1,
				},
			},
			makeAddress(2): {
				AccountBaseData: ledgercore.AccountBaseData{
					MicroAlgos:          basics.MicroAlgos{Raw: 1000002},
					TotalAppLocalStates: 1,
				},
			},
		},
		apps: map[basics.Address]map[basics.AppIndex]ledgercore.AppResource{
			makeAddress(1): {
				appID: {
					AppParams: &basics.AppParams{
						ApprovalProgram:   []byte{0x02, 0x20, 0x01, 0x01, 0x22},
						ClearStateProgram: []byte{0x02, 0x20, 0x01, 0x01, 0x22},
					},
					AppLocalState: &basics.AppLocalState{},
				},
			},
			makeAddress(2): {
				appID: {
					AppLocalState: &basics.AppLocalState{},
				},
			},
		},
		creators: map[basics.CreatableIndex]basics.Address{
			basics.CreatableIndex(appID): makeAddress(1),
		},
	}

	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      makeAddress(2),
			GenesisHash: genesisHash(),
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: appID,
			ForeignAssets: []basics.AssetIndex{6, 8},
		},
	}

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	// Loading foreign assets depends on the smart contract program. Ignore the assets
	// not requested.
	requested.Creators[creatable{cindex: 6, ctype: basics.AssetCreatable}] = struct{}{}
	requested.Creators[creatable{cindex: 8, ctype: basics.AssetCreatable}] = struct{}{}
	require.Equal(t, requested, prefetched)
}

func TestEvaluatorPrefetcherAlignmentCompactCert(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr := makeAddress(1)
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

	requested, prefetched := run(t, l, txn)

	prefetched.Accounts[rewardsPool()] = struct{}{}
	require.Equal(t, requested, prefetched)
}
