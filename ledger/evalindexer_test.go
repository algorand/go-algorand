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
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type indexerLedgerForEvalImpl struct {
	l           *Ledger
	latestRound basics.Round
}

func (il indexerLedgerForEvalImpl) LatestBlockHdr() (bookkeeping.BlockHeader, error) {
	return il.l.BlockHdr(il.latestRound)
}

// The value of the returned map is nil iff the account was not found.
func (il indexerLedgerForEvalImpl) LookupWithoutRewards(addresses map[basics.Address]struct{}) (map[basics.Address]*basics.AccountData, error) {
	res := make(map[basics.Address]*basics.AccountData)

	for address := range addresses {
		accountData, _, err := il.l.LookupWithoutRewards(il.latestRound, address)
		if err != nil {
			return nil, err
		}

		if accountData.IsZero() {
			res[address] = nil
		} else {
			accountDataCopy := new(basics.AccountData)
			*accountDataCopy = accountData
			res[address] = accountDataCopy
		}
	}

	return res, nil
}

func (il indexerLedgerForEvalImpl) GetAssetCreator(map[basics.AssetIndex]struct{}) (map[basics.AssetIndex]FoundAddress, error) {
	// This function is unused.
	return nil, errors.New("GetAssetCreator() not implemented")
}

func (il indexerLedgerForEvalImpl) GetAppCreator(map[basics.AppIndex]struct{}) (map[basics.AppIndex]FoundAddress, error) {
	// This function is unused.
	return nil, errors.New("GetAppCreator() not implemented")
}

func (il indexerLedgerForEvalImpl) LatestTotals() (totals ledgercore.AccountTotals, err error) {
	_, totals, err = il.l.LatestTotals()
	return
}

// Test that overriding the consensus parameters effects the generated apply data.
func TestEvalForIndexerCustomProtocolParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisBalances, addrs, _ := ledgertesting.NewTestGenesis()

	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	block, err := bookkeeping.MakeGenesisBlock(protocol.ConsensusV24,
		genesisBalances, "test", genHash)

	dbName := fmt.Sprintf("%s", t.Name())
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, true, ledgercore.InitState{
		Block:       block,
		Accounts:    genesisBalances.Balances,
		GenesisHash: genHash,
	}, cfg)
	require.NoError(t, err)
	defer l.Close()

	const assetid basics.AssetIndex = 1
	proto := config.Consensus[protocol.ConsensusV24]

	block = bookkeeping.MakeBlock(block.BlockHeader)

	createTxn := txntest.Txn{
		Type:        "acfg",
		Sender:      addrs[0],
		GenesisHash: block.GenesisHash(),
		AssetParams: basics.AssetParams{
			Total:    200,
			Decimals: 0,
			Manager:  addrs[0],
			Reserve:  addrs[0],
			Freeze:   addrs[0],
			Clawback: addrs[0],
		},
	}
	createTxn.FillDefaults(proto)
	createStib, err := block.BlockHeader.EncodeSignedTxn(
		createTxn.SignedTxn(), transactions.ApplyData{})
	require.NoError(t, err)

	optInTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[1],
		GenesisHash:   block.GenesisHash(),
		XferAsset:     assetid,
		AssetAmount:   0,
		AssetReceiver: addrs[1],
	}
	optInTxn.FillDefaults(proto)
	optInStib, err := block.BlockHeader.EncodeSignedTxn(
		optInTxn.SignedTxn(), transactions.ApplyData{})
	require.NoError(t, err)

	fundTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[0],
		GenesisHash:   block.GenesisHash(),
		XferAsset:     assetid,
		AssetAmount:   100,
		AssetReceiver: addrs[1],
	}
	fundTxn.FillDefaults(proto)
	fundStib, err := block.BlockHeader.EncodeSignedTxn(
		fundTxn.SignedTxn(), transactions.ApplyData{})
	require.NoError(t, err)

	optOutTxn := txntest.Txn{
		Type:          "axfer",
		Sender:        addrs[1],
		GenesisHash:   block.GenesisHash(),
		XferAsset:     assetid,
		AssetAmount:   30,
		AssetReceiver: addrs[0],
		AssetCloseTo:  addrs[0],
	}
	optOutTxn.FillDefaults(proto)
	optOutStib, err := block.BlockHeader.EncodeSignedTxn(
		optOutTxn.SignedTxn(), transactions.ApplyData{})
	require.NoError(t, err)

	block.Payset = []transactions.SignedTxnInBlock{
		createStib, optInStib, fundStib, optOutStib,
	}

	il := indexerLedgerForEvalImpl{
		l:           l,
		latestRound: 0,
	}
	proto.EnableAssetCloseAmount = true
	_, modifiedTxns, err := EvalForIndexer(il, &block, proto, EvalForIndexerResources{})
	require.NoError(t, err)

	require.Equal(t, 4, len(modifiedTxns))
	assert.Equal(t, uint64(70), modifiedTxns[3].AssetClosingAmount)
}

// TestEvalForIndexerForExpiredAccounts tests that the EvalForIndexer function will correctly mark accounts offline
func TestEvalForIndexerForExpiredAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisBalances, addrs, _ := ledgertesting.NewTestGenesis()

	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	block, err := bookkeeping.MakeGenesisBlock(protocol.ConsensusFuture,
		genesisBalances, "test", genHash)

	dbName := fmt.Sprintf("%s", t.Name())
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, true, ledgercore.InitState{
		Block:       block,
		Accounts:    genesisBalances.Balances,
		GenesisHash: genHash,
	}, cfg)
	require.NoError(t, err)
	defer l.Close()

	proto := config.Consensus[protocol.ConsensusFuture]

	block = bookkeeping.MakeBlock(block.BlockHeader)

	il := indexerLedgerForEvalImpl{
		l:           l,
		latestRound: 0,
	}

	_, _, err = EvalForIndexer(il, &block, proto, EvalForIndexerResources{})
	require.NoError(t, err)

	badBlock := block
	// First validate that bad block is fine if we dont touch it...
	_, _, err = EvalForIndexer(il, &badBlock, proto, EvalForIndexerResources{})
	require.NoError(t, err)

	// Introduce an unknown address, but this time the Eval function is called with parameters that
	// don't necessarily mean that this will cause an error.  Just that an empty address will be added
	badBlock.ExpiredParticipationAccounts = append(badBlock.ExpiredParticipationAccounts, basics.Address{123})

	_, _, err = EvalForIndexer(il, &badBlock, proto, EvalForIndexerResources{})
	require.NoError(t, err)

	badBlock = block

	// Now we add way too many accounts which will cause resetExpiredOnlineAccountsParticipationKeys() to fail
	addressToCopy := addrs[0]

	for i := 0; i < proto.MaxProposedExpiredOnlineAccounts+1; i++ {
		badBlock.ExpiredParticipationAccounts = append(badBlock.ExpiredParticipationAccounts, addressToCopy)
	}

	_, _, err = EvalForIndexer(il, &badBlock, proto, EvalForIndexerResources{})
	require.Error(t, err)

	// Sanity Check

	badBlock = block

	_, _, err = EvalForIndexer(il, &badBlock, proto, EvalForIndexerResources{})
	require.NoError(t, err)
}

// Test that preloading data in cow base works as expected.
func TestResourceCaching(t *testing.T) {
	partitiontest.PartitionTest(t)

	var address basics.Address
	_, err := rand.Read(address[:])
	require.NoError(t, err)

	genesisInitState, _, _ := ledgertesting.GenesisWithProto(10, protocol.ConsensusFuture)

	genesisBalances := bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
		Timestamp:   0,
	}
	l := newTestLedger(t, genesisBalances)

	genesisBlockHeader, err := l.BlockHdr(basics.Round(0))
	require.NoError(t, err)
	block := bookkeeping.MakeBlock(genesisBlockHeader)

	resources := EvalForIndexerResources{
		Accounts: map[basics.Address]*basics.AccountData{
			address: {
				MicroAlgos: basics.MicroAlgos{Raw: 5},
			},
		},
		Creators: map[Creatable]FoundAddress{
			{Index: basics.CreatableIndex(6), Type: basics.AssetCreatable}: {Address: address, Exists: true},
			{Index: basics.CreatableIndex(6), Type: basics.AppCreatable}:   {Address: address, Exists: false},
		},
	}

	ilc := makeIndexerLedgerConnector(indexerLedgerForEvalImpl{l: l, latestRound: basics.Round(0)}, block.GenesisHash(), block.Round()-1, resources)

	{
		accountData, rnd, err := ilc.LookupWithoutRewards(basics.Round(0), address)
		require.NoError(t, err)
		assert.Equal(t, basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 5}}, accountData)
		assert.Equal(t, basics.Round(0), rnd)
	}
	{
		address, found, err := ilc.GetCreatorForRound(basics.Round(0), basics.CreatableIndex(6), basics.AssetCreatable)
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, address, address)
	}
	{
		_, found, err := ilc.GetCreatorForRound(basics.Round(0), basics.CreatableIndex(6), basics.AppCreatable)
		require.NoError(t, err)
		require.False(t, found)
	}
}
