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

func (il indexerLedgerForEvalImpl) Totals() (ledgercore.AccountTotals, error) {
	return il.l.Totals(il.latestRound)
}

// Test that overriding the consensus parameters effects the generated apply data.
func TestEvalForIndexerCustomProtocolParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	genesisBalances, addrs, _ := newTestGenesis()

	var genHash crypto.Digest
	crypto.RandBytes(genHash[:])
	block, err := bookkeeping.MakeGenesisBlock(protocol.ConsensusV24,
		genesisBalances, "test", genHash)

	dbName := fmt.Sprintf("%s", t.Name())
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := OpenLedger(logging.Base(), dbName, true, InitState{
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
	_, modifiedTxns, err := EvalForIndexer(il, &block, proto)
	require.NoError(t, err)

	require.Equal(t, 4, len(modifiedTxns))
	assert.Equal(t, uint64(70), modifiedTxns[3].AssetClosingAmount)
}
