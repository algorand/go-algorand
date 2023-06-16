// Copyright (C) 2019-2023 Algorand, Inc.
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

package generator

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func makePrivateGenerator(t *testing.T, round uint64, genesis bookkeeping.Genesis) *generator {
	cfg := GenerationConfig{
		Name:                         "test",
		NumGenesisAccounts:           10,
		GenesisAccountInitialBalance: 1000000000000,
		PaymentTransactionFraction:   1.0,
		PaymentNewAccountFraction:    1.0,
		AssetCreateFraction:          1.0,
	}
	cfg.validateWithDefaults(true)
	publicGenerator, err := MakeGenerator(round, genesis, cfg)
	require.NoError(t, err)
	return publicGenerator.(*generator)
}

func TestPaymentAcctCreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})
	g.generatePaymentTxnInternal(paymentAcctCreateTx, 0, 0)
	require.Len(t, g.balances, int(g.config.NumGenesisAccounts+1))
}

func TestPaymentTransfer(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})
	g.generatePaymentTxnInternal(paymentTx, 0, 0)
	require.Len(t, g.balances, int(g.config.NumGenesisAccounts))
}

func TestAssetXferNoAssetsOverride(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})

	// First asset transaction must create.
	actual, txn := g.generateAssetTxnInternal(assetXfer, 1, 0)
	require.Equal(t, assetCreate, actual)
	require.Equal(t, protocol.AssetConfigTx, txn.Type)
	require.Len(t, g.assets, 0)
	require.Len(t, g.pendingAssets, 1)
	require.Len(t, g.pendingAssets[0].holdings, 1)
	require.Len(t, g.pendingAssets[0].holders, 1)
}

func TestAssetXferOneHolderOverride(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})
	g.finishRound(0)
	g.generateAssetTxnInternal(assetCreate, 1, 0)
	g.finishRound(1)

	// Transfer converted to optin if there is only 1 holder.
	actual, txn := g.generateAssetTxnInternal(assetXfer, 2, 0)
	require.Equal(t, assetOptin, actual)
	require.Equal(t, protocol.AssetTransferTx, txn.Type)
	require.Len(t, g.assets, 1)
	// A new holding is created, indicating the optin
	require.Len(t, g.assets[0].holdings, 2)
	require.Len(t, g.assets[0].holders, 2)
}

func TestAssetCloseCreatorOverride(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})
	g.finishRound(0)
	g.generateAssetTxnInternal(assetCreate, 1, 0)
	g.finishRound(1)

	// Instead of closing the creator, optin a new account
	actual, txn := g.generateAssetTxnInternal(assetClose, 2, 0)
	require.Equal(t, assetOptin, actual)
	require.Equal(t, protocol.AssetTransferTx, txn.Type)
	require.Len(t, g.assets, 1)
	// A new holding is created, indicating the optin
	require.Len(t, g.assets[0].holdings, 2)
	require.Len(t, g.assets[0].holders, 2)
}

func TestAssetOptinEveryAccountOverride(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})
	g.finishRound(0)
	g.generateAssetTxnInternal(assetCreate, 1, 0)
	g.finishRound(1)

	// Opt all the accounts in, this also verifies that no account is opted in twice
	var txn transactions.Transaction
	var actual TxTypeID
	for i := 2; uint64(i) <= g.numAccounts; i++ {
		actual, txn = g.generateAssetTxnInternal(assetOptin, 2, uint64(1+i))
		require.Equal(t, assetOptin, actual)
		require.Equal(t, protocol.AssetTransferTx, txn.Type)
		require.Len(t, g.assets, 1)
		require.Len(t, g.assets[0].holdings, i)
		require.Len(t, g.assets[0].holders, i)
	}
	g.finishRound(2)

	// All accounts have opted in
	require.Equal(t, g.numAccounts, uint64(len(g.assets[0].holdings)))

	// The next optin closes instead
	actual, txn = g.generateAssetTxnInternal(assetOptin, 3, 0)
	g.finishRound(3)
	require.Equal(t, assetClose, actual)
	require.Equal(t, protocol.AssetTransferTx, txn.Type)
	require.Len(t, g.assets, 1)
	require.Len(t, g.assets[0].holdings, int(g.numAccounts-1))
	require.Len(t, g.assets[0].holders, int(g.numAccounts-1))
}

func TestAssetDestroyWithHoldingsOverride(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})
	g.finishRound(0)
	g.generateAssetTxnInternal(assetCreate, 1, 0)
	g.finishRound(1)
	g.generateAssetTxnInternal(assetOptin, 2, 0)
	g.finishRound(2)
	g.generateAssetTxnInternal(assetXfer, 3, 0)
	g.finishRound(3)
	require.Len(t, g.assets[0].holdings, 2)
	require.Len(t, g.assets[0].holders, 2)

	actual, txn := g.generateAssetTxnInternal(assetDestroy, 4, 0)
	require.Equal(t, assetClose, actual)
	require.Equal(t, protocol.AssetTransferTx, txn.Type)
	require.Len(t, g.assets, 1)
	require.Len(t, g.assets[0].holdings, 1)
	require.Len(t, g.assets[0].holders, 1)
}

func TestAssetTransfer(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})
	g.finishRound(0)

	g.generateAssetTxnInternal(assetCreate, 1, 0)
	g.finishRound(1)
	g.generateAssetTxnInternal(assetOptin, 2, 0)
	g.finishRound(2)
	g.generateAssetTxnInternal(assetXfer, 3, 0)
	g.finishRound(3)
	require.Greater(t, g.assets[0].holdings[1].balance, uint64(0))
}

func TestAssetDestroy(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})
	g.finishRound(0)
	g.generateAssetTxnInternal(assetCreate, 1, 0)
	g.finishRound(1)
	require.Len(t, g.assets, 1)

	actual, txn := g.generateAssetTxnInternal(assetDestroy, 2, 0)
	require.Equal(t, assetDestroy, actual)
	require.Equal(t, protocol.AssetConfigTx, txn.Type)
	require.Len(t, g.assets, 0)
}

func TestAppCreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})

	// app call transaction creating appBoxes
	actual, txn, err := g.generateAppCallInternal(appBoxesCreate, 1, 0, 0, nil)
	require.NoError(t, err)
	require.Equal(t, appBoxesCreate, actual)
	require.Equal(t, protocol.ApplicationCallTx, txn.Type)
	require.Len(t, g.apps, 0)
	require.Len(t, g.pendingApps, 1)
	require.Len(t, g.pendingApps[appKindBoxes], 1)
	require.Len(t, g.pendingApps[appKindSwap], 0)
	require.Len(t, g.pendingApps[appKindBoxes][0].holdings, 1)
	require.Len(t, g.pendingApps[appKindBoxes][0].holders, 1)
	ad := *g.pendingApps[appKindBoxes][0]
	holding := *ad.holdings[0]
	require.Equal(t, holding, *ad.holders[0])
	require.Equal(t, uint64(1001), holding.appIndex)
	require.Equal(t, ad.appID, holding.appIndex)
	require.Equal(t, appKindBoxes, ad.kind)

	// app call transaction creating appSwap
	actual, txn, err = g.generateAppCallInternal(appSwapCreate, 1, 0, 0, nil)
	require.NoError(t, err)
	require.Equal(t, appSwapCreate, actual)
	require.Equal(t, protocol.ApplicationCallTx, txn.Type)
	require.Len(t, g.apps, 0)
	require.Len(t, g.pendingApps, 2)
	require.Len(t, g.pendingApps[appKindBoxes], 1)
	require.Len(t, g.pendingApps[appKindSwap], 1)
	require.Len(t, g.pendingApps[appKindSwap][0].holdings, 1)
	require.Len(t, g.pendingApps[appKindSwap][0].holders, 1)
	ad = *g.pendingApps[appKindSwap][0]
	holding = *ad.holdings[0]
	require.Equal(t, holding, *ad.holders[0])
	require.Equal(t, uint64(1001), holding.appIndex)
	require.Equal(t, ad.appID, holding.appIndex)
	require.Equal(t, appKindSwap, ad.kind)
}

func TestWriteRoundZero(t *testing.T) {
	partitiontest.PartitionTest(t)
	var testcases = []struct {
		name    string
		dbround uint64
		round   uint64
		genesis bookkeeping.Genesis
	}{
		{
			name:    "empty database",
			dbround: 0,
			round:   0,
			genesis: bookkeeping.Genesis{},
		},
		{
			name:    "preloaded database",
			dbround: 1,
			round:   1,
			genesis: bookkeeping.Genesis{Network: "TestWriteRoundZero"},
		},
	}
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := makePrivateGenerator(t, tc.dbround, tc.genesis)
			var data []byte
			writer := bytes.NewBuffer(data)
			g.WriteBlock(writer, tc.round)
			var block rpcs.EncodedBlockCert
			protocol.Decode(data, &block)
			require.Len(t, block.Block.Payset, 0)
			g.ledger.Close()
		})
	}

}

func TestWriteRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})

	prepBuffer := func() (*bytes.Buffer, rpcs.EncodedBlockCert) {
		return bytes.NewBuffer([]byte{}), rpcs.EncodedBlockCert{}
	}

	// Initial conditions of g from makePrivateGenerator:
	require.Equal(t, uint64(0), g.round)

	// Round 0:
	blockBuff, block0_1 := prepBuffer()
	err := g.WriteBlock(blockBuff, 0)
	require.NoError(t, err)

	require.Equal(t, uint64(1), g.round)
	protocol.Decode(blockBuff.Bytes(), &block0_1)
	require.Equal(t, "blockgen-test", block0_1.Block.BlockHeader.GenesisID)
	require.Equal(t, basics.Round(0), block0_1.Block.BlockHeader.Round)
	require.NotNil(t, g.ledger)
	require.Equal(t, basics.Round(0), g.ledger.Latest())

	// WriteBlocks only advances the _internal_ round
	// the first time called for a particular _given_ round
	blockBuff, block0_2 := prepBuffer()
	err = g.WriteBlock(blockBuff, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), g.round)
	protocol.Decode(blockBuff.Bytes(), &block0_2)
	require.Equal(t, block0_1, block0_2)
	require.NotNil(t, g.ledger)
	require.Equal(t, basics.Round(0), g.ledger.Latest())

	blockBuff, block0_3 := prepBuffer()
	err = g.WriteBlock(blockBuff, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), g.round)
	protocol.Decode(blockBuff.Bytes(), &block0_3)
	require.Equal(t, block0_1, block0_3)
	require.NotNil(t, g.ledger)
	require.Equal(t, basics.Round(0), g.ledger.Latest())

	// Round 1:
	blockBuff, block1_1 := prepBuffer()
	err = g.WriteBlock(blockBuff, 1)
	require.NoError(t, err)
	require.Equal(t, uint64(2), g.round)
	protocol.Decode(blockBuff.Bytes(), &block1_1)
	require.Equal(t, "blockgen-test", block1_1.Block.BlockHeader.GenesisID)
	require.Equal(t, basics.Round(1), block1_1.Block.BlockHeader.Round)
	require.Len(t, block1_1.Block.Payset, int(g.config.TxnPerBlock))
	require.NotNil(t, g.ledger)
	require.Equal(t, basics.Round(1), g.ledger.Latest())
	_, err = g.ledger.GetStateDeltaForRound(1)
	require.NoError(t, err)

	blockBuff, block1_2 := prepBuffer()
	err = g.WriteBlock(blockBuff, 1)
	require.NoError(t, err)
	require.Equal(t, uint64(2), g.round)
	protocol.Decode(blockBuff.Bytes(), &block1_2)
	require.Equal(t, block1_1, block1_2)
	require.NotNil(t, g.ledger)
	require.Equal(t, basics.Round(1), g.ledger.Latest())
	_, err = g.ledger.GetStateDeltaForRound(1)
	require.NoError(t, err)

	// request a block that is several rounds ahead of the current round
	err = g.WriteBlock(blockBuff, 10)
	require.NotNil(t, err)
	require.Equal(t, err.Error(), "generator only supports sequential block access. Expected 1 or 2 but received request for 10")
}

func TestWriteRoundWithPreloadedDB(t *testing.T) {
	partitiontest.PartitionTest(t)
	var testcases = []struct {
		name    string
		dbround uint64
		round   uint64
		genesis bookkeeping.Genesis
		err     error
	}{
		{
			name:    "preloaded database starting at round 1",
			dbround: 1,
			round:   1,
			genesis: bookkeeping.Genesis{Network: "generator-test1"},
		},
		{
			name:    "invalid request",
			dbround: 10,
			round:   1,
			genesis: bookkeeping.Genesis{Network: "generator-test2"},
			err:     fmt.Errorf("cannot generate block for round 1, already in database"),
		},
		{
			name:    "invalid request 2",
			dbround: 1,
			round:   10,
			genesis: bookkeeping.Genesis{Network: "generator-test3"},
			err:     fmt.Errorf("generator only supports sequential block access. Expected 1 or 2 but received request for 10"),
		},
		{
			name:    "preloaded database starting at 10",
			dbround: 10,
			round:   11,
			genesis: bookkeeping.Genesis{Network: "generator-test4"},
		},
		{
			name:    "preloaded database request round 20",
			dbround: 10,
			round:   20,
			genesis: bookkeeping.Genesis{Network: "generator-test5"},
		},
	}
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// No t.Parallel() here, to avoid contention in the ledger
			g := makePrivateGenerator(t, tc.dbround, tc.genesis)

			defer g.ledger.Close()
			var data []byte
			writer := bytes.NewBuffer(data)
			err := g.WriteBlock(writer, tc.dbround)
			require.Nil(t, err)
			// invalid block request
			if tc.round != tc.dbround && tc.err != nil {
				err = g.WriteBlock(writer, tc.round)
				require.NotNil(t, err)
				require.Equal(t, tc.err.Error(), err.Error())
				return
			}
			// write the rest of the blocks
			for i := tc.dbround + 1; i <= tc.round; i++ {
				err = g.WriteBlock(writer, i)
				require.Nil(t, err)
			}
			var block rpcs.EncodedBlockCert
			protocol.Decode(data, &block)
			require.Len(t, block.Block.Payset, int(g.config.TxnPerBlock))
			require.NotNil(t, g.ledger)
			require.Equal(t, basics.Round(tc.round-tc.dbround), g.ledger.Latest())
			if tc.round > tc.dbround {
				_, err = g.ledger.GetStateDeltaForRound(basics.Round(tc.round - tc.dbround))
				require.NoError(t, err)
			}
		})
	}
}

func TestHandlers(t *testing.T) {
	partitiontest.PartitionTest(t)
	g := makePrivateGenerator(t, 0, bookkeeping.Genesis{})
	handler := getBlockHandler(g)
	var testcases = []struct {
		name string
		url  string
		err  string
	}{
		{
			name: "no block",
			url:  "/v2/blocks/?nothing",
			err:  "invalid request path, /",
		},
		{
			name: "blocks: round must be numeric",
			url:  "/v2/blocks/round",
			err:  `strconv.ParseUint: parsing "round": invalid syntax`,
		},
		{
			name: "deltas: round must be numeric",
			url:  "/v2/deltas/round",
			err:  `strconv.ParseUint: parsing "round": invalid syntax`,
		},
	}

	for _, testcase := range testcases {
		testcase := testcase
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", testcase.url, nil)
			w := httptest.NewRecorder()
			handler(w, req)
			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Contains(t, w.Body.String(), testcase.err)
		})
	}
}
