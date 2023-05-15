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
	partitiontest.PartitionTest(t)
	publicGenerator, err := MakeGenerator(round, genesis, GenerationConfig{
		NumGenesisAccounts:           10,
		GenesisAccountInitialBalance: 1000000000000,
		PaymentTransactionFraction:   1.0,
		PaymentNewAccountFraction:    1.0,
		AssetCreateFraction:          1.0,
	})
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

func TestWriteRoundZero(t *testing.T) {
	partitiontest.PartitionTest(t)
	testcases := []struct {
		name    string
		dbround uint64
		round   uint64
		genesis bookkeeping.Genesis
	}{
		{"empty database", 0, 0, bookkeeping.Genesis{}},
		{"preloaded database", 1, 1, bookkeeping.Genesis{Network: "TestWriteRoundZero"}},
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
	var data []byte
	writer := bytes.NewBuffer(data)
	g.WriteBlock(writer, 0)
	g.WriteBlock(writer, 1)
	var block rpcs.EncodedBlockCert
	protocol.Decode(data, &block)
	require.Len(t, block.Block.Payset, int(g.config.TxnPerBlock))
	require.NotNil(t, g.ledger)
	require.Equal(t, basics.Round(1), g.ledger.Latest())
	_, err := g.ledger.GetStateDeltaForRound(1)
	require.NoError(t, err)
	// request a block that is several rounds ahead of the current round
	err = g.WriteBlock(writer, 10)
	require.NotNil(t, err)
	require.Equal(t, err.Error(), "generator only supports sequential block access. Expected 2 but received request for 10")
}

func TestWriteRoundWithPreloadedDB(t *testing.T) {
	partitiontest.PartitionTest(t)
	testcases := []struct {
		name    string
		dbround uint64
		round   uint64
		genesis bookkeeping.Genesis
		err     error
	}{
		{"preloaded database starting at round 1", 1, 1, bookkeeping.Genesis{Network: "generator-test1"}, nil},
		{"invalid request", 10, 1, bookkeeping.Genesis{Network: "generator-test"}, fmt.Errorf("cannot generate block for round 1, already in database")},
		{"invalid request", 1, 10, bookkeeping.Genesis{Network: "generator-test"}, fmt.Errorf("generator only supports sequential block access. Expected 2 but received request for 10")},
		{"preloaded database starting at 10", 10, 11, bookkeeping.Genesis{Network: "generator-test2"}, nil},
		{"preloaded database request round 20", 10, 20, bookkeeping.Genesis{Network: "generator-test3"}, nil},
	}
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
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
				require.Equal(t, err.Error(), tc.err.Error())
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
		t.Run(testcase.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", testcase.url, nil)
			w := httptest.NewRecorder()
			handler(w, req)
			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Contains(t, w.Body.String(), testcase.err)
		})
	}
}
