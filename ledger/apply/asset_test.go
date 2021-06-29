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

package apply

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
   "github.com/algorand/go-algorand/testPartitioning"
)

func TestAssetTransfer(t *testing.T) {
   testPartitioning.PartitionTest(t)

	// Creator
	secretSrc := keypair()
	src := basics.Address(secretSrc.SignatureVerifier)

	secretDst := keypair()
	dst := basics.Address(secretDst.SignatureVerifier)

	secretCls := keypair()
	cls := basics.Address(secretCls.SignatureVerifier)

	var total, toSend, dstAmount uint64
	total = 1000000
	dstAmount = 500
	toSend = 200

	// prepare data
	var addrs = map[basics.Address]basics.AccountData{
		src: {
			MicroAlgos: basics.MicroAlgos{Raw: 10000000},
			AssetParams: map[basics.AssetIndex]basics.AssetParams{
				1: {Total: total},
			},
			Assets: map[basics.AssetIndex]basics.AssetHolding{
				1: {Amount: total - dstAmount},
			},
		},
		dst: {
			MicroAlgos: basics.MicroAlgos{Raw: 10000000},
			Assets: map[basics.AssetIndex]basics.AssetHolding{
				1: {Amount: dstAmount},
			},
		},
		cls: {
			MicroAlgos: basics.MicroAlgos{Raw: 10000000},
			Assets: map[basics.AssetIndex]basics.AssetHolding{
				1: {Amount: 0},
			},
		},
	}

	mockBal := makeMockBalancesWithAccounts(protocol.ConsensusCurrentVersion, addrs)

	tx := transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:     dst,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     1,
			AssetAmount:   toSend,
			AssetReceiver: src,
			AssetCloseTo:  cls,
		},
	}

	var ad transactions.ApplyData
	err := AssetTransfer(tx.AssetTransferTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, &ad)
	require.NoError(t, err)

	if config.Consensus[protocol.ConsensusCurrentVersion].EnableAssetCloseAmount {
		require.Equal(t, uint64(0), addrs[dst].Assets[1].Amount)
		require.Equal(t, dstAmount-toSend, ad.AssetClosingAmount)
		require.Equal(t, total-dstAmount+toSend, addrs[src].Assets[1].Amount)
		require.Equal(t, dstAmount-toSend, addrs[cls].Assets[1].Amount)
	}
}

var benchTotal int = 0

func BenchmarkAssetCloning(b *testing.B) {
	const numAssets = 800
	assets := make(map[basics.AssetIndex]basics.AssetHolding, numAssets)
	for j := 0; j < numAssets; j++ {
		aidx := basics.AssetIndex(rand.Int63n(100000000))
		assets[aidx] = basics.AssetHolding{Amount: uint64(aidx)}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clone := cloneAssetHoldings(assets)
		benchTotal += len(clone) // make sure the compiler does not optimize out cloneAssetHoldings call
	}
}
