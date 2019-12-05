// Copyright (C) 2019 Algorand, Inc.
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

package data

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func TestBlockEncoding(t *testing.T) {
	var b bookkeeping.Block
	for i := 0; i < 1000; i++ {
		err := protocol.EncodingTest(&b)
		require.NoError(t, err)
	}
}

func TestGenesisEncoding(t *testing.T) {
	var g bookkeeping.Genesis
	for i := 0; i < 1000; i++ {
		err := protocol.EncodingTest(&g)
		require.NoError(t, err)
	}
}

func TestTransactionEncoding(t *testing.T) {
	var tx transactions.Transaction
	for i := 0; i < 1000; i++ {
		err := protocol.EncodingTest(&tx)
		require.NoError(t, err)
	}
}

func TestSignedTxnEncoding(t *testing.T) {
	var st transactions.SignedTxn
	for i := 0; i < 1000; i++ {
		err := protocol.EncodingTest(&st)
		require.NoError(t, err)
	}
}

func BenchmarkBlockEncoding(b *testing.B) {
	ledger, _, _, pendingTransactions, release := testingenv(b, 10, 1000, false)
	defer release()

	prev, err := ledger.BlockHdr(ledger.LastRound())
	if err != nil {
		panic(err)
	}

	block := bookkeeping.MakeBlock(prev)
	pendingTransactionsEnc := make([]transactions.SignedTxnInBlock, len(pendingTransactions))
	for i, txn := range pendingTransactions {
		pendingTransactionsEnc[i], err = block.EncodeSignedTxn(txn, transactions.ApplyData{})
		require.NoError(b, err)
	}
	block.Payset = pendingTransactionsEnc
	block.TxnRoot = block.Payset.Commit(false)

	b.Run("Encode+Decode reflect", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var dec bookkeeping.Block
			err := protocol.DecodeReflect(protocol.EncodeReflect(&block), &dec)
			if err != nil {
				panic(err)
			}

			require.Equal(b, block.Hash(), dec.Hash())
		}
	})

	b.Run("Encode+Decode msgp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var dec bookkeeping.Block
			err := protocol.DecodeMsgp(protocol.EncodeMsgp(&block), &dec)
			if err != nil {
				panic(err)
			}

			require.Equal(b, block.Hash(), dec.Hash())
		}
	})
}
