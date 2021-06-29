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

package bookkeeping

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
   "github.com/algorand/go-algorand/testPartitioning"
)

func TestEmptyEncoding(t *testing.T) {
   testPartitioning.PartitionTest(t)

	var b Block
	require.Equal(t, 1, len(protocol.Encode(&b)))

	var bh BlockHeader
	require.Equal(t, 1, len(protocol.Encode(&bh)))
}

func TestBlockWithTxnEncoding(t *testing.T) {
   testPartitioning.PartitionTest(t)

	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		PaymentTxnFields: transactions.PaymentTxnFields{
			Amount: basics.MicroAlgos{Raw: 1},
		},
	}

	sigtxn := transactions.SignedTxn{
		Txn: txn,
	}

	var b Block
	b.Payset = []transactions.SignedTxnInBlock{
		{
			SignedTxnWithAD: transactions.SignedTxnWithAD{
				SignedTxn: sigtxn,
			},
		},
	}
	enc := protocol.Encode(&b)

	var b2 Block
	err := protocol.Decode(enc, &b2)
	require.NoError(t, err)
	require.Equal(t, b, b2)
}
