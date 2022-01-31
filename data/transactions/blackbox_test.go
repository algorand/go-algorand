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

package transactions_test

import (
	"testing"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func TestFeeCredit(t *testing.T) {
	c, err := transactions.FeeCredit([]transactions.SignedTxnWithAD{
		txntest.Txn{Fee: 5}.SignedTxnWithAD(),
	}, 5)
	require.NoError(t, err)
	require.Equal(t, c, uint64(0))

	c, err = transactions.FeeCredit([]transactions.SignedTxnWithAD{
		txntest.Txn{Fee: 4}.SignedTxnWithAD(),
	}, 5)
	require.Error(t, err)

	c, err = transactions.FeeCredit([]transactions.SignedTxnWithAD{
		txntest.Txn{Fee: 5}.SignedTxnWithAD(),
	}, 4)
	require.NoError(t, err)
	require.Equal(t, c, uint64(1))

	c, err = transactions.FeeCredit([]transactions.SignedTxnWithAD{
		txntest.Txn{Fee: 5}.SignedTxnWithAD(),
		txntest.Txn{Fee: 5}.SignedTxnWithAD(),
	}, 5)
	require.NoError(t, err)
	require.Equal(t, c, uint64(0))

	c, err = transactions.FeeCredit([]transactions.SignedTxnWithAD{
		txntest.Txn{Fee: 5}.SignedTxnWithAD(),
		txntest.Txn{Type: protocol.CompactCertTx, Fee: 0}.SignedTxnWithAD(),
	}, 5)
	require.NoError(t, err)
	require.Equal(t, c, uint64(0))

	c, err = transactions.FeeCredit([]transactions.SignedTxnWithAD{
		txntest.Txn{Fee: 5}.SignedTxnWithAD(),
		txntest.Txn{Fee: 5}.SignedTxnWithAD(),
		txntest.Txn{Fee: 5}.SignedTxnWithAD(),
	}, 5)
	require.NoError(t, err)
	require.Equal(t, c, uint64(0))

	c, err = transactions.FeeCredit([]transactions.SignedTxnWithAD{}, 5)
	require.NoError(t, err)
	require.Equal(t, c, uint64(0))

	c, err = transactions.FeeCredit([]transactions.SignedTxnWithAD{
		txntest.Txn{Fee: 5}.SignedTxnWithAD(),
		txntest.Txn{Fee: 25}.SignedTxnWithAD(),
		txntest.Txn{Fee: 5}.SignedTxnWithAD(),
	}, 5)
	require.NoError(t, err)
	require.Equal(t, c, uint64(20))
}
