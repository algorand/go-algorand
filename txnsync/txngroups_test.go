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

package txnsync

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func TestTxnGroupEncoding(t *testing.T) {

	inTxnGroups := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{
				{
					Txn: transactions.Transaction{
						Type: protocol.PaymentTx,
					},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.KeyRegistrationTx,
					},
				},
			},
		},
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{
				{
					Txn: transactions.Transaction{
						Type: protocol.AssetConfigTx,
					},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.AssetFreezeTx,
					},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.CompactCertTx,
					},
				},
			},
		},
	}
	encodedGroupsBytes := encodeTransactionGroups(inTxnGroups)
	out, err := decodeTransactionGroups(encodedGroupsBytes)
	require.NoError(t, err)
	require.Equal(t, inTxnGroups, out)
}
