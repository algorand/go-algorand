// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestValidateSafeToSignRequiresAllowRekey(t *testing.T) {
	partitiontest.PartitionTest(t)

	originalAllowRekey := allowRekey
	defer func() {
		allowRekey = originalAllowRekey
	}()

	allowRekey = false
	err := validateSafeToSign([]transactions.SignedTxn{{
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:  basics.Address{1},
				RekeyTo: basics.Address{2},
			},
		},
	}}, "test.txn")
	require.ErrorContains(t, err, "--allow-rekey")

	allowRekey = true
	require.NoError(t, validateSafeToSign([]transactions.SignedTxn{{
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:  basics.Address{1},
				RekeyTo: basics.Address{2},
			},
		},
	}}, "test.txn"))
}

func TestScanForRekeyDetectsAssetOptInGroup(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	sender := basics.Address{1}
	rekeyTo := basics.Address{2}
	group := crypto.Digest{3}

	report := scanForRekey([]transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type: protocol.AssetTransferTx,
				Header: transactions.Header{
					Sender: sender,
					Group:  group,
				},
				AssetTransferTxnFields: transactions.AssetTransferTxnFields{
					XferAsset:     99,
					AssetAmount:   0,
					AssetReceiver: sender,
				},
			},
		},
		{
			Txn: transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:  sender,
					Group:   group,
					RekeyTo: rekeyTo,
				},
			},
		},
	})

	require.Len(t, report.Rekeys, 1)
	require.True(t, report.HasAssetOptInAndRekey)
}
