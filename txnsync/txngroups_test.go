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

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func TestBitmask(t *testing.T) {
	b := make(bitmask, 12)
	b.SetBit(0)
	b.SetBit(2)
	b.SetBit(69)
	for i := 0; i < 80; i++ {
		exists := b.EntryExists(i)
		if i == 0 || i == 2 || i == 69 {
			require.True(t, exists)
		} else {
			require.False(t, exists)
		}
	}
	b.trimBitmask(80)
	b.expandBitmask(80)
	for i := 0; i < 80; i++ {
		exists := b.EntryExists(i)
		if i == 0 || i == 2 || i == 69 {
			require.True(t, exists)
		} else {
			require.False(t, exists)
		}
	}
}

func TestNibble(t *testing.T) {
	var b []byte
	for i := 0; i < 10; i++ {
		b = append(b, byte(i))
	}
	b = squeezeByteArray(b)
	for i := 0; i < 10; i++ {
		val, err := getNibble(b, i)
		require.NoError(t, err)
		require.Equal(t, byte(i), val)
	}
}

func TestTxnGroupEncodingSmall(t *testing.T) {
	genesisHash := crypto.Hash([]byte("gh"))

	inTxnGroups := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{
				{
					Txn: transactions.Transaction{
						Type: protocol.PaymentTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("2"))),
							Fee:         basics.MicroAlgos{Raw: 100},
							GenesisHash: genesisHash,
						},
						PaymentTxnFields: transactions.PaymentTxnFields{
							Receiver: basics.Address(crypto.Hash([]byte("4"))),
							Amount:   basics.MicroAlgos{Raw: 1000},
						},
					},
					Sig: crypto.Signature{1},
				},
			},
		},
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{
				{
					Txn: transactions.Transaction{
						Type: protocol.PaymentTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("1"))),
							Fee:         basics.MicroAlgos{Raw: 100},
							GenesisHash: genesisHash,
						},
						PaymentTxnFields: transactions.PaymentTxnFields{
							Receiver: basics.Address(crypto.Hash([]byte("2"))),
							Amount:   basics.MicroAlgos{Raw: 1000},
						},
					},
					Sig: crypto.Signature{2},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.KeyRegistrationTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("1"))),
							GenesisHash: genesisHash,
						},
					},
					Sig: crypto.Signature{3},
				},
			},
		},
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{
				{
					Txn: transactions.Transaction{
						Type: protocol.AssetConfigTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("1"))),
							Fee:         basics.MicroAlgos{Raw: 100},
							GenesisHash: genesisHash,
						},
					},
					Sig: crypto.Signature{4},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.AssetFreezeTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("1"))),
							GenesisHash: genesisHash,
						},
					},
					Sig: crypto.Signature{5},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.CompactCertTx,
						Header: transactions.Header{
							Sender:      basics.Address(crypto.Hash([]byte("1"))),
							GenesisHash: genesisHash,
						},
					},
					Msig: crypto.MultisigSig{Version: 1},
				},
			},
		},
	}
	addGroupHashes(inTxnGroups, 6, []byte{1})
	encodedGroupsBytes := encodeTransactionGroups(inTxnGroups)
	out, err := decodeTransactionGroups(encodedGroupsBytes)
	require.NoError(t, err)
	require.ElementsMatch(t, inTxnGroups, out)
}

// TestTxnGroupEncodingReflection generates random
// txns of each type using reflection
func TestTxnGroupEncodingReflection(t *testing.T) {
	for i := 0; i < 10; i++ {
		v0, err := protocol.RandomizeObject(&transactions.SignedTxn{})
		require.NoError(t, err)
		stx, ok := v0.(*transactions.SignedTxn)
		require.True(t, ok)

		var txns []transactions.SignedTxn
		for _, txType := range protocol.TxnTypes {
			txn := *stx
			txn.Txn.PaymentTxnFields = transactions.PaymentTxnFields{}
			txn.Txn.KeyregTxnFields = transactions.KeyregTxnFields{}
			txn.Txn.AssetConfigTxnFields = transactions.AssetConfigTxnFields{}
			txn.Txn.AssetTransferTxnFields = transactions.AssetTransferTxnFields{}
			txn.Txn.AssetFreezeTxnFields = transactions.AssetFreezeTxnFields{}
			txn.Txn.ApplicationCallTxnFields = transactions.ApplicationCallTxnFields{}
			txn.Txn.CompactCertTxnFields = transactions.CompactCertTxnFields{}
			txn.Txn.Type = txType
			txn.Lsig.Logic = []byte("logic")
			if i%3 != 0 {
				txn.Sig = crypto.Signature{}
			}
			if i%3 != 1 {
				txn.Msig = crypto.MultisigSig{}
			}
			if i%3 != 2 {
				txn.Lsig = transactions.LogicSig{}
			}
			switch txType {
			case protocol.UnknownTx:
				continue
			case protocol.PaymentTx:
				v0, err := protocol.RandomizeObject(&txn.Txn.PaymentTxnFields)
				require.NoError(t, err)
				PaymentTxnFields, ok := v0.(*transactions.PaymentTxnFields)
				require.True(t, ok)
				txn.Txn.PaymentTxnFields = *PaymentTxnFields
			case protocol.KeyRegistrationTx:
				v0, err := protocol.RandomizeObject(&txn.Txn.KeyregTxnFields)
				require.NoError(t, err)
				KeyregTxnFields, ok := v0.(*transactions.KeyregTxnFields)
				require.True(t, ok)
				txn.Txn.KeyregTxnFields = *KeyregTxnFields
			case protocol.AssetConfigTx:
				v0, err := protocol.RandomizeObject(&txn.Txn.AssetConfigTxnFields)
				require.NoError(t, err)
				AssetConfigTxnFields, ok := v0.(*transactions.AssetConfigTxnFields)
				require.True(t, ok)
				txn.Txn.AssetConfigTxnFields = *AssetConfigTxnFields
			case protocol.AssetTransferTx:
				v0, err := protocol.RandomizeObject(&txn.Txn.AssetTransferTxnFields)
				require.NoError(t, err)
				AssetTransferTxnFields, ok := v0.(*transactions.AssetTransferTxnFields)
				require.True(t, ok)
				txn.Txn.AssetTransferTxnFields = *AssetTransferTxnFields
			case protocol.AssetFreezeTx:
				v0, err := protocol.RandomizeObject(&txn.Txn.AssetFreezeTxnFields)
				require.NoError(t, err)
				AssetFreezeTxnFields, ok := v0.(*transactions.AssetFreezeTxnFields)
				require.True(t, ok)
				txn.Txn.AssetFreezeTxnFields = *AssetFreezeTxnFields
			case protocol.ApplicationCallTx:
				v0, err := protocol.RandomizeObject(&txn.Txn.ApplicationCallTxnFields)
				require.NoError(t, err)
				ApplicationCallTxnFields, ok := v0.(*transactions.ApplicationCallTxnFields)
				require.True(t, ok)
				txn.Txn.ApplicationCallTxnFields = *ApplicationCallTxnFields
				txn.Txn.ApplicationCallTxnFields.OnCompletion = 1
			case protocol.CompactCertTx:
				v0, err := protocol.RandomizeObject(&txn.Txn.CompactCertTxnFields)
				require.NoError(t, err)
				CompactCertTxnFields, ok := v0.(*transactions.CompactCertTxnFields)
				require.True(t, ok)
				txn.Txn.CompactCertTxnFields = *CompactCertTxnFields
			default:
				require.Fail(t, "unsupported txntype for txnsync msg encoding")
			}
			txn.Txn.Group = crypto.Digest{}
			txns = append(txns, txn)
		}
		txnGroups := []transactions.SignedTxGroup{
			transactions.SignedTxGroup{
				Transactions: txns,
			},
		}
		addGroupHashes(txnGroups, len(txns), []byte{1})

		encodedGroupsBytes := encodeTransactionGroups(txnGroups)
		out, err := decodeTransactionGroups(encodedGroupsBytes)
		require.NoError(t, err)
		require.ElementsMatch(t, txnGroups, out)
	}
}
