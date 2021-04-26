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
	"fmt"
	"io"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

func TestTxnGroupEncodingSmall(t *testing.T) {
	genesisHash := crypto.Hash([]byte("gh"))

	inTxnGroups := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{
				{
					Txn: transactions.Transaction{
						Type: protocol.PaymentTx,
						Header: transactions.Header{
							Sender: basics.Address(crypto.Hash([]byte("2"))),
							Fee: basics.MicroAlgos{Raw: 100},
							GenesisHash: genesisHash,
						},
						PaymentTxnFields: transactions.PaymentTxnFields{
							Receiver: basics.Address(crypto.Hash([]byte("4"))),
							Amount: basics.MicroAlgos{Raw: 1000},
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
							Sender: basics.Address(crypto.Hash([]byte("1"))),
							Fee: basics.MicroAlgos{Raw: 100},
							GenesisHash: genesisHash,
						},
						PaymentTxnFields: transactions.PaymentTxnFields{
							Receiver: basics.Address(crypto.Hash([]byte("2"))),
							Amount: basics.MicroAlgos{Raw: 1000},
						},
					},
					Sig: crypto.Signature{2},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.KeyRegistrationTx,
						Header: transactions.Header{
							Sender: basics.Address(crypto.Hash([]byte("1"))),
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
							Sender: basics.Address(crypto.Hash([]byte("1"))),
							Fee: basics.MicroAlgos{Raw: 100},
							GenesisHash: genesisHash,
						},
					},
					Sig: crypto.Signature{4},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.AssetFreezeTx,
						Header: transactions.Header{
							Sender: basics.Address(crypto.Hash([]byte("1"))),
							GenesisHash: genesisHash,
						},
					},
					Sig: crypto.Signature{5},
				},
				{
					Txn: transactions.Transaction{
						Type: protocol.CompactCertTx,
						Header: transactions.Header{
							Sender: basics.Address(crypto.Hash([]byte("1"))),
							GenesisHash: genesisHash,
						},
					},
					Msig: crypto.MultisigSig{Version: 1},
				},
			},
		},
	}
	addGroupHashes(inTxnGroups)
	encodedGroupsBytes := encodeTransactionGroups(inTxnGroups)
	fmt.Println(len(encodedGroupsBytes))
	fmt.Println(string(encodedGroupsBytes))
	out, err := decodeTransactionGroups(encodedGroupsBytes)
	require.NoError(t, err)
	require.ElementsMatch(t, inTxnGroups, out)
}

func TestTxnGroupEncodingLarge(t *testing.T) {
	dat, err := ioutil.ReadFile("/Users/nicholas/Downloads/txns.txt")
	require.NoError(t, err)
	dec := protocol.NewDecoderBytes(dat)
	ntx := 0
	blocksData := make([]rpcs.EncodedBlockCert, 1)
	for {
		if len(blocksData) == ntx {
			n := make([]rpcs.EncodedBlockCert, len(blocksData)*2)
			copy(n, blocksData)
			blocksData = n
		}

		err := dec.Decode(&blocksData[ntx])
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		ntx++
	}
	blocksData = blocksData[:ntx]
	fmt.Println("blocks: ", len(blocksData))

	var txnGroups []transactions.SignedTxGroup
	for _, blockData := range blocksData {
		block := blockData.Block
		payset, err := block.DecodePaysetGroups()
		require.NoError(t, err)
		for _, txns := range payset {
			var txnGroup transactions.SignedTxGroup
			for _, txn := range txns {
				txnGroup.Transactions = append(txnGroup.Transactions, txn.SignedTxn)
			}
			txnGroups = append(txnGroups, txnGroup)
		}
	}
	fmt.Println("txngroups: ", len(txnGroups))

	encodedGroupsBytes := encodeTransactionGroups(txnGroups)
	fmt.Println("new data: ", len(encodedGroupsBytes))
	out, err := decodeTransactionGroups(encodedGroupsBytes)
	require.NoError(t, err)
	require.ElementsMatch(t, txnGroups, out)

	encodedGroupsBytes = encodeTransactionGroupsOld(txnGroups)
	fmt.Println("old data: ", len(encodedGroupsBytes))
	out, err = decodeTransactionGroupsOld(encodedGroupsBytes)
	require.NoError(t, err)
	require.ElementsMatch(t, txnGroups, out)
}
