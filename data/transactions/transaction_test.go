// Copyright (C) 2019-2025 Algorand, Inc.
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

package transactions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestTransaction_EstimateEncodedSize(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	buf := make([]byte, 10)
	crypto.RandBytes(buf[:])

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	tx := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender:     addr,
			Fee:        basics.MicroAlgos{Raw: 100},
			FirstValid: basics.Round(1000),
			LastValid:  basics.Round(1000 + proto.MaxTxnLife),
			Note:       buf,
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver: addr,
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}

	require.Equal(t, 200, tx.EstimateEncodedSize())
}

// TestTransactionHash checks that Transaction.ID() is equivalent to the old simpler crypto.HashObj() implementation.
func TestTransactionHash(t *testing.T) {
	partitiontest.PartitionTest(t)

	var txn Transaction
	txn.Sender[1] = 3
	txn.Fee.Raw = 1234
	txid := txn.ID()
	txid2 := Txid(crypto.HashObj(txn))
	require.Equal(t, txid, txid2)

	txn.LastValid = 4321
	txid3 := txn.ID()
	txid2 = Txid(crypto.HashObj(txn))
	require.NotEqual(t, txid, txid3)
	require.Equal(t, txid3, txid2)
}

func TestTransactionIDChanges(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	txn := Transaction{
		Type: "pay",
		Header: Header{
			Sender:     [32]byte{0x01},
			Fee:        basics.MicroAlgos{Raw: 10_000},
			FirstValid: 100,
			LastValid:  200,
			Note:       []byte{0x02},
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver:         [32]byte{0x03},
			Amount:           basics.MicroAlgos{Raw: 200_000},
			CloseRemainderTo: [32]byte{0x04},
		},
	}

	// Make a copy of txn, change some fields, be sure the TXID changes. This is not exhaustive.
	txn2 := txn
	txn2.Note = []byte{42}
	if txn2.ID() == txn.ID() {
		t.Errorf("txid does not depend on note")
	}
	txn2 = txn
	txn2.Amount.Raw++
	if txn2.ID() == txn.ID() {
		t.Errorf("txid does not depend on amount")
	}
	txn2 = txn
	txn2.Fee.Raw++
	if txn2.ID() == txn.ID() {
		t.Errorf("txid does not depend on fee")
	}
	txn2 = txn
	txn2.LastValid++
	if txn2.ID() == txn.ID() {
		t.Errorf("txid does not depend on lastvalid")
	}
}

func TestApplyDataEquality(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var empty ApplyData
	for _, ad := range basics_testing.NearZeros(t, ApplyData{}) {
		assert.False(t, ad.Equal(empty), "Equal() seems to be disregarding something %+v", ad)
	}

}

func TestEvalDataEquality(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var empty EvalDelta
	for _, ed := range basics_testing.NearZeros(t, EvalDelta{}) {
		assert.False(t, ed.Equal(empty), "Equal() seems to be disregarding something %+v", ed)
	}

}

func TestLogicSigEquality(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var empty LogicSig
	for _, ls := range basics_testing.NearZeros(t, LogicSig{}) {
		assert.False(t, ls.Equal(&empty), "Equal() seems to be disregarding something %+v", ls)
	}

}
