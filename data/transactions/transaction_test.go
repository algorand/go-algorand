// Copyright (C) 2019-2026 Algorand, Inc.
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
	"reflect"
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

// TestHeaderWellFormed tests WellFormed for things that are not transaction
// specific (which get tested for the specific transactions).
func TestHeaderWellFormed(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	correctTxn := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender:     basics.Address{0x01},
			Fee:        basics.MicroAlgos{Raw: 1000},
			FirstValid: 100,
			LastValid:  200,
			Note:       []byte{0x02},
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver: basics.Address{0x03},
			Amount:   basics.MicroAlgos{Raw: 1000},
		},
	}

	sp := SpecialAddresses{
		RewardsPool: basics.Address{0xEE},
		FeeSink:     basics.Address{0xFF},
	}

	current := config.Consensus[protocol.ConsensusCurrentVersion]
	future := config.Consensus[protocol.ConsensusFuture]

	a := assert.New(t)

	testGood := func(msg string, fn func(tx *Transaction), protos ...config.ConsensusParams) {
		for _, p := range protos {
			t.Helper()
			copy := correctTxn
			fn(&correctTxn)
			defer func() { correctTxn = copy }()
			err := correctTxn.WellFormed(sp, p)
			a.NoError(err, msg)
		}
	}

	testGood("base case", func(tx *Transaction) {}, current, future)

	testBad := func(msg string, fn func(tx *Transaction), protos ...config.ConsensusParams) {
		for _, p := range protos {
			t.Helper()
			copy := correctTxn
			fn(&correctTxn)
			defer func() { correctTxn = copy }()
			err := correctTxn.WellFormed(sp, p)
			a.ErrorContains(err, msg)
		}
	}
	testBad("invalid range", func(tx *Transaction) {
		tx.FirstValid = tx.LastValid + 1
	}, current, future)
	testBad("window size excessive", func(tx *Transaction) {
		tx.LastValid = tx.FirstValid + 10_000
	}, current, future)
	testBad("note too big", func(tx *Transaction) {
		tx.Note = make([]byte, 10_000)
	}, current, future)
	testBad("from incentive pool is invalid", func(tx *Transaction) {
		tx.Sender = sp.RewardsPool
	}, current, future)
	testBad("cannot have zero sender", func(tx *Transaction) {
		tx.CloseRemainderTo = basics.Address{0x88} // to avoid the early error that sender != closeTo
		tx.Sender = basics.Address{}
	}, current, future)

	// Now test some fields that were added in certain releases
	testAdded := func(msg string, fn func(tx *Transaction), lastBad protocol.ConsensusVersion) {
		t.Helper()
		testBad(msg, fn, config.Consensus[lastBad])
		if lastBad != protocol.ConsensusFuture {
			testGood(msg, fn, future)
		}
	}
	testAdded("tried to acquire lease", func(tx *Transaction) {
		tx.Lease = [32]byte{0x77}
	}, protocol.ConsensusV17)
	testAdded("groups not yet enabled", func(tx *Transaction) {
		tx.Group = crypto.Digest{0x11}
	}, protocol.ConsensusV17)
	testAdded("rekeying not yet enabled", func(tx *Transaction) {
		tx.RekeyTo = basics.Address{0x22}
	}, protocol.ConsensusV23)
	testAdded("tips not yet enabled", func(tx *Transaction) {
		tx.Tip = 10
	}, protocol.ConsensusCurrentVersion) // make explicit after release
}

func TestHeaderFieldCount(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// When a field is added to the transaction header, this test will fail as
	// a reminder to consider whether the field should be banned from use by
	// stateproofs and/or free heartbeats. Adjust their wellFormed methods and
	// then change the value in the test.

	// Such a new field should probably also be consensus flagged at the end of
	// transaction.WellFormed()
	assert.Equal(t, 12, reflect.TypeFor[Header]().NumField())
}
