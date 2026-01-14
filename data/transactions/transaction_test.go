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

func TestHeaderFieldCount(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// When a field is added to the transaction header, this test will fail as
	// a reminder to consider whether the field should be banned from use by
	// stateproofs and/or free heartbeats. Adjust their wellFormed methods and
	// then change the value in the test.
	assert.Equal(t, 12, reflect.TypeFor[Header]().NumField())
}

// TestFeeFactor_BigNotes tests the FeeFactor calculation with various Note sizes
func TestFeeFactor_BigNotes(t *testing.T) {
	partitiontest.PartitionTest(t)

	v41 := config.Consensus[protocol.ConsensusV41]
	vFuture := config.Consensus[protocol.ConsensusFuture]

	tests := []struct {
		name           string
		proto          config.ConsensusParams
		noteSize       int
		expectedFactor basics.Micros
	}{
		// v41: MaxAbsoluteTxnNoteBytes = MaxTxnNoteBytes = 1024
		{
			name:           "v41: standard note size (1024 bytes)",
			proto:          v41,
			noteSize:       1024,
			expectedFactor: 1e6,
		},
		// vFuture: MaxAbsoluteTxnNoteBytes = 4096, so larger notes are allowed
		{
			name:           "vFuture: standard note size (1024 bytes)",
			proto:          vFuture,
			noteSize:       1024,
			expectedFactor: 1e6,
		},
		{
			name:           "vFuture: 1 extra byte (1025 bytes)",
			proto:          vFuture,
			noteSize:       1025,
			expectedFactor: 1e6 + 1000,
		},
		{
			name:           "vFuture: 100 extra bytes (1124 bytes)",
			proto:          vFuture,
			noteSize:       1124,
			expectedFactor: 1e6 + 100000,
		},
		{
			name:           "vFuture: 1024 extra bytes (2048 bytes)",
			proto:          vFuture,
			noteSize:       2048,
			expectedFactor: 1e6 + 1024000,
		},
		{
			name:           "vFuture: maximum allowed (4096 bytes)",
			proto:          vFuture,
			noteSize:       4096,
			expectedFactor: 1e6 + (4096-1024)*1000,
		},
	}

	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := Transaction{
				Type: protocol.PaymentTx,
				Header: Header{
					Sender:     addr,
					Fee:        basics.MicroAlgos{Raw: 1000},
					FirstValid: 100,
					LastValid:  200,
					Note:       make([]byte, tt.noteSize),
				},
				PaymentTxnFields: PaymentTxnFields{
					Receiver: addr,
					Amount:   basics.MicroAlgos{Raw: 1000},
				},
			}

			factor := tx.FeeFactor(tt.proto)
			assert.Equal(t, tt.expectedFactor, factor, "FeeFactor mismatch for note size %d", tt.noteSize)
		})
	}
}

// TestFeeFactor_StateProofAndHeartbeat tests that StateProof and Heartbeat transactions
// maintain their special fee behavior even with large Notes
func TestFeeFactor_StateProofAndHeartbeat(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	vFuture := config.Consensus[protocol.ConsensusFuture]
	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	// StateProof transactions should always be free. (Notes aren't actually
	// allowed, but that's up to WellFormed to deal with.)
	stateProofTx := Transaction{
		Type: protocol.StateProofTx,
		Header: Header{
			Sender:     addr,
			FirstValid: 100,
			LastValid:  200,
			Note:       make([]byte, 2048), // Large note
		},
	}
	assert.Equal(t, basics.Micros(0), stateProofTx.FeeFactor(vFuture), "StateProof should be free")

	// Singleton heartbeat (no group) should be free. Again, having a note is
	// not allowed in a free heartbeat, but that is checked elsewhere.
	singletonHeartbeat := Transaction{
		Type: protocol.HeartbeatTx,
		Header: Header{
			Sender:     addr,
			FirstValid: 100,
			LastValid:  200,
			Note:       make([]byte, 2048), // Large note
		},
	}
	assert.Equal(t, basics.Micros(0), singletonHeartbeat.FeeFactor(vFuture), "Singleton heartbeat should be free")

	// Grouped heartbeat should have normal fee
	groupedHeartbeat := Transaction{
		Type: protocol.HeartbeatTx,
		Header: Header{
			Sender:     addr,
			FirstValid: 100,
			LastValid:  200,
			Note:       make([]byte, 1024),
			Group:      crypto.Digest{1}, // Has a group
		},
	}
	assert.Equal(t, basics.Micros(1e6), groupedHeartbeat.FeeFactor(vFuture), "Grouped heartbeat should have base fee")

	// Grouped heartbeat with big note should have the extra charge for it
	groupedHeartbeatBigNote := Transaction{
		Type: protocol.HeartbeatTx,
		Header: Header{
			Sender:     addr,
			FirstValid: 100,
			LastValid:  200,
			Note:       make([]byte, 1124),
			Group:      crypto.Digest{1}, // Has a group
		},
	}
	assert.Equal(t, basics.Micros(1_100_000), groupedHeartbeatBigNote.FeeFactor(vFuture), "Grouped heartbeat should have extra fee")
}

// TestWellFormed_BigNotes tests Note size validation with MaxAbsoluteTxnNoteBytes
func TestWellFormed_BigNotes(t *testing.T) {
	partitiontest.PartitionTest(t)

	v41 := config.Consensus[protocol.ConsensusV41]
	vFuture := config.Consensus[protocol.ConsensusFuture]

	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	spec := SpecialAddresses{
		FeeSink:     basics.Address{0x01},
		RewardsPool: basics.Address{0x02},
	}

	tests := []struct {
		name        string
		proto       config.ConsensusParams
		noteSize    int
		shouldError bool
		errorMsg    string
	}{
		// v41: MaxAbsoluteTxnNoteBytes = MaxTxnNoteBytes = 1024
		{
			name:        "v41: note at limit (1024 bytes) - pass",
			proto:       v41,
			noteSize:    1024,
			shouldError: false,
		},
		{
			name:        "v41: note over limit (1025 bytes) - fail",
			proto:       v41,
			noteSize:    1025,
			shouldError: true,
			errorMsg:    "transaction note too big: 1025 > 1024",
		},
		{
			name:        "v41: large note (2048 bytes) - fail",
			proto:       v41,
			noteSize:    2048,
			shouldError: true,
			errorMsg:    "transaction note too big: 2048 > 1024",
		},
		// vFuture: MaxAbsoluteTxnNoteBytes = 16384, allows larger notes
		{
			name:        "vFuture: note at standard limit (1024 bytes) - pass",
			proto:       vFuture,
			noteSize:    1024,
			shouldError: false,
		},
		{
			name:        "vFuture: note over standard limit (1025 bytes) - pass",
			proto:       vFuture,
			noteSize:    1025,
			shouldError: false,
		},
		{
			name:        "vFuture: large note (2048 bytes) - pass",
			proto:       vFuture,
			noteSize:    2048,
			shouldError: false,
		},
		{
			name:        "vFuture: note at absolute limit (4096 bytes) - pass",
			proto:       vFuture,
			noteSize:    4096,
			shouldError: false,
		},
		{
			name:        "vFuture: note over absolute limit (4097 bytes) - fail",
			proto:       vFuture,
			noteSize:    4097,
			shouldError: true,
			errorMsg:    "transaction note too big: 4097 > 4096",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := Transaction{
				Type: protocol.PaymentTx,
				Header: Header{
					Sender:     addr,
					Fee:        basics.MicroAlgos{Raw: 100000}, // High enough for any test
					FirstValid: 100,
					LastValid:  200,
					Note:       make([]byte, tt.noteSize),
				},
				PaymentTxnFields: PaymentTxnFields{
					Receiver: addr,
					Amount:   basics.MicroAlgos{Raw: 1000},
				},
			}

			err := tx.WellFormed(spec, tt.proto)
			if tt.shouldError {
				require.Error(t, err, "Expected error for note size %d", tt.noteSize)
				assert.Contains(t, err.Error(), tt.errorMsg, "Error message mismatch")
			} else {
				require.NoError(t, err, "Unexpected error for note size %d", tt.noteSize)
			}
		})
	}
}

// TestSummarizeFees_BigNotes tests fee summarization with large Notes
func TestSummarizeFees_BigNotes(t *testing.T) {
	partitiontest.PartitionTest(t)

	v41 := config.Consensus[protocol.ConsensusV41]
	vFuture := config.Consensus[protocol.ConsensusFuture]

	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	// Test case 1: Single transaction with large note in vFuture
	t.Run("vFuture: single txn with 2KB note", func(t *testing.T) {
		tx := Transaction{
			Type: protocol.PaymentTx,
			Header: Header{
				Sender:     addr,
				Fee:        basics.MicroAlgos{Raw: 10000},
				FirstValid: 100,
				LastValid:  200,
				Note:       make([]byte, 2048),
			},
			PaymentTxnFields: PaymentTxnFields{
				Receiver: addr,
				Amount:   basics.MicroAlgos{Raw: 1000},
			},
		}

		stxn := SignedTxn{Txn: tx}
		stxnAD := SignedTxnWithAD{SignedTxn: stxn}

		usage, paid, tip := SummarizeFees([]SignedTxnWithAD{stxnAD}, vFuture)

		// Expected: 1e6 + (2048-1024)*1000 = 1e6 + 1024000 = 2024000
		assert.Equal(t, basics.Micros(2024000), usage, "Usage calculation incorrect")
		assert.Equal(t, basics.MicroAlgos{Raw: 10000}, paid, "Paid amount incorrect")
		assert.Equal(t, basics.Micros(0), tip, "Tip should be 0")
	})

	// Test case 2: Transaction group with mixed note sizes in vFuture
	t.Run("vFuture: group with mixed note sizes", func(t *testing.T) {
		// Transaction 1: standard note (1024 bytes)
		tx1 := Transaction{
			Type: protocol.PaymentTx,
			Header: Header{
				Sender:     addr,
				Fee:        basics.MicroAlgos{Raw: 1000},
				FirstValid: 100,
				LastValid:  200,
				Note:       make([]byte, 1024),
			},
			PaymentTxnFields: PaymentTxnFields{
				Receiver: addr,
				Amount:   basics.MicroAlgos{Raw: 1000},
			},
		}

		// Transaction 2: large note (2048 bytes)
		tx2 := Transaction{
			Type: protocol.PaymentTx,
			Header: Header{
				Sender:     addr,
				Fee:        basics.MicroAlgos{Raw: 2024},
				FirstValid: 100,
				LastValid:  200,
				Note:       make([]byte, 2048),
			},
			PaymentTxnFields: PaymentTxnFields{
				Receiver: addr,
				Amount:   basics.MicroAlgos{Raw: 1000},
			},
		}

		stxn1 := SignedTxn{Txn: tx1}
		stxn2 := SignedTxn{Txn: tx2}
		group := []SignedTxnWithAD{
			{SignedTxn: stxn1},
			{SignedTxn: stxn2},
		}

		usage, paid, tip := SummarizeFees(group, vFuture)

		// Expected usage: 1e6 + (1e6 + 1024000) = 3024000
		assert.Equal(t, basics.Micros(3024000), usage, "Group usage calculation incorrect")
		assert.Equal(t, basics.MicroAlgos{Raw: 3024}, paid, "Group paid amount incorrect")
		assert.Equal(t, basics.Micros(0), tip, "Tip should be 0")
	})

	// Test case 3: Transaction in v41 (MaxAbsoluteTxnNoteBytes = 1024)
	t.Run("v41: standard note has base fee", func(t *testing.T) {
		tx := Transaction{
			Type: protocol.PaymentTx,
			Header: Header{
				Sender:     addr,
				Fee:        basics.MicroAlgos{Raw: 1000},
				FirstValid: 100,
				LastValid:  200,
				Note:       make([]byte, 1024), // At the limit in v41
			},
			PaymentTxnFields: PaymentTxnFields{
				Receiver: addr,
				Amount:   basics.MicroAlgos{Raw: 1000},
			},
		}

		stxn := SignedTxn{Txn: tx}
		stxnAD := SignedTxnWithAD{SignedTxn: stxn}

		usage, paid, tip := SummarizeFees([]SignedTxnWithAD{stxnAD}, v41)

		// Expected: just base fee of 1e6, no extra charge since at MaxTxnNoteBytes
		assert.Equal(t, basics.Micros(1e6), usage, "Usage should be base fee only in v41")
		assert.Equal(t, basics.MicroAlgos{Raw: 1000}, paid, "Paid amount incorrect")
		assert.Equal(t, basics.Micros(0), tip, "Tip should be 0")
	})

	// Test case 4: With tip
	t.Run("vFuture: large note with tip", func(t *testing.T) {
		tx := Transaction{
			Type: protocol.PaymentTx,
			Header: Header{
				Sender:     addr,
				Fee:        basics.MicroAlgos{Raw: 10000},
				FirstValid: 100,
				LastValid:  200,
				Note:       make([]byte, 2048),
				Tip:        1000, // Tip in micros
			},
			PaymentTxnFields: PaymentTxnFields{
				Receiver: addr,
				Amount:   basics.MicroAlgos{Raw: 1000},
			},
		}

		stxn := SignedTxn{Txn: tx}
		stxnAD := SignedTxnWithAD{SignedTxn: stxn}

		usage, paid, tip := SummarizeFees([]SignedTxnWithAD{stxnAD}, vFuture)

		assert.Equal(t, basics.Micros(2024000), usage, "Usage calculation incorrect with tip")
		assert.Equal(t, basics.MicroAlgos{Raw: 10000}, paid, "Paid amount incorrect")
		assert.Equal(t, basics.Micros(1000), tip, "Tip should be 1000")
	})
}
