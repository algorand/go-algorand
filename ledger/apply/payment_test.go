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

package apply

import (
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var spec = transactions.SpecialAddresses{
	FeeSink:     ledgertesting.RandomAddress(),
	RewardsPool: ledgertesting.RandomAddress(),
}

func TestAlgosEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	var a basics.MicroAlgos
	var b basics.MicroAlgos
	var i uint64

	a.Raw = 222233333
	err := protocol.Decode(protocol.Encode(&a), &b)
	if err != nil {
		panic(err)
	}
	require.Equal(t, a, b)

	a.Raw = 12345678
	err = protocol.DecodeReflect(protocol.Encode(a), &i)
	if err != nil {
		panic(err)
	}
	require.Equal(t, a.Raw, i)

	i = 87654321
	err = protocol.Decode(protocol.EncodeReflect(i), &a)
	if err != nil {
		panic(err)
	}
	require.Equal(t, a.Raw, i)

	x := true
	err = protocol.Decode(protocol.EncodeReflect(x), &a)
	if err == nil {
		panic("decode of bool into MicroAlgos succeeded")
	}
}

func TestPaymentApply(t *testing.T) {
	partitiontest.PartitionTest(t)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     ledgertesting.RandomAddress(),
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: ledgertesting.RandomAddress(),
			Amount:   basics.MicroAlgos{Raw: uint64(50)},
		},
	}

	mockBalV0 := makeMockBalances(protocol.ConsensusCurrentVersion)
	var ad transactions.ApplyData
	err := Payment(tx.PaymentTxnFields, tx.Header, mockBalV0, transactions.SpecialAddresses{}, &ad)
	require.NoError(t, err)
}

func TestPaymentValidation(t *testing.T) {
	partitiontest.PartitionTest(t)

	current := config.Consensus[protocol.ConsensusCurrentVersion]
	for _, txn := range generateTestPays(100) {
		// Check malformed transactions
		largeWindow := txn
		largeWindow.LastValid += basics.Round(current.MaxTxnLife)
		if largeWindow.WellFormed(spec, current) == nil {
			t.Errorf("transaction with large window %#v verified incorrectly", largeWindow)
		}

		badWindow := txn
		badWindow.LastValid = badWindow.FirstValid - 1
		if badWindow.WellFormed(spec, current) == nil {
			t.Errorf("transaction with bad window %#v verified incorrectly", badWindow)
		}

		badFee := txn
		badFee.Fee = basics.MicroAlgos{}
		if badFee.WellFormed(spec, config.Consensus[protocol.ConsensusV27]) == nil {
			t.Errorf("transaction with no fee %#v verified incorrectly", badFee)
		}
		assert.NoError(t, badFee.WellFormed(spec, current))

		badFee.Fee.Raw = 1
		if badFee.WellFormed(spec, config.Consensus[protocol.ConsensusV27]) == nil {
			t.Errorf("transaction with low fee %#v verified incorrectly", badFee)
		}
		assert.NoError(t, badFee.WellFormed(spec, current))
	}
}

func TestPaymentSelfClose(t *testing.T) {
	partitiontest.PartitionTest(t)

	self := ledgertesting.RandomAddress()

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     self,
			Fee:        basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         ledgertesting.RandomAddress(),
			Amount:           basics.MicroAlgos{Raw: uint64(50)},
			CloseRemainderTo: self,
		},
	}
	require.Error(t, tx.WellFormed(spec, config.Consensus[protocol.ConsensusCurrentVersion]))
}

func generateTestPays(numTxs int) []transactions.Transaction {
	txs := make([]transactions.Transaction, numTxs)
	for i := range numTxs {
		a := rand.IntN(1000)
		f := config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee + uint64(rand.IntN(10))
		iss := 50 + rand.IntN(30)
		exp := iss + 10

		txs[i] = transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      ledgertesting.RandomAddress(),
				Fee:         basics.MicroAlgos{Raw: f},
				FirstValid:  basics.Round(iss),
				LastValid:   basics.Round(exp),
				GenesisHash: crypto.Digest{0x02},
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: ledgertesting.RandomAddress(),
				Amount:   basics.MicroAlgos{Raw: uint64(a)},
			},
		}
	}
	return txs
}
