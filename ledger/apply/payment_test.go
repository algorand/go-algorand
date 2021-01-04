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

package apply

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

var spec = transactions.SpecialAddresses{
	FeeSink:     feeSink,
	RewardsPool: poolAddr,
}

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

func TestAlgosEncoding(t *testing.T) {
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

type mockBalances struct {
	protocol.ConsensusVersion
}

func (balances mockBalances) Round() basics.Round {
	return basics.Round(8675309)
}

func (balances mockBalances) Allocate(basics.Address, basics.AppIndex, bool, basics.StateSchema) error {
	return nil
}

func (balances mockBalances) Deallocate(basics.Address, basics.AppIndex, bool) error {
	return nil
}

func (balances mockBalances) StatefulEval(logic.EvalParams, basics.AppIndex, []byte) (bool, basics.EvalDelta, error) {
	return false, basics.EvalDelta{}, nil
}

func (balances mockBalances) PutWithCreatable(basics.Address, basics.AccountData, *basics.CreatableLocator, *basics.CreatableLocator) error {
	return nil
}

func (balances mockBalances) Get(basics.Address, bool) (basics.AccountData, error) {
	return basics.AccountData{}, nil
}

func (balances mockBalances) GetCreator(idx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return basics.Address{}, true, nil
}

func (balances mockBalances) Put(basics.Address, basics.AccountData) error {
	return nil
}

func (balances mockBalances) Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards, dstRewards *basics.MicroAlgos) error {
	return nil
}

func (balances mockBalances) ConsensusParams() config.ConsensusParams {
	return config.Consensus[balances.ConsensusVersion]
}

func TestPaymentApply(t *testing.T) {
	mockBalV0 := mockBalances{protocol.ConsensusCurrentVersion}

	secretSrc := keypair()
	src := basics.Address(secretSrc.SignatureVerifier)

	secretDst := keypair()
	dst := basics.Address(secretDst.SignatureVerifier)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     src,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: dst,
			Amount:   basics.MicroAlgos{Raw: uint64(50)},
		},
	}
	var ad transactions.ApplyData
	err := Payment(tx.PaymentTxnFields, tx.Header, mockBalV0, transactions.SpecialAddresses{FeeSink: feeSink}, &ad)
	require.NoError(t, err)
}

func TestCheckSpender(t *testing.T) {
	mockBalV0 := mockBalances{protocol.ConsensusCurrentVersion}
	mockBalV7 := mockBalances{protocol.ConsensusV7}

	secretSrc := keypair()
	src := basics.Address(secretSrc.SignatureVerifier)

	secretDst := keypair()
	dst := basics.Address(secretDst.SignatureVerifier)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     src,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: dst,
			Amount:   basics.MicroAlgos{Raw: uint64(50)},
		},
	}

	tx.Sender = basics.Address(feeSink)
	require.Error(t, checkSpender(tx.PaymentTxnFields, tx.Header, spec, mockBalV0.ConsensusParams()))

	poolAddr := basics.Address(poolAddr)
	tx.Receiver = poolAddr
	require.NoError(t, checkSpender(tx.PaymentTxnFields, tx.Header, spec, mockBalV0.ConsensusParams()))

	tx.CloseRemainderTo = poolAddr
	require.Error(t, checkSpender(tx.PaymentTxnFields, tx.Header, spec, mockBalV0.ConsensusParams()))
	require.Error(t, checkSpender(tx.PaymentTxnFields, tx.Header, spec, mockBalV7.ConsensusParams()))

	tx.Sender = src
	require.NoError(t, checkSpender(tx.PaymentTxnFields, tx.Header, spec, mockBalV7.ConsensusParams()))
}

func TestPaymentValidation(t *testing.T) {
	payments, _, _, _ := generateTestObjects(100, 50)
	genHash := crypto.Digest{0x42}
	for i, txn := range payments {
		txn.GenesisHash = genHash
		payments[i] = txn
	}
	tc := transactions.ExplicitTxnContext{
		Proto:   config.Consensus[protocol.ConsensusCurrentVersion],
		GenHash: genHash,
	}
	for _, txn := range payments {
		// Lifetime window
		tc.ExplicitRound = txn.First() + 1
		if txn.Alive(tc) != nil {
			t.Errorf("transaction not alive during lifetime %v", txn)
		}

		tc.ExplicitRound = txn.First()
		if txn.Alive(tc) != nil {
			t.Errorf("transaction not alive at issuance %v", txn)
		}

		tc.ExplicitRound = txn.Last()
		if txn.Alive(tc) != nil {
			t.Errorf("transaction not alive at expiry %v", txn)
		}

		tc.ExplicitRound = txn.First() - 1
		if txn.Alive(tc) == nil {
			t.Errorf("premature transaction alive %v", txn)
		}

		tc.ExplicitRound = txn.Last() + 1
		if txn.Alive(tc) == nil {
			t.Errorf("expired transaction alive %v", txn)
		}

		// Make a copy of txn, change some fields, be sure the TXID changes. This is not exhaustive.
		var txn2 transactions.Transaction
		txn2 = txn
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

		// Check malformed transactions
		largeWindow := txn
		largeWindow.LastValid += basics.Round(tc.Proto.MaxTxnLife)
		if largeWindow.WellFormed(spec, tc.Proto) == nil {
			t.Errorf("transaction with large window %#v verified incorrectly", largeWindow)
		}

		badWindow := txn
		badWindow.LastValid = badWindow.FirstValid - 1
		if badWindow.WellFormed(spec, tc.Proto) == nil {
			t.Errorf("transaction with bad window %#v verified incorrectly", badWindow)
		}

		badFee := txn
		badFee.Fee = basics.MicroAlgos{}
		if badFee.WellFormed(spec, tc.Proto) == nil {
			t.Errorf("transaction with no fee %#v verified incorrectly", badFee)
		}
	}
}

func TestPaymentSelfClose(t *testing.T) {
	secretSrc := keypair()
	src := basics.Address(secretSrc.SignatureVerifier)

	secretDst := keypair()
	dst := basics.Address(secretDst.SignatureVerifier)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     src,
			Fee:        basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         dst,
			Amount:           basics.MicroAlgos{Raw: uint64(50)},
			CloseRemainderTo: src,
		},
	}
	require.Error(t, tx.WellFormed(spec, config.Consensus[protocol.ConsensusCurrentVersion]))
}

func generateTestObjects(numTxs, numAccs int) ([]transactions.Transaction, []transactions.SignedTxn, []*crypto.SignatureSecrets, []basics.Address) {
	txs := make([]transactions.Transaction, numTxs)
	signed := make([]transactions.SignedTxn, numTxs)
	secrets := make([]*crypto.SignatureSecrets, numAccs)
	addresses := make([]basics.Address, numAccs)

	for i := 0; i < numAccs; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	for i := 0; i < numTxs; i++ {
		s := rand.Intn(numAccs)
		r := rand.Intn(numAccs)
		a := rand.Intn(1000)
		f := config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee + uint64(rand.Intn(10))
		iss := 50 + rand.Intn(30)
		exp := iss + 10

		txs[i] = transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:     addresses[s],
				Fee:        basics.MicroAlgos{Raw: f},
				FirstValid: basics.Round(iss),
				LastValid:  basics.Round(exp),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: addresses[r],
				Amount:   basics.MicroAlgos{Raw: uint64(a)},
			},
		}
		signed[i] = txs[i].Sign(secrets[s])
	}

	return txs, signed, secrets, addresses
}
