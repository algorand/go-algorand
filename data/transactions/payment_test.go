// Copyright (C) 2019 Algorand, Inc.
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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

var spec = SpecialAddresses{
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
	err := protocol.Decode(protocol.Encode(a), &b)
	if err != nil {
		panic(err)
	}
	require.Equal(t, a, b)

	a.Raw = 12345678
	err = protocol.Decode(protocol.Encode(a), &i)
	if err != nil {
		panic(err)
	}
	require.Equal(t, a.Raw, i)

	i = 87654321
	err = protocol.Decode(protocol.Encode(i), &a)
	if err != nil {
		panic(err)
	}
	require.Equal(t, a.Raw, i)

	x := true
	err = protocol.Decode(protocol.Encode(x), &a)
	if err == nil {
		panic("decode of bool into MicroAlgos succeeded")
	}
}

type mockBalances struct {
	protocol.ConsensusVersion
}

func (balances mockBalances) Get(basics.Address) (basics.BalanceRecord, error) {
	return basics.BalanceRecord{}, nil
}

func (balances mockBalances) Put(basics.BalanceRecord) error {
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

	tx := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender:     src,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver: dst,
			Amount:   basics.MicroAlgos{Raw: uint64(50)},
		},
	}
	_, err := tx.Apply(mockBalV0, SpecialAddresses{FeeSink: feeSink})
	require.NoError(t, err)
}

func TestCheckSpender(t *testing.T) {
	mockBalV0 := mockBalances{protocol.ConsensusCurrentVersion}
	mockBalV7 := mockBalances{protocol.ConsensusV7}

	secretSrc := keypair()
	src := basics.Address(secretSrc.SignatureVerifier)

	secretDst := keypair()
	dst := basics.Address(secretDst.SignatureVerifier)

	tx := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender:     src,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver: dst,
			Amount:   basics.MicroAlgos{Raw: uint64(50)},
		},
	}

	tx.Sender = basics.Address(feeSink)
	require.Error(t, tx.checkSpender(tx.Header, spec, mockBalV0.ConsensusParams()))

	poolAddr := basics.Address(poolAddr)
	tx.Receiver = poolAddr
	require.NoError(t, tx.checkSpender(tx.Header, spec, mockBalV0.ConsensusParams()))

	tx.CloseRemainderTo = poolAddr
	require.Error(t, tx.checkSpender(tx.Header, spec, mockBalV0.ConsensusParams()))
	require.Error(t, tx.checkSpender(tx.Header, spec, mockBalV7.ConsensusParams()))

	tx.Sender = src
	require.NoError(t, tx.checkSpender(tx.Header, spec, mockBalV7.ConsensusParams()))
}

func TestPaymentValidation(t *testing.T) {
	payments, _, _, _ := generateTestObjects(100, 50)
	genHash := crypto.Digest{0x42}
	for i, txn := range payments {
		txn.GenesisHash = genHash
		payments[i] = txn
	}
	tc := ExplicitTxnContext{
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
		var txn2 Transaction
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

	tx := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender:     src,
			Fee:        basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver:         dst,
			Amount:           basics.MicroAlgos{Raw: uint64(50)},
			CloseRemainderTo: src,
		},
	}
	require.Error(t, tx.WellFormed(spec, config.Consensus[protocol.ConsensusCurrentVersion]))
}

func TestSignedPayment(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	payments, stxns, secrets, addrs := generateTestObjects(1, 1)
	payment, stxn, secret, addr := payments[0], stxns[0], secrets[0], addrs[0]

	require.NoError(t, payment.WellFormed(spec, proto), "generateTestObjects generated an invalid payment")
	require.NoError(t, stxn.Verify(spec, proto), "generateTestObjects generated a bad signedtxn")

	stxn2 := payment.Sign(secret)
	require.Equal(t, stxn2.Sig, stxn.Sig, "got two different signatures for the same transaction (our signing function is deterministic)")

	stxn2.MessUpSigForTesting()
	require.Equal(t, stxn.ID(), stxn2.ID(), "changing sig caused txid to change")
	require.Error(t, stxn2.Verify(spec, proto), "verify succeeded with bad sig")

	require.True(t, crypto.SignatureVerifier(addr).Verify(payment, stxn.Sig), "signature on the transaction is not the signature of the hash of the transaction under the spender's key")
}

/*
func TestTxnValidation(t *testing.T) {
	_, signed, _, _ := generateTestObjects(100, 50)
	tc := ExplicitTxnContext{
		Proto: config.Consensus[protocol.ConsensusCurrentVersion],
	}

	for i, stxn := range signed {
		if stxn.Verify() != nil {
			t.Errorf("signed transaction %#v did not verify", stxn)
		}
		txn := stxn.Transaction.(Payment)

		tc.ExplicitRound = txn.First()+1
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

		tc.ExplicitRound = txn.First()-1
		if txn.Alive(tc) != nil {
			t.Errorf("premature transaction alive %v", txn)
		}

		tc.ExplicitRound = txn.Last()+1
		if txn.Alive(tc) != nil {
			t.Errorf("expired transaction alive %v", txn)
		}

		badSig := stxn
		otherTransaction := txn
		otherTransaction.Note = []byte{42}
		badSig.Transaction = &otherTransaction
		badSig.InitCaches()
		if badSig.Verify() == nil {
			t.Errorf("modified transaction %#v verified incorrectly", badSig)
		}

		noSig := stxn
		noSig.Sig = crypto.Signature{}
		if noSig.Verify() == nil {
			t.Errorf("transaction with no signature %#v verified incorrectly", noSig)
		}

		largeWindow := stxn
		largeWindow.LastValid += basics.Round(config.Protocol.MaxTxnLife)
		if largeWindow.Verify() == nil {
			t.Errorf("transaction with large window %#v verified incorrectly", largeWindow)
		}

		badWindow := txn
		badWindow.Payment.LastValid = badWindow.Payment.FirstValid - 1
		if badWindow.Verify() == nil {
			t.Errorf("transaction with bad window %#v verified incorrectly", badWindow)
		}

		badFee := txn
		badFee.Payment.Fee = basics.MicroAlgos{}
		if badFee.Verify() == nil {
			t.Errorf("transaction with small fee %#v verified incorrectly", badFee)
		}

		overflow := txn
		overflow.Payment.Amount = basics.MicroAlgos{}
		overflow.Payment.Fee = basics.MicroAlgos{Raw: 10}
		if overflow.Verify() == nil {
			t.Errorf("transaction with overflowing amount %#v verified incorrectly", overflow)
		}

		if i > 5 {
			break
		}
	}
}
*/

func TestTxnValidationEncodeDecode(t *testing.T) {
	_, signed, _, _ := generateTestObjects(100, 50)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	for _, txn := range signed {
		if txn.Verify(spec, proto) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}

		x := protocol.Encode(txn)
		var signedTx SignedTxn
		protocol.Decode(x, &signedTx)

		if signedTx.Verify(spec, proto) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}
	}
}
