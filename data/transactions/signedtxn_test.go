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

package transactions

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testPartitioning"
)

func TestEncoding(t *testing.T) {
	testPartitioning.PartitionTest(t)

	secrets := keypair()
	zeroPayment := Transaction{Type: protocol.PaymentTx}
	zeroKeyReg := Transaction{Type: protocol.KeyRegistrationTx}
	require.NotEqual(t, zeroPayment.ID(), zeroKeyReg.ID(), "Empty payment and empty key reg have the same Txid -- domain separation is broken")

	stxn1 := zeroPayment.Sign(secrets)
	stxn2 := zeroKeyReg.Sign(secrets)

	ids := make(map[Txid]bool)
	ids[stxn1.ID()] = true
	ids[stxn2.ID()] = true
	require.Len(t, ids, 2, "Signed payment and signed key reg have the same Txid -- either domain separation or txid caching is broken")

	paymentBytes := protocol.Encode(&stxn1)
	keyRegBytes := protocol.Encode(&stxn2)

	bytes := make(map[crypto.Digest]bool)
	bytes[crypto.Hash(paymentBytes)] = true
	bytes[crypto.Hash(keyRegBytes)] = true
	require.Len(t, bytes, 2, "Encoding of a signed payment and a signed key reg were identical")

	var decodedPayment, decodedKeyReg SignedTxn
	require.NoError(t, protocol.Decode(paymentBytes, &decodedPayment), "error decoding encoded signed payment")
	require.NoError(t, protocol.Decode(keyRegBytes, &decodedKeyReg), "error decoding encoded signed keyreg")

	if decodedPayment.Txn.Type != protocol.PaymentTx {
		t.Errorf("decoding a signed payment gave a signedtxn of the wrong type: %v", decodedPayment.Txn)
	}
	if decodedKeyReg.Txn.Type != protocol.KeyRegistrationTx {
		t.Errorf("decoding a signed keyreg gave a signedtxn of the wrong type: %v", decodedKeyReg.Txn)
	}
}

func TestDecodeNil(t *testing.T) {
	testPartitioning.PartitionTest(t)

	// This is a regression test for improper decoding of a nil SignedTxn.
	// This is a subtle case because decoding a msgpack nil does not run
	// SignedTxn.CodecDecodeSelf().
	nilEncoding := []byte{0xc0}

	var st SignedTxn
	err := protocol.Decode(nilEncoding, &st)
	if err == nil {
		// This function used to panic when run on a zero value of SignedTxn.
		st.ID()
	}
}

func TestSignedTxnInBlockHash(t *testing.T) {
	testPartitioning.PartitionTest(t)

	var stib SignedTxnInBlock
	crypto.RandBytes(stib.Txn.Sender[:])
	require.Equal(t, crypto.HashObj(&stib), stib.Hash())
}

//TODO: test multisig
