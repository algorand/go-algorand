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

package transactions

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type pqSigTestFixture struct {
	signer     crypto.FalconSigner
	proto      config.ConsensusParams
	txn        Transaction
	authorizer basics.Address
	pqSig      PQSig
}

func makePQSigTestFixture(t *testing.T, firstSeedByte byte) pqSigTestFixture {
	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	signer, err := crypto.GenerateFalconSigner(seed)
	require.NoError(t, err)

	publicKey := append([]byte(nil), signer.PublicKey[:]...)
	salt, authorizer, err := basics.CanonicalPQAddressSalt(protocol.PQSchemeFalcon1024, publicKey)
	require.NoError(t, err)

	txn := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender: authorizer,
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver: authorizer,
		},
	}

	signature, err := signer.Sign(txn)
	require.NoError(t, err)

	proto := config.Consensus[protocol.ConsensusFuture]
	require.True(t, proto.EnablePQSchemeFalcon1024)

	return pqSigTestFixture{
		signer:     signer,
		proto:      proto,
		txn:        txn,
		authorizer: authorizer,
		pqSig: PQSig{
			Scheme:    protocol.PQSchemeFalcon1024,
			Salt:      salt,
			PublicKey: publicKey,
			Signature: signature,
		},
	}
}

func TestPQSigBlank(t *testing.T) {
	partitiontest.PartitionTest(t)

	var nilPQSig *PQSig
	require.True(t, nilPQSig.Blank())
	require.True(t, (&PQSig{}).Blank())
	require.True(t, (&PQSig{Salt: 0}).Blank())

	require.False(t, (&PQSig{Salt: 1}).Blank())
	require.False(t, (&PQSig{Scheme: protocol.PQSchemeFalcon1024}).Blank())
	require.False(t, (&PQSig{PublicKey: []byte{1}}).Blank())
	require.False(t, (&PQSig{Signature: []byte{1}}).Blank())
}

func TestPQSigEqual(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)
	same := fixture.pqSig
	same.PublicKey = append([]byte(nil), same.PublicKey...)
	same.Signature = append([]byte(nil), same.Signature...)

	require.True(t, fixture.pqSig.Equal(&same))

	changedScheme := fixture.pqSig
	changedScheme.Scheme = protocol.PQScheme("x1")
	require.False(t, fixture.pqSig.Equal(&changedScheme))

	changedSalt := fixture.pqSig
	changedSalt.Salt++
	require.False(t, fixture.pqSig.Equal(&changedSalt))

	changedPublicKey := fixture.pqSig
	changedPublicKey.PublicKey = append([]byte(nil), changedPublicKey.PublicKey...)
	changedPublicKey.PublicKey[0] ^= 1
	require.False(t, fixture.pqSig.Equal(&changedPublicKey))

	changedSignature := fixture.pqSig
	changedSignature.Signature = append([]byte(nil), changedSignature.Signature...)
	changedSignature.Signature[0] ^= 1
	require.False(t, fixture.pqSig.Equal(&changedSignature))

	var nilPQSig *PQSig
	blank := PQSig{}
	require.True(t, nilPQSig.Equal(&blank))
	require.True(t, blank.Equal(nil))
	require.False(t, nilPQSig.Equal(&fixture.pqSig))
}

func TestPQSigAuthorizerAddress(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	require.Equal(t, fixture.authorizer, fixture.pqSig.AuthorizerAddress())
	require.Equal(t, basics.PQAddress(fixture.pqSig.Scheme, fixture.pqSig.Salt, fixture.pqSig.PublicKey), fixture.pqSig.AuthorizerAddress())
}

func TestPQSigVerify(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	require.NoError(t, fixture.pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer))
}

func TestPQSigVerifyAcceptsSignatureOverTxnID(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	txid := crypto.Digest(fixture.txn.ID())
	txidSignature, err := fixture.signer.SignBytes(txid[:])
	require.NoError(t, err)

	pqSig := fixture.pqSig
	pqSig.Signature = txidSignature
	require.NoError(t, pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer))

	rawTxnSignature, err := fixture.signer.SignBytes(crypto.HashRep(fixture.txn))
	require.NoError(t, err)
	require.False(t, bytes.Equal(txidSignature, rawTxnSignature))

	pqSig.Signature = rawTxnSignature
	require.ErrorIs(t, pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer), basics.ErrPQFalcon1024SigInvalid)
}

func TestPQSigVerifyChecksConsensusParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	require.NoError(t, fixture.pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer))

	disabledProto := fixture.proto
	disabledProto.EnablePQSchemeFalcon1024 = false
	require.ErrorIs(t, fixture.pqSig.Verify(disabledProto, fixture.txn, fixture.authorizer), basics.ErrPQSchemeNotEnabled)
}

func TestPQSigVerifyRejectsBlank(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	var nilPQSig *PQSig
	require.ErrorIs(t, nilPQSig.Verify(fixture.proto, fixture.txn, fixture.authorizer), errPQSigBlank)

	var blank PQSig
	require.ErrorIs(t, blank.Verify(fixture.proto, fixture.txn, fixture.authorizer), errPQSigBlank)
}

func TestPQSigVerifyRejectsEmptySignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	pqSig := fixture.pqSig
	pqSig.Signature = nil

	require.ErrorIs(t, pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer), errPQSigEmpty)
}

func TestPQSigVerifyRejectsUnsupportedScheme(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	pqSig := fixture.pqSig
	pqSig.Scheme = protocol.PQScheme("x1")
	pqSig.Signature = []byte{1}

	require.ErrorIs(t, pqSig.Verify(fixture.proto, fixture.txn, pqSig.AuthorizerAddress()), basics.ErrPQSchemeNotSupported)
}

func TestPQSigVerifyRejectsAuthorizerMismatch(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	var wrongAuthorizer basics.Address
	wrongAuthorizer[0] = 1
	require.NotEqual(t, fixture.authorizer, wrongAuthorizer)

	require.ErrorIs(t, fixture.pqSig.Verify(fixture.proto, fixture.txn, wrongAuthorizer), errPQSigAuthorizerMismatch)
}

func TestPQSigVerifyRejectsMalformedPublicKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	pqSig := fixture.pqSig
	pqSig.PublicKey = pqSig.PublicKey[:len(pqSig.PublicKey)-1]

	err := pqSig.Verify(fixture.proto, fixture.txn, pqSig.AuthorizerAddress())
	require.Error(t, err)
	require.NotErrorIs(t, err, errPQSigAuthorizerMismatch)
}

func TestPQSigVerifyRejectsMalformedSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	pqSig := fixture.pqSig
	pqSig.Signature = make([]byte, crypto.FalconMaxSignatureSize+1)

	err := pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer)
	require.Error(t, err)
	require.NotErrorIs(t, err, basics.ErrPQFalcon1024SigInvalid)
}

func TestPQSigVerifyRejectsChangedTransaction(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	txn := fixture.txn
	txn.Note = []byte("changed")

	require.ErrorIs(t, fixture.pqSig.Verify(fixture.proto, txn, fixture.authorizer), basics.ErrPQFalcon1024SigInvalid)
}

func TestPQSigVerifyRejectsChangedSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	pqSig := fixture.pqSig
	pqSig.Signature = append([]byte(nil), pqSig.Signature...)
	pqSig.Signature[len(pqSig.Signature)-1] ^= 1

	require.ErrorIs(t, pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer), basics.ErrPQFalcon1024SigInvalid)
}
