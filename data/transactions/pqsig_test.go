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

	"github.com/algorand/msgp/msgp"

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

func TestPQDecodeBoundsFeedSignedTxnMaxSize(t *testing.T) {
	partitiontest.PartitionTest(t)

	expectedPQSigMaxSize := 1 +
		4 + protocol.PQSchemeMaxSize() +
		4 + basics.PQAddressSaltMaxSize() +
		3 + msgp.BytesPrefixSize + PQMaxPublicKeySize +
		4 + msgp.BytesPrefixSize + PQMaxSignatureSize
	require.Equal(t, expectedPQSigMaxSize, PQSigMaxSize())

	// PQSigMaxSize is part of the network-facing SignedTxn bound. Bumping
	// PQMax* intentionally increases PQSigMaxSize and therefore SignedTxnMaxSize.
	expectedSignedTxnMaxSize := 1 +
		4 + crypto.SignatureMaxSize() +
		5 + crypto.MultisigSigMaxSize() +
		5 + LogicSigMaxSize() +
		3 + expectedPQSigMaxSize +
		4 + TransactionMaxSize() +
		5 + basics.AddressMaxSize()
	require.Equal(t, expectedSignedTxnMaxSize, SignedTxnMaxSize())
}

func TestEnabledPQSchemesFitDecodeBounds(t *testing.T) {
	partitiontest.PartitionTest(t)

	var maxPublicKeySize uint64
	var maxSignatureSize uint64

	for _, scheme := range []protocol.PQScheme{protocol.PQSchemeFalcon1024} {
		spec, ok := basics.LookupPQScheme(scheme)
		require.True(t, ok)

		for protoVersion, proto := range config.Consensus {
			if !proto.PQSchemeEnabled(scheme) {
				continue
			}

			require.LessOrEqualf(t, spec.PublicKeySize, uint64(PQMaxPublicKeySize),
				"scheme %q is enabled by %s", scheme, protoVersion)
			require.LessOrEqualf(t, spec.SignatureSize, uint64(PQMaxSignatureSize),
				"scheme %q is enabled by %s", scheme, protoVersion)

			if spec.PublicKeySize > maxPublicKeySize {
				maxPublicKeySize = spec.PublicKeySize
			}
			if spec.SignatureSize > maxSignatureSize {
				maxSignatureSize = spec.SignatureSize
			}
		}
	}

	require.NotZero(t, maxPublicKeySize)
	require.NotZero(t, maxSignatureSize)
	require.Equal(t, uint64(PQMaxPublicKeySize), maxPublicKeySize)
	require.Equal(t, uint64(PQMaxSignatureSize), maxSignatureSize)
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

func TestPQSigValidateEnvelope(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makePQSigTestFixture(t, 0)

	require.NoError(t, fixture.pqSig.ValidateEnvelope(fixture.proto, fixture.authorizer))

	noSignature := fixture.pqSig
	noSignature.Signature = nil
	require.NoError(t, noSignature.ValidateEnvelope(fixture.proto, fixture.authorizer))

	disabledProto := fixture.proto
	disabledProto.EnablePQSchemeFalcon1024 = false
	require.ErrorIs(t, fixture.pqSig.ValidateEnvelope(disabledProto, fixture.authorizer), basics.ErrPQSchemeNotEnabled)

	unknownScheme := fixture.pqSig
	unknownScheme.Scheme = protocol.PQScheme("x1")
	require.ErrorIs(t, unknownScheme.ValidateEnvelope(fixture.proto, unknownScheme.AuthorizerAddress()), basics.ErrPQSchemeNotSupported)

	malformedPublicKey := fixture.pqSig
	malformedPublicKey.PublicKey = malformedPublicKey.PublicKey[:len(malformedPublicKey.PublicKey)-1]
	require.ErrorContains(t, malformedPublicKey.ValidateEnvelope(fixture.proto, malformedPublicKey.AuthorizerAddress()), "falcon public key size invalid")

	var wrongAuthorizer basics.Address
	wrongAuthorizer[0] = 1
	require.ErrorIs(t, fixture.pqSig.ValidateEnvelope(fixture.proto, wrongAuthorizer), errPQSigAuthorizerMismatch)

	corruptSignature := fixture.pqSig
	corruptSignature.Signature = append([]byte(nil), corruptSignature.Signature...)
	corruptSignature.Signature[0] ^= 1
	require.NoError(t, corruptSignature.ValidateEnvelope(fixture.proto, fixture.authorizer))
	require.Error(t, corruptSignature.Verify(fixture.proto, fixture.txn, fixture.authorizer))

	require.ErrorIs(t, (*PQSig).ValidateEnvelope(nil, fixture.proto, fixture.authorizer), errPQSigBlank)
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

	require.ErrorIs(t, (*PQSig).Verify(nil, fixture.proto, fixture.txn, fixture.authorizer), errPQSigBlank)

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
