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
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// pqSigTestSigner adapts one scheme's concrete signer to the byte-oriented
// operations the tests need.
type pqSigTestSigner interface {
	sign(message crypto.Hashable) ([]byte, error)
	signBytes(data []byte) ([]byte, error)
	verify(message crypto.Hashable, sig []byte) error
	verifyBytes(data []byte, sig []byte) error
}

type falcon1024TestSigner struct{ crypto.Falcon1024Signer }

func (s falcon1024TestSigner) sign(message crypto.Hashable) ([]byte, error) {
	return s.Sign(message)
}
func (s falcon1024TestSigner) signBytes(data []byte) ([]byte, error) {
	return s.SignBytes(data)
}
func (s falcon1024TestSigner) verify(message crypto.Hashable, sig []byte) error {
	return s.GetVerifyingKey().Verify(message, sig)
}
func (s falcon1024TestSigner) verifyBytes(data []byte, sig []byte) error {
	return s.GetVerifyingKey().VerifyBytes(data, sig)
}

type falcon512TestSigner struct{ crypto.Falcon512Signer }

func (s falcon512TestSigner) sign(message crypto.Hashable) ([]byte, error) {
	return s.Sign(message)
}
func (s falcon512TestSigner) signBytes(data []byte) ([]byte, error) {
	return s.SignBytes(data)
}
func (s falcon512TestSigner) verify(message crypto.Hashable, sig []byte) error {
	return s.GetVerifyingKey().Verify(message, sig)
}
func (s falcon512TestSigner) verifyBytes(data []byte, sig []byte) error {
	return s.GetVerifyingKey().VerifyBytes(data, sig)
}

type pqSigTestFixture struct {
	name             string
	signer           pqSigTestSigner
	proto            config.ConsensusParams
	txn              Transaction
	authorizer       basics.Address
	pqSig            PQSig
	errSigInvalid    error
	maxSignatureSize int
}

// protoWithSchemeDisabled returns a copy of the fixture's consensus params
// with the fixture's scheme turned off.
func (f pqSigTestFixture) protoWithSchemeDisabled(t *testing.T) config.ConsensusParams {
	proto := f.proto
	switch f.pqSig.Scheme {
	case protocol.PQSchemeFalcon1024:
		proto.EnablePQSchemeFalcon1024 = false
	case protocol.PQSchemeFalcon512:
		proto.EnablePQSchemeFalcon512 = false
	default:
		t.Fatalf("unknown scheme %s", f.pqSig.Scheme)
	}
	return proto
}

func makePQSigTestFixture(t *testing.T, firstSeedByte byte, scheme protocol.PQScheme) pqSigTestFixture {
	var seed crypto.FalconSeed
	seed[0] = firstSeedByte

	var name string
	var signer pqSigTestSigner
	var publicKey []byte
	var errSigInvalid error
	var maxSignatureSize int
	switch scheme {
	case protocol.PQSchemeFalcon1024:
		s, err := crypto.GenerateFalcon1024Signer(seed)
		require.NoError(t, err)
		name = "falcon-1024"
		signer = falcon1024TestSigner{s}
		publicKey = slices.Clone(s.PublicKey[:])
		errSigInvalid = crypto.ErrPQFalcon1024SigInvalid
		maxSignatureSize = crypto.Falcon1024MaxSignatureSize
	case protocol.PQSchemeFalcon512:
		s, err := crypto.GenerateFalcon512Signer(seed)
		require.NoError(t, err)
		name = "falcon-512"
		signer = falcon512TestSigner{s}
		publicKey = slices.Clone(s.PublicKey[:])
		errSigInvalid = crypto.ErrPQFalcon512SigInvalid
		maxSignatureSize = crypto.Falcon512MaxSignatureSize
	default:
		t.Fatalf("unknown scheme %s", scheme)
	}

	salt, authorizer, err := basics.CanonicalPQAddressSalt(scheme, publicKey)
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

	signature, err := signer.sign(txn)
	require.NoError(t, err)

	proto := config.Consensus[protocol.ConsensusFuture]
	require.True(t, proto.PQSchemeEnabled(scheme))

	return pqSigTestFixture{
		name:       name,
		signer:     signer,
		proto:      proto,
		txn:        txn,
		authorizer: authorizer,
		pqSig: PQSig{
			Scheme:    scheme,
			Salt:      salt,
			PublicKey: publicKey,
			Signature: signature,
		},
		errSigInvalid:    errSigInvalid,
		maxSignatureSize: maxSignatureSize,
	}
}

func makePQSigTestFixtures(t *testing.T, firstSeedByte byte) []pqSigTestFixture {
	return []pqSigTestFixture{
		makePQSigTestFixture(t, firstSeedByte, protocol.PQSchemeFalcon1024),
		makePQSigTestFixture(t, firstSeedByte, protocol.PQSchemeFalcon512),
	}
}

func TestPQDecodeBoundsFeedSignedTxnMaxSize(t *testing.T) {
	partitiontest.PartitionTest(t)

	expectedPQSigMaxSize := 1 +
		4 + protocol.PQSchemeMaxSize() +
		4 + basics.PQAddressSaltMaxSize() +
		3 + msgp.BytesPrefixSize + crypto.MaxPQPublicKeySize +
		4 + msgp.BytesPrefixSize + crypto.MaxPQSignatureSize
	require.Equal(t, expectedPQSigMaxSize, PQSigMaxSize())

	expectedLogicSigMaxSize := 1 +
		4 + msgp.ArrayHeaderSize + bounds.MaxLogicSigMaxSize +
		2 + msgp.BytesPrefixSize + bounds.MaxLogicSigMaxSize +
		6 + crypto.MultisigSigMaxSize() +
		5 + crypto.MultisigSigMaxSize() +
		6 + expectedPQSigMaxSize +
		4 + crypto.SignatureMaxSize()
	require.Equal(t, expectedLogicSigMaxSize, LogicSigMaxSize())

	// PQSigMaxSize is part of the network-facing SignedTxn bound. Growing
	// PQMax* intentionally increases PQSigMaxSize and therefore SignedTxnMaxSize.
	expectedSignedTxnMaxSize := 1 +
		4 + crypto.SignatureMaxSize() +
		5 + crypto.MultisigSigMaxSize() +
		5 + LogicSigMaxSize() +
		6 + expectedPQSigMaxSize +
		4 + TransactionMaxSize() +
		5 + basics.AddressMaxSize()
	require.Equal(t, expectedSignedTxnMaxSize, SignedTxnMaxSize())
}

func TestPQSigBlank(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.True(t, (PQSig{}).Blank())
	require.True(t, (PQSig{Salt: 0}).Blank())

	require.False(t, (PQSig{Salt: 1}).Blank())
	require.False(t, (PQSig{Scheme: protocol.PQSchemeFalcon1024}).Blank())
	require.False(t, (PQSig{Scheme: protocol.PQSchemeFalcon512}).Blank())
	require.False(t, (PQSig{PublicKey: []byte{1}}).Blank())
	require.False(t, (PQSig{Signature: []byte{1}}).Blank())
}

func TestPQSigEqual(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			same := fixture.pqSig
			same.PublicKey = slices.Clone(same.PublicKey)
			same.Signature = slices.Clone(same.Signature)

			require.True(t, fixture.pqSig.Equal(same))

			changedScheme := fixture.pqSig
			changedScheme.Scheme = protocol.PQScheme{'x', '1'}
			require.False(t, fixture.pqSig.Equal(changedScheme))

			changedSalt := fixture.pqSig
			changedSalt.Salt++
			require.False(t, fixture.pqSig.Equal(changedSalt))

			changedPublicKey := fixture.pqSig
			changedPublicKey.PublicKey = slices.Clone(changedPublicKey.PublicKey)
			changedPublicKey.PublicKey[0] ^= 1
			require.False(t, fixture.pqSig.Equal(changedPublicKey))

			changedSignature := fixture.pqSig
			changedSignature.Signature = slices.Clone(changedSignature.Signature)
			changedSignature.Signature[0] ^= 1
			require.False(t, fixture.pqSig.Equal(changedSignature))

			blank := PQSig{}
			require.True(t, blank.Equal(PQSig{}))
			require.False(t, blank.Equal(fixture.pqSig))
		})
	}
}

func TestPQSigAuthorizerAddress(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.Equal(t, fixture.authorizer, fixture.pqSig.Address())
			require.Equal(t, basics.PQAddress(fixture.pqSig.Scheme, fixture.pqSig.Salt, fixture.pqSig.PublicKey), fixture.pqSig.Address())
		})
	}
}

func TestPQSigValidateEnvelope(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.NoError(t, fixture.pqSig.ValidateScheme(fixture.proto))

			schemeOnly := PQSig{Scheme: fixture.pqSig.Scheme}
			require.NoError(t, schemeOnly.ValidateScheme(fixture.proto))

			require.NoError(t, fixture.pqSig.ValidateEnvelope(fixture.proto, fixture.authorizer))

			noSignature := fixture.pqSig
			noSignature.Signature = nil
			require.NoError(t, noSignature.ValidateEnvelope(fixture.proto, fixture.authorizer))

			disabledProto := fixture.protoWithSchemeDisabled(t)
			require.ErrorIs(t, fixture.pqSig.ValidateScheme(disabledProto), crypto.ErrPQSchemeNotEnabled)
			require.ErrorIs(t, fixture.pqSig.ValidateEnvelope(disabledProto, fixture.authorizer), crypto.ErrPQSchemeNotEnabled)

			unknownScheme := fixture.pqSig
			unknownScheme.Scheme = protocol.PQScheme{'x', '1'}
			require.ErrorIs(t, unknownScheme.ValidateScheme(fixture.proto), crypto.ErrPQSchemeNotSupported)
			require.ErrorIs(t, unknownScheme.ValidateEnvelope(fixture.proto, unknownScheme.Address()), crypto.ErrPQSchemeNotSupported)

			malformedPublicKey := fixture.pqSig
			malformedPublicKey.PublicKey = malformedPublicKey.PublicKey[:len(malformedPublicKey.PublicKey)-1]
			require.NoError(t, malformedPublicKey.ValidateEnvelope(fixture.proto, malformedPublicKey.Address()))
			require.ErrorIs(t, malformedPublicKey.Verify(fixture.proto, fixture.txn, malformedPublicKey.Address()), fixture.errSigInvalid)

			var wrongAuthorizer basics.Address
			wrongAuthorizer[0] = 1
			require.ErrorIs(t, fixture.pqSig.ValidateEnvelope(fixture.proto, wrongAuthorizer), errPQSigAuthorizerMismatch)

			corruptSignature := fixture.pqSig
			corruptSignature.Signature = slices.Clone(corruptSignature.Signature)
			corruptSignature.Signature[0] ^= 1
			require.NoError(t, corruptSignature.ValidateEnvelope(fixture.proto, fixture.authorizer))
			require.Error(t, corruptSignature.Verify(fixture.proto, fixture.txn, fixture.authorizer))

			require.ErrorIs(t, (PQSig{}).ValidateEnvelope(fixture.proto, fixture.authorizer), errPQSigBlank)
			require.ErrorIs(t, (PQSig{}).ValidateScheme(fixture.proto), errPQSigBlank)
		})
	}
}

func TestPQSigVerify(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.NoError(t, fixture.pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer))
		})
	}
}

func TestPQSigVerifyAcceptsSignatureOverRawTxn(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) { // fixture uses signer.sign()
		t.Run(fixture.name, func(t *testing.T) {
			rawTxnSignature, err := fixture.signer.signBytes(crypto.HashRep(fixture.txn))
			require.NoError(t, err)

			// Sign(txn) applies HashRep internally, so it must produce the same sig as SignBytes(HashRep(txn))
			require.Equal(t, fixture.pqSig.Signature, rawTxnSignature)

			pqSig := fixture.pqSig
			pqSig.Signature = rawTxnSignature
			require.NoError(t, pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer))

			require.NoError(t, fixture.signer.verify(fixture.txn, rawTxnSignature))
			require.NoError(t, fixture.signer.verifyBytes(crypto.HashRep(fixture.txn), rawTxnSignature))

			// A signature over the txid (the pre-hashed payload) must not verify:
			// the payload is the raw canonical encoding, not its digest.
			txid := crypto.Digest(fixture.txn.ID())
			txidSignature, err := fixture.signer.signBytes(txid[:])
			require.NoError(t, err)
			require.False(t, bytes.Equal(txidSignature, rawTxnSignature))

			pqSig.Signature = txidSignature
			require.ErrorIs(t, pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer), fixture.errSigInvalid)
		})
	}
}

func TestPQSigVerifyChecksConsensusParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.NoError(t, fixture.pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer))

			disabledProto := fixture.protoWithSchemeDisabled(t)
			require.ErrorIs(t, fixture.pqSig.Verify(disabledProto, fixture.txn, fixture.authorizer), crypto.ErrPQSchemeNotEnabled)
		})
	}
}

func TestPQSigVerifyRejectsBlank(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.ErrorIs(t, (PQSig{}).Verify(fixture.proto, fixture.txn, fixture.authorizer), errPQSigBlank)
		})
	}
}

func TestPQSigVerifyRejectsEmptySignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			pqSig := fixture.pqSig
			pqSig.Signature = nil

			require.ErrorIs(t, pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer), errPQSigEmpty)
		})
	}
}

func TestPQSigVerifyRejectsUnsupportedScheme(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			pqSig := fixture.pqSig
			pqSig.Scheme = protocol.PQScheme{'x', '1'}
			pqSig.Signature = []byte{1}

			require.ErrorIs(t, pqSig.Verify(fixture.proto, fixture.txn, pqSig.Address()), crypto.ErrPQSchemeNotSupported)
		})
	}
}

func TestPQSigVerifyRejectsAuthorizerMismatch(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			var wrongAuthorizer basics.Address
			wrongAuthorizer[0] = 1
			require.NotEqual(t, fixture.authorizer, wrongAuthorizer)

			require.ErrorIs(t, fixture.pqSig.Verify(fixture.proto, fixture.txn, wrongAuthorizer), errPQSigAuthorizerMismatch)
		})
	}
}

func TestPQSigVerifyRejectsMalformedPublicKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			pqSig := fixture.pqSig
			pqSig.PublicKey = pqSig.PublicKey[:len(pqSig.PublicKey)-1]

			err := pqSig.Verify(fixture.proto, fixture.txn, pqSig.Address())
			require.Error(t, err)
			require.NotErrorIs(t, err, errPQSigAuthorizerMismatch)
		})
	}
}

func TestPQSigVerifyRejectsMalformedSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			pqSig := fixture.pqSig
			pqSig.Signature = make([]byte, fixture.maxSignatureSize+1)

			err := pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer)
			require.ErrorIs(t, err, fixture.errSigInvalid)
		})
	}
}

func TestPQSigVerifyRejectsChangedTransaction(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			txn := fixture.txn
			txn.Note = []byte("changed")

			require.ErrorIs(t, fixture.pqSig.Verify(fixture.proto, txn, fixture.authorizer), fixture.errSigInvalid)
		})
	}
}

func TestPQSigVerifyRejectsChangedSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makePQSigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			pqSig := fixture.pqSig
			pqSig.Signature = slices.Clone(pqSig.Signature)
			pqSig.Signature[len(pqSig.Signature)-1] ^= 1

			require.ErrorIs(t, pqSig.Verify(fixture.proto, fixture.txn, fixture.authorizer), fixture.errSigInvalid)
		})
	}
}
