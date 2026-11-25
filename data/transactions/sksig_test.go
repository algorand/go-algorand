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
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type saltedKeySigTestFixture struct {
	name       string
	signer     basics_testing.SigSchemeSigner
	proto      config.ConsensusParams
	txn        Transaction
	authorizer basics.Address
	sksig      SaltedKeySig
}

// protoWithSchemeDisabled returns a copy of the fixture's consensus params
// with the fixture's scheme turned off.
func (f saltedKeySigTestFixture) protoWithSchemeDisabled(t *testing.T) config.ConsensusParams {
	proto := f.proto
	switch f.sksig.Scheme {
	case protocol.SigSchemeFalcon1024:
		proto.EnablePQSchemeFalcon1024 = false
	case protocol.SigSchemeFalcon512:
		proto.EnableSigSchemeFalcon512 = false
	case protocol.SigSchemeEd25519:
		proto.EnableSigSchemeEd25519 = false
	case protocol.SigSchemeMLDSA44:
		proto.EnableSigSchemeMLDSA44 = false
	case protocol.SigSchemeMLDSA65:
		proto.EnableSigSchemeMLDSA65 = false
	case protocol.SigSchemeMLDSA87:
		proto.EnableSigSchemeMLDSA87 = false
	case protocol.SigSchemeLogicSig:
		proto.EnableSigSchemeLogicSig = false
	default:
		t.Fatalf("unknown scheme %s", f.sksig.Scheme)
	}
	return proto
}

func makeSaltedKeySigTestFixture(t *testing.T, firstSeedByte byte, scheme protocol.SigScheme) saltedKeySigTestFixture {
	schemeInfo := basics_testing.SigSchemeTestInfo(t, scheme)
	acct := basics_testing.MakeSaltedKeySigTestAccount(t, firstSeedByte, scheme)

	txn := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender: acct.Address,
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver: acct.Address,
		},
	}

	signature, err := acct.Signer.Sign(txn)
	require.NoError(t, err)

	proto := config.Consensus[protocol.ConsensusFuture]
	require.True(t, SigSchemeEnabled(proto, scheme))

	return saltedKeySigTestFixture{
		name:       schemeInfo.Name,
		signer:     acct.Signer,
		proto:      proto,
		txn:        txn,
		authorizer: acct.Address,
		sksig: SaltedKeySig{
			Scheme:    acct.Scheme,
			Salt:      acct.Salt,
			PublicKey: acct.PublicKey,
			Signature: signature,
		},
	}
}

func makeSaltedKeySigTestFixtures(t *testing.T, firstSeedByte byte) []saltedKeySigTestFixture {
	fixtures := make([]saltedKeySigTestFixture, 0, len(basics_testing.SigSchemeTests))
	for _, scheme := range basics_testing.SigSchemeTests {
		fixtures = append(fixtures, makeSaltedKeySigTestFixture(t, firstSeedByte, scheme.Scheme))
	}
	return fixtures
}

func TestLogicSigArgsRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, args := range []LogicSigArgs{
		nil,
		{{}},
		{{1}},
		{{1, 2, 3}, {}, {4}},
		{make([]byte, MaxLogicSigArgSize)},
		make(LogicSigArgs, EvalMaxArgs),
	} {
		decoded, err := DecodeLogicSigArgs(EncodeLogicSigArgs(args))
		require.NoError(t, err)
		require.Equal(t, args.Len(), decoded.Len())
		if len(args) == 0 {
			require.Empty(t, decoded)
			continue
		}
		require.Len(t, decoded, len(args))
	}

	// No arguments must be no bytes, so that "absent" and "present but empty"
	// cannot both appear on the wire.
	require.Empty(t, EncodeLogicSigArgs(nil))
	require.Empty(t, EncodeLogicSigArgs(LogicSigArgs{}))
}

func TestLogicSigArgsRejectsNonCanonical(t *testing.T) {
	partitiontest.PartitionTest(t)

	canonical := EncodeLogicSigArgs(LogicSigArgs{{1, 2, 3}})
	decoded, err := DecodeLogicSigArgs(canonical)
	require.NoError(t, err)
	require.Equal(t, LogicSigArgs{{1, 2, 3}}, decoded)

	// An empty array spells no arguments, which must be spelled as no bytes.
	_, err = DecodeLogicSigArgs([]byte{0x90})
	require.ErrorIs(t, err, errLogicSigArgsNotCanonical)

	// Trailing bytes are not part of the arguments, so they are not canonical
	// either, whatever they hold.
	_, err = DecodeLogicSigArgs(append(slices.Clone(canonical), 0x00))
	require.ErrorIs(t, err, errLogicSigArgsNotCanonical)

	// array16 spelling of a length that fits in a fixarray.
	wide := append([]byte{0xdc, 0x00, 0x01}, canonical[1:]...)
	_, err = DecodeLogicSigArgs(wide)
	require.ErrorIs(t, err, errLogicSigArgsNotCanonical)

	_, err = DecodeLogicSigArgs([]byte{0xc1})
	require.Error(t, err)
}

func TestLogicSigArgsDecodeBounds(t *testing.T) {
	partitiontest.PartitionTest(t)

	tooMany := make(LogicSigArgs, EvalMaxArgs+1)
	_, err := DecodeLogicSigArgs(protocol.Encode(tooMany))
	require.Error(t, err)

	tooBig := LogicSigArgs{make([]byte, MaxLogicSigArgSize+1)}
	_, err = DecodeLogicSigArgs(protocol.Encode(tooBig))
	require.Error(t, err)
}

// TestSaltedKeySigSchemeSizeLimits checks that ValidateEnvelope holds each scheme to
// its own size limits, which are tighter than the wire bounds for every scheme
// but the largest. For ls, it also checks that the largest program and the
// largest set of arguments that LogicSig allows still fit.
func TestSaltedKeySigSchemeSizeLimits(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]

	edAcct := basics_testing.MakeSaltedKeySigTestAccount(t, 1, protocol.SigSchemeEd25519)
	edSig := SaltedKeySig{
		Scheme:    protocol.SigSchemeEd25519,
		Salt:      edAcct.Salt,
		PublicKey: edAcct.PublicKey,
		Signature: make([]byte, len(crypto.Signature{})),
	}
	require.NoError(t, edSig.ValidateEnvelope(proto, edAcct.Address))
	long := edSig
	long.Signature = make([]byte, len(crypto.Signature{})+1)
	require.ErrorIs(t, long.ValidateEnvelope(proto, edAcct.Address), errSaltedKeySigTooLarge)

	program := make([]byte, bounds.MaxLogicSigMaxSize)
	program[0] = 0x0e // #pragma version 14
	salt, authorizer, err := basics.CanonicalAddressSalt(protocol.SigSchemeLogicSig, program)
	require.NoError(t, err)

	// 255 arguments sharing the whole LogicSig size budget.
	args := make(LogicSigArgs, EvalMaxArgs)
	remaining := bounds.MaxLogicSigMaxSize
	for i := range args {
		n := remaining / (len(args) - i)
		args[i] = make([]byte, n)
		remaining -= n
	}
	lsSig := SaltedKeySig{
		Scheme:    protocol.SigSchemeLogicSig,
		Salt:      salt,
		PublicKey: program,
		Signature: EncodeLogicSigArgs(args),
	}
	require.NoError(t, lsSig.ValidateEnvelope(proto, authorizer))

	long = lsSig
	long.PublicKey = append(program, 0x01)
	salt, authorizer, err = basics.CanonicalAddressSalt(protocol.SigSchemeLogicSig, long.PublicKey)
	require.NoError(t, err)
	long.Salt = salt
	require.ErrorIs(t, long.ValidateEnvelope(proto, authorizer), errSaltedKeySigTooLarge)
}

func TestSaltedKeySigDecodeBoundsFeedSignedTxnMaxSize(t *testing.T) {
	partitiontest.PartitionTest(t)

	expectedSaltedKeySigMaxSize := 1 +
		4 + protocol.SigSchemeMaxSize() +
		4 + basics.AddressSaltMaxSize() +
		3 + msgp.BytesPrefixSize + maxSigSchemePublicKeySize() +
		4 + msgp.BytesPrefixSize + maxSigSchemeSignatureSize()
	require.Equal(t, expectedSaltedKeySigMaxSize, SaltedKeySigMaxSize())

	expectedLogicSigMaxSize := 1 +
		4 + msgp.ArrayHeaderSize + EvalMaxArgs*msgp.BytesPrefixSize + bounds.MaxLogicSigMaxSize +
		2 + msgp.BytesPrefixSize + bounds.MaxLogicSigMaxSize +
		6 + crypto.MultisigSigMaxSize() +
		5 + crypto.MultisigSigMaxSize() +
		6 + expectedSaltedKeySigMaxSize +
		4 + crypto.SignatureMaxSize()
	require.Equal(t, expectedLogicSigMaxSize, LogicSigMaxSize())

	// SaltedKeySigMaxSize is part of the network-facing SignedTxn bound. Growing
	// MaxSigScheme* intentionally increases SaltedKeySigMaxSize and therefore SignedTxnMaxSize.
	expectedSignedTxnMaxSize := 1 +
		4 + crypto.SignatureMaxSize() +
		5 + crypto.MultisigSigMaxSize() +
		5 + LogicSigMaxSize() +
		6 + expectedSaltedKeySigMaxSize +
		4 + TransactionMaxSize() +
		5 + basics.AddressMaxSize()
	require.Equal(t, expectedSignedTxnMaxSize, SignedTxnMaxSize())
}

func TestSaltedKeySigBlank(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.True(t, (SaltedKeySig{}).Blank())
	require.True(t, (SaltedKeySig{Salt: 0}).Blank())

	require.False(t, (SaltedKeySig{Salt: 1}).Blank())
	require.False(t, (SaltedKeySig{Scheme: protocol.SigSchemeFalcon1024}).Blank())
	require.False(t, (SaltedKeySig{Scheme: protocol.SigSchemeFalcon512}).Blank())
	require.False(t, (SaltedKeySig{Scheme: protocol.SigSchemeEd25519}).Blank())
	require.False(t, (SaltedKeySig{PublicKey: []byte{1}}).Blank())
	require.False(t, (SaltedKeySig{Signature: []byte{1}}).Blank())
}

func TestSaltedKeySigEqual(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			same := fixture.sksig
			same.PublicKey = slices.Clone(same.PublicKey)
			same.Signature = slices.Clone(same.Signature)

			require.True(t, fixture.sksig.Equal(same))

			changedScheme := fixture.sksig
			changedScheme.Scheme = protocol.SigScheme{'x', '1'}
			require.False(t, fixture.sksig.Equal(changedScheme))

			changedSalt := fixture.sksig
			changedSalt.Salt++
			require.False(t, fixture.sksig.Equal(changedSalt))

			changedPublicKey := fixture.sksig
			changedPublicKey.PublicKey = slices.Clone(changedPublicKey.PublicKey)
			changedPublicKey.PublicKey[0] ^= 1
			require.False(t, fixture.sksig.Equal(changedPublicKey))

			changedSignature := fixture.sksig
			changedSignature.Signature = slices.Clone(changedSignature.Signature)
			changedSignature.Signature[0] ^= 1
			require.False(t, fixture.sksig.Equal(changedSignature))

			blank := SaltedKeySig{}
			require.True(t, blank.Equal(SaltedKeySig{}))
			require.False(t, blank.Equal(fixture.sksig))
		})
	}
}

func TestSaltedKeySigAuthorizerAddress(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.Equal(t, fixture.authorizer, fixture.sksig.Address())
			require.Equal(t, basics.SaltedAddress(fixture.sksig.Scheme, fixture.sksig.Salt, fixture.sksig.PublicKey), fixture.sksig.Address())
		})
	}
}

func TestSaltedKeySigValidateEnvelope(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.NoError(t, fixture.sksig.ValidateScheme(fixture.proto))

			schemeOnly := SaltedKeySig{Scheme: fixture.sksig.Scheme}
			require.NoError(t, schemeOnly.ValidateScheme(fixture.proto))

			require.NoError(t, fixture.sksig.ValidateEnvelope(fixture.proto, fixture.authorizer))

			noSignature := fixture.sksig
			noSignature.Signature = nil
			require.NoError(t, noSignature.ValidateEnvelope(fixture.proto, fixture.authorizer))

			disabledProto := fixture.protoWithSchemeDisabled(t)
			require.ErrorIs(t, fixture.sksig.ValidateScheme(disabledProto), ErrSigSchemeNotEnabled)
			require.ErrorIs(t, fixture.sksig.ValidateEnvelope(disabledProto, fixture.authorizer), ErrSigSchemeNotEnabled)

			unknownScheme := fixture.sksig
			unknownScheme.Scheme = protocol.SigScheme{'x', '1'}
			require.ErrorIs(t, unknownScheme.ValidateScheme(fixture.proto), ErrSigSchemeNotSupported)
			require.ErrorIs(t, unknownScheme.ValidateEnvelope(fixture.proto, unknownScheme.Address()), ErrSigSchemeNotSupported)

			malformedPublicKey := fixture.sksig
			malformedPublicKey.PublicKey = malformedPublicKey.PublicKey[:len(malformedPublicKey.PublicKey)-1]
			require.NoError(t, malformedPublicKey.ValidateEnvelope(fixture.proto, malformedPublicKey.Address()))
			require.ErrorIs(t, malformedPublicKey.Verify(fixture.proto, fixture.txn, malformedPublicKey.Address()), crypto.ErrSigInvalid)

			var wrongAuthorizer basics.Address
			wrongAuthorizer[0] = 1
			require.ErrorIs(t, fixture.sksig.ValidateEnvelope(fixture.proto, wrongAuthorizer), errSaltedKeySigAuthorizerMismatch)

			corruptSignature := fixture.sksig
			corruptSignature.Signature = slices.Clone(corruptSignature.Signature)
			corruptSignature.Signature[0] ^= 1
			require.NoError(t, corruptSignature.ValidateEnvelope(fixture.proto, fixture.authorizer))
			require.Error(t, corruptSignature.Verify(fixture.proto, fixture.txn, fixture.authorizer))

			require.ErrorIs(t, (SaltedKeySig{}).ValidateEnvelope(fixture.proto, fixture.authorizer), errSaltedKeySigBlank)
			require.ErrorIs(t, (SaltedKeySig{}).ValidateScheme(fixture.proto), errSaltedKeySigBlank)
		})
	}
}

// TestSaltedKeySigLogicSigScheme pins the split that the ls scheme depends on: its
// envelope validates like any other authorization scheme, so the address check is shared,
// but the generic Verify path refuses it. Callers must dispatch on the scheme
// and evaluate the program instead.
func TestSaltedKeySigLogicSigScheme(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]
	require.True(t, proto.EnableSigSchemeLogicSig)

	program := []byte{0x0e, 0x81, 0x01} // #pragma version 14; pushint 1
	salt, authorizer, err := basics.CanonicalAddressSalt(protocol.SigSchemeLogicSig, program)
	require.NoError(t, err)
	require.True(t, authorizer.IsOffEd25519Curve())

	sksig := SaltedKeySig{
		Scheme:    protocol.SigSchemeLogicSig,
		Salt:      salt,
		PublicKey: program,
	}
	require.Equal(t, authorizer, sksig.Address())

	// The address check must be reachable for ls, since that is the whole
	// authorization other than evaluating the program.
	require.NoError(t, sksig.ValidateEnvelope(proto, authorizer))

	var wrongAuthorizer basics.Address
	wrongAuthorizer[0] = 1
	require.ErrorIs(t, sksig.ValidateEnvelope(proto, wrongAuthorizer), errSaltedKeySigAuthorizerMismatch)

	disabledProto := proto
	disabledProto.EnableSigSchemeLogicSig = false
	require.ErrorIs(t, sksig.ValidateEnvelope(disabledProto, authorizer), ErrSigSchemeNotEnabled)

	// A program's args are not signature bytes. Whatever they hold, no caller
	// may authorize an ls account by handing them to a signature verifier.
	withArgs := sksig
	withArgs.Signature = []byte("args")
	txn := Transaction{
		Type:             protocol.PaymentTx,
		Header:           Header{Sender: authorizer},
		PaymentTxnFields: PaymentTxnFields{Receiver: authorizer},
	}
	require.ErrorIs(t, withArgs.Verify(proto, txn, authorizer), errLogicSigNotEvaluated)
}

func TestSaltedKeySigVerify(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.NoError(t, fixture.sksig.Verify(fixture.proto, fixture.txn, fixture.authorizer))
		})
	}
}

func TestSaltedKeySigBatchPrep(t *testing.T) {
	partitiontest.PartitionTest(t)

	ed := makeSaltedKeySigTestFixture(t, 1, protocol.SigSchemeEd25519)
	edBatch := crypto.MakeBatchVerifier()
	require.True(t, ed.sksig.Batched())
	require.NoError(t, ed.sksig.BatchPrep(ed.proto, ed.txn, ed.authorizer, edBatch))
	require.Equal(t, 1, edBatch.GetNumberOfEnqueuedSignatures())
	require.NoError(t, edBatch.Verify())

	falcon := makeSaltedKeySigTestFixture(t, 1, protocol.SigSchemeFalcon1024)
	falconBatch := crypto.MakeBatchVerifier()
	require.False(t, falcon.sksig.Batched())
	require.NoError(t, falcon.sksig.BatchPrep(falcon.proto, falcon.txn, falcon.authorizer, falconBatch))
	require.Zero(t, falconBatch.GetNumberOfEnqueuedSignatures())
	require.False(t, (SaltedKeySig{Scheme: protocol.SigScheme{'x', '1'}}).Batched())
}

func TestSaltedKeySigBatchPrepMatchesVerifyEnvelopeErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makeSaltedKeySigTestFixture(t, 2, protocol.SigSchemeEd25519)
	proto, txn, valid, authorizer := fixture.proto, fixture.txn, fixture.sksig, fixture.authorizer
	disabledProto := proto
	disabledProto.EnableSigSchemeEd25519 = false
	unsupported := valid
	unsupported.Scheme = protocol.SigScheme{'x', '1'}
	emptySignature := valid
	emptySignature.Signature = nil
	wrongAuthorizer := authorizer
	wrongAuthorizer[0] ^= 1

	tests := []struct {
		name       string
		sksig      SaltedKeySig
		proto      config.ConsensusParams
		authorizer basics.Address
		expected   error
	}{
		{"blank", SaltedKeySig{}, proto, authorizer, errSaltedKeySigBlank},
		{"unsupported", unsupported, proto, authorizer, ErrSigSchemeNotSupported},
		{"disabled", valid, disabledProto, authorizer, ErrSigSchemeNotEnabled},
		{"authorizer-mismatch", valid, proto, wrongAuthorizer, errSaltedKeySigAuthorizerMismatch},
		{"empty-signature", emptySignature, proto, authorizer, errSaltedKeySigEmpty},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifyErr := test.sksig.Verify(test.proto, txn, test.authorizer)
			batchErr := test.sksig.BatchPrep(test.proto, txn, test.authorizer, crypto.MakeBatchVerifier())
			require.ErrorIs(t, verifyErr, test.expected)
			require.ErrorIs(t, batchErr, test.expected)
			require.EqualError(t, batchErr, verifyErr.Error())
		})
	}
}

func TestSaltedKeySigVerifyAcceptsSignatureOverRawTxn(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) { // fixture uses signer.sign()
		t.Run(fixture.name, func(t *testing.T) {
			rawTxnSignature, err := fixture.signer.SignBytes(crypto.HashRep(fixture.txn))
			require.NoError(t, err)

			// Sign(txn) applies HashRep internally, so it must produce the same sig as SignBytes(HashRep(txn))
			require.Equal(t, fixture.sksig.Signature, rawTxnSignature)

			sksig := fixture.sksig
			sksig.Signature = rawTxnSignature
			require.NoError(t, sksig.Verify(fixture.proto, fixture.txn, fixture.authorizer))

			require.NoError(t, fixture.signer.Verify(fixture.txn, rawTxnSignature))
			require.NoError(t, fixture.signer.VerifyBytes(crypto.HashRep(fixture.txn), rawTxnSignature))

			// A signature over the txid (the pre-hashed payload) must not verify:
			// the payload is the raw canonical encoding, not its digest.
			txid := crypto.Digest(fixture.txn.ID())
			txidSignature, err := fixture.signer.SignBytes(txid[:])
			require.NoError(t, err)
			require.False(t, bytes.Equal(txidSignature, rawTxnSignature))

			sksig.Signature = txidSignature
			require.ErrorIs(t, sksig.Verify(fixture.proto, fixture.txn, fixture.authorizer), crypto.ErrSigInvalid)
		})
	}
}

func TestSaltedKeySigVerifyChecksConsensusParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.NoError(t, fixture.sksig.Verify(fixture.proto, fixture.txn, fixture.authorizer))

			disabledProto := fixture.protoWithSchemeDisabled(t)
			require.ErrorIs(t, fixture.sksig.Verify(disabledProto, fixture.txn, fixture.authorizer), ErrSigSchemeNotEnabled)
		})
	}
}

func TestSaltedKeySigVerifyRejectsBlank(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.ErrorIs(t, (SaltedKeySig{}).Verify(fixture.proto, fixture.txn, fixture.authorizer), errSaltedKeySigBlank)
		})
	}
}

func TestSaltedKeySigVerifyRejectsEmptySignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			sksig := fixture.sksig
			sksig.Signature = nil

			require.ErrorIs(t, sksig.Verify(fixture.proto, fixture.txn, fixture.authorizer), errSaltedKeySigEmpty)
		})
	}
}

func TestSaltedKeySigVerifyRejectsUnsupportedScheme(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			sksig := fixture.sksig
			sksig.Scheme = protocol.SigScheme{'x', '1'}
			sksig.Signature = []byte{1}

			require.ErrorIs(t, sksig.Verify(fixture.proto, fixture.txn, sksig.Address()), ErrSigSchemeNotSupported)
		})
	}
}

func TestSaltedKeySigVerifyRejectsAuthorizerMismatch(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			var wrongAuthorizer basics.Address
			wrongAuthorizer[0] = 1
			require.NotEqual(t, fixture.authorizer, wrongAuthorizer)

			require.ErrorIs(t, fixture.sksig.Verify(fixture.proto, fixture.txn, wrongAuthorizer), errSaltedKeySigAuthorizerMismatch)
		})
	}
}

func TestSaltedKeySigVerifyRejectsMalformedPublicKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			sksig := fixture.sksig
			sksig.PublicKey = sksig.PublicKey[:len(sksig.PublicKey)-1]

			err := sksig.Verify(fixture.proto, fixture.txn, sksig.Address())
			require.Error(t, err)
			require.NotErrorIs(t, err, errSaltedKeySigAuthorizerMismatch)
		})
	}
}

func TestSaltedKeySigVerifyRejectsMalformedSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			// A signature too long for the scheme never reaches its verifier.
			sksig := fixture.sksig
			sksig.Signature = make([]byte, sigSchemes[sksig.Scheme].maxSignatureSize()+1)
			err := sksig.Verify(fixture.proto, fixture.txn, fixture.authorizer)
			require.ErrorIs(t, err, errSaltedKeySigTooLarge)

			// One that fits, but is garbage, is rejected by the verifier.
			sksig.Signature = make([]byte, sigSchemes[sksig.Scheme].maxSignatureSize())
			err = sksig.Verify(fixture.proto, fixture.txn, fixture.authorizer)
			require.ErrorIs(t, err, crypto.ErrSigInvalid)
		})
	}
}

func TestSaltedKeySigVerifyRejectsChangedTransaction(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			txn := fixture.txn
			txn.Note = []byte("changed")

			require.ErrorIs(t, fixture.sksig.Verify(fixture.proto, txn, fixture.authorizer), crypto.ErrSigInvalid)
		})
	}
}

func TestSaltedKeySigVerifyRejectsChangedSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeSaltedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			sksig := fixture.sksig
			sksig.Signature = slices.Clone(sksig.Signature)
			sksig.Signature[len(sksig.Signature)-1] ^= 1

			require.ErrorIs(t, sksig.Verify(fixture.proto, fixture.txn, fixture.authorizer), crypto.ErrSigInvalid)
		})
	}
}
