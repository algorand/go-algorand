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

type hashedKeySigTestFixture struct {
	name       string
	signer     basics_testing.SigSchemeSigner
	proto      config.ConsensusParams
	txn        Transaction
	authorizer basics.Address
	hsig       HashedKeySig
}

// protoWithSchemeDisabled returns a copy of the fixture's consensus params
// with the fixture's scheme turned off.
func (f hashedKeySigTestFixture) protoWithSchemeDisabled(t *testing.T) config.ConsensusParams {
	proto := f.proto
	switch f.hsig.Scheme {
	case protocol.SigSchemeFalcon1024:
		proto.EnablePQSchemeFalcon1024 = false
	case protocol.SigSchemeFalcon512:
		proto.EnableSigSchemeFalcon512 = false
	case protocol.SigSchemeEd25519:
		proto.EnableSigSchemeEd25519 = false
	case protocol.SigSchemeLogicSig:
		proto.EnableSigSchemeLogicSig = false
	default:
		t.Fatalf("unknown scheme %s", f.hsig.Scheme)
	}
	return proto
}

func makeHashedKeySigTestFixture(t *testing.T, firstSeedByte byte, scheme protocol.SigScheme) hashedKeySigTestFixture {
	schemeInfo := basics_testing.SigSchemeTestInfo(t, scheme)
	acct := basics_testing.MakeHashedKeySigTestAccount(t, firstSeedByte, scheme)

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

	return hashedKeySigTestFixture{
		name:       schemeInfo.Name,
		signer:     acct.Signer,
		proto:      proto,
		txn:        txn,
		authorizer: acct.Address,
		hsig: HashedKeySig{
			Scheme:    acct.Scheme,
			Salt:      acct.Salt,
			PublicKey: acct.PublicKey,
			Signature: signature,
		},
	}
}

func makeHashedKeySigTestFixtures(t *testing.T, firstSeedByte byte) []hashedKeySigTestFixture {
	fixtures := make([]hashedKeySigTestFixture, 0, len(basics_testing.SigSchemeTests))
	for _, scheme := range basics_testing.SigSchemeTests {
		fixtures = append(fixtures, makeHashedKeySigTestFixture(t, firstSeedByte, scheme.Scheme))
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

// TestHashedKeySigSchemeSizeLimits checks that ValidateEnvelope holds each scheme to
// its own size limits, which are tighter than the wire bounds for every scheme
// but the largest. For ls, it also checks that the largest program and the
// largest set of arguments that LogicSig allows still fit.
func TestHashedKeySigSchemeSizeLimits(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]

	edAcct := basics_testing.MakeHashedKeySigTestAccount(t, 1, protocol.SigSchemeEd25519)
	edSig := HashedKeySig{
		Scheme:    protocol.SigSchemeEd25519,
		Salt:      edAcct.Salt,
		PublicKey: edAcct.PublicKey,
		Signature: make([]byte, len(crypto.Signature{})),
	}
	require.NoError(t, edSig.ValidateEnvelope(proto, edAcct.Address))
	long := edSig
	long.Signature = make([]byte, len(crypto.Signature{})+1)
	require.ErrorIs(t, long.ValidateEnvelope(proto, edAcct.Address), errHashedKeySigTooLarge)

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
	lsSig := HashedKeySig{
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
	require.ErrorIs(t, long.ValidateEnvelope(proto, authorizer), errHashedKeySigTooLarge)
}

func TestHashedKeySigDecodeBoundsFeedSignedTxnMaxSize(t *testing.T) {
	partitiontest.PartitionTest(t)

	expectedHashedKeySigMaxSize := 1 +
		4 + protocol.SigSchemeMaxSize() +
		4 + basics.AddressSaltMaxSize() +
		3 + msgp.BytesPrefixSize + maxSigSchemePublicKeySize() +
		4 + msgp.BytesPrefixSize + maxSigSchemeSignatureSize()
	require.Equal(t, expectedHashedKeySigMaxSize, HashedKeySigMaxSize())

	expectedLogicSigMaxSize := 1 +
		4 + msgp.ArrayHeaderSize + EvalMaxArgs*msgp.BytesPrefixSize + bounds.MaxLogicSigMaxSize +
		2 + msgp.BytesPrefixSize + bounds.MaxLogicSigMaxSize +
		6 + crypto.MultisigSigMaxSize() +
		5 + crypto.MultisigSigMaxSize() +
		6 + expectedHashedKeySigMaxSize +
		4 + crypto.SignatureMaxSize()
	require.Equal(t, expectedLogicSigMaxSize, LogicSigMaxSize())

	// HashedKeySigMaxSize is part of the network-facing SignedTxn bound. Growing
	// MaxSigScheme* intentionally increases HashedKeySigMaxSize and therefore SignedTxnMaxSize.
	expectedSignedTxnMaxSize := 1 +
		4 + crypto.SignatureMaxSize() +
		5 + crypto.MultisigSigMaxSize() +
		5 + LogicSigMaxSize() +
		6 + expectedHashedKeySigMaxSize +
		4 + TransactionMaxSize() +
		5 + basics.AddressMaxSize()
	require.Equal(t, expectedSignedTxnMaxSize, SignedTxnMaxSize())
}

func TestHashedKeySigBlank(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.True(t, (HashedKeySig{}).Blank())
	require.True(t, (HashedKeySig{Salt: 0}).Blank())

	require.False(t, (HashedKeySig{Salt: 1}).Blank())
	require.False(t, (HashedKeySig{Scheme: protocol.SigSchemeFalcon1024}).Blank())
	require.False(t, (HashedKeySig{Scheme: protocol.SigSchemeFalcon512}).Blank())
	require.False(t, (HashedKeySig{Scheme: protocol.SigSchemeEd25519}).Blank())
	require.False(t, (HashedKeySig{PublicKey: []byte{1}}).Blank())
	require.False(t, (HashedKeySig{Signature: []byte{1}}).Blank())
}

func TestHashedKeySigEqual(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			same := fixture.hsig
			same.PublicKey = slices.Clone(same.PublicKey)
			same.Signature = slices.Clone(same.Signature)

			require.True(t, fixture.hsig.Equal(same))

			changedScheme := fixture.hsig
			changedScheme.Scheme = protocol.SigScheme{'x', '1'}
			require.False(t, fixture.hsig.Equal(changedScheme))

			changedSalt := fixture.hsig
			changedSalt.Salt++
			require.False(t, fixture.hsig.Equal(changedSalt))

			changedPublicKey := fixture.hsig
			changedPublicKey.PublicKey = slices.Clone(changedPublicKey.PublicKey)
			changedPublicKey.PublicKey[0] ^= 1
			require.False(t, fixture.hsig.Equal(changedPublicKey))

			changedSignature := fixture.hsig
			changedSignature.Signature = slices.Clone(changedSignature.Signature)
			changedSignature.Signature[0] ^= 1
			require.False(t, fixture.hsig.Equal(changedSignature))

			blank := HashedKeySig{}
			require.True(t, blank.Equal(HashedKeySig{}))
			require.False(t, blank.Equal(fixture.hsig))
		})
	}
}

func TestHashedKeySigAuthorizerAddress(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.Equal(t, fixture.authorizer, fixture.hsig.Address())
			require.Equal(t, basics.SaltedAddress(fixture.hsig.Scheme, fixture.hsig.Salt, fixture.hsig.PublicKey), fixture.hsig.Address())
		})
	}
}

func TestHashedKeySigValidateEnvelope(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.NoError(t, fixture.hsig.ValidateScheme(fixture.proto))

			schemeOnly := HashedKeySig{Scheme: fixture.hsig.Scheme}
			require.NoError(t, schemeOnly.ValidateScheme(fixture.proto))

			require.NoError(t, fixture.hsig.ValidateEnvelope(fixture.proto, fixture.authorizer))

			noSignature := fixture.hsig
			noSignature.Signature = nil
			require.NoError(t, noSignature.ValidateEnvelope(fixture.proto, fixture.authorizer))

			disabledProto := fixture.protoWithSchemeDisabled(t)
			require.ErrorIs(t, fixture.hsig.ValidateScheme(disabledProto), ErrSigSchemeNotEnabled)
			require.ErrorIs(t, fixture.hsig.ValidateEnvelope(disabledProto, fixture.authorizer), ErrSigSchemeNotEnabled)

			unknownScheme := fixture.hsig
			unknownScheme.Scheme = protocol.SigScheme{'x', '1'}
			require.ErrorIs(t, unknownScheme.ValidateScheme(fixture.proto), ErrSigSchemeNotSupported)
			require.ErrorIs(t, unknownScheme.ValidateEnvelope(fixture.proto, unknownScheme.Address()), ErrSigSchemeNotSupported)

			malformedPublicKey := fixture.hsig
			malformedPublicKey.PublicKey = malformedPublicKey.PublicKey[:len(malformedPublicKey.PublicKey)-1]
			require.NoError(t, malformedPublicKey.ValidateEnvelope(fixture.proto, malformedPublicKey.Address()))
			require.ErrorIs(t, malformedPublicKey.Verify(fixture.proto, fixture.txn, malformedPublicKey.Address()), crypto.ErrSigInvalid)

			var wrongAuthorizer basics.Address
			wrongAuthorizer[0] = 1
			require.ErrorIs(t, fixture.hsig.ValidateEnvelope(fixture.proto, wrongAuthorizer), errHashedKeySigAuthorizerMismatch)

			corruptSignature := fixture.hsig
			corruptSignature.Signature = slices.Clone(corruptSignature.Signature)
			corruptSignature.Signature[0] ^= 1
			require.NoError(t, corruptSignature.ValidateEnvelope(fixture.proto, fixture.authorizer))
			require.Error(t, corruptSignature.Verify(fixture.proto, fixture.txn, fixture.authorizer))

			require.ErrorIs(t, (HashedKeySig{}).ValidateEnvelope(fixture.proto, fixture.authorizer), errHashedKeySigBlank)
			require.ErrorIs(t, (HashedKeySig{}).ValidateScheme(fixture.proto), errHashedKeySigBlank)
		})
	}
}

// TestHashedKeySigLogicSigScheme pins the split that the ls scheme depends on: its
// envelope validates like any other authorization scheme, so the address check is shared,
// but the generic Verify path refuses it. Callers must dispatch on the scheme
// and evaluate the program instead.
func TestHashedKeySigLogicSigScheme(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]
	require.True(t, proto.EnableSigSchemeLogicSig)

	program := []byte{0x0e, 0x81, 0x01} // #pragma version 14; pushint 1
	salt, authorizer, err := basics.CanonicalAddressSalt(protocol.SigSchemeLogicSig, program)
	require.NoError(t, err)
	require.True(t, authorizer.IsOffEd25519Curve())

	hsig := HashedKeySig{
		Scheme:    protocol.SigSchemeLogicSig,
		Salt:      salt,
		PublicKey: program,
	}
	require.Equal(t, authorizer, hsig.Address())

	// The address check must be reachable for ls, since that is the whole
	// authorization other than evaluating the program.
	require.NoError(t, hsig.ValidateEnvelope(proto, authorizer))

	var wrongAuthorizer basics.Address
	wrongAuthorizer[0] = 1
	require.ErrorIs(t, hsig.ValidateEnvelope(proto, wrongAuthorizer), errHashedKeySigAuthorizerMismatch)

	disabledProto := proto
	disabledProto.EnableSigSchemeLogicSig = false
	require.ErrorIs(t, hsig.ValidateEnvelope(disabledProto, authorizer), ErrSigSchemeNotEnabled)

	// A program's args are not signature bytes. Whatever they hold, no caller
	// may authorize an ls account by handing them to a signature verifier.
	withArgs := hsig
	withArgs.Signature = []byte("args")
	txn := Transaction{
		Type:             protocol.PaymentTx,
		Header:           Header{Sender: authorizer},
		PaymentTxnFields: PaymentTxnFields{Receiver: authorizer},
	}
	require.ErrorIs(t, withArgs.Verify(proto, txn, authorizer), errLogicSigNotEvaluated)
}

func TestHashedKeySigVerify(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.NoError(t, fixture.hsig.Verify(fixture.proto, fixture.txn, fixture.authorizer))
		})
	}
}

func TestHashedKeySigBatchPrep(t *testing.T) {
	partitiontest.PartitionTest(t)

	ed := makeHashedKeySigTestFixture(t, 1, protocol.SigSchemeEd25519)
	edBatch := crypto.MakeBatchVerifier()
	require.True(t, ed.hsig.Batched())
	require.NoError(t, ed.hsig.BatchPrep(ed.proto, ed.txn, ed.authorizer, edBatch))
	require.Equal(t, 1, edBatch.GetNumberOfEnqueuedSignatures())
	require.NoError(t, edBatch.Verify())

	falcon := makeHashedKeySigTestFixture(t, 1, protocol.SigSchemeFalcon1024)
	falconBatch := crypto.MakeBatchVerifier()
	require.False(t, falcon.hsig.Batched())
	require.NoError(t, falcon.hsig.BatchPrep(falcon.proto, falcon.txn, falcon.authorizer, falconBatch))
	require.Zero(t, falconBatch.GetNumberOfEnqueuedSignatures())
	require.False(t, (HashedKeySig{Scheme: protocol.SigScheme{'x', '1'}}).Batched())
}

func TestHashedKeySigBatchPrepMatchesVerifyEnvelopeErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makeHashedKeySigTestFixture(t, 2, protocol.SigSchemeEd25519)
	proto, txn, valid, authorizer := fixture.proto, fixture.txn, fixture.hsig, fixture.authorizer
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
		hsig       HashedKeySig
		proto      config.ConsensusParams
		authorizer basics.Address
		expected   error
	}{
		{"blank", HashedKeySig{}, proto, authorizer, errHashedKeySigBlank},
		{"unsupported", unsupported, proto, authorizer, ErrSigSchemeNotSupported},
		{"disabled", valid, disabledProto, authorizer, ErrSigSchemeNotEnabled},
		{"authorizer-mismatch", valid, proto, wrongAuthorizer, errHashedKeySigAuthorizerMismatch},
		{"empty-signature", emptySignature, proto, authorizer, errHashedKeySigEmpty},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifyErr := test.hsig.Verify(test.proto, txn, test.authorizer)
			batchErr := test.hsig.BatchPrep(test.proto, txn, test.authorizer, crypto.MakeBatchVerifier())
			require.ErrorIs(t, verifyErr, test.expected)
			require.ErrorIs(t, batchErr, test.expected)
			require.EqualError(t, batchErr, verifyErr.Error())
		})
	}
}

func TestHashedKeySigVerifyAcceptsSignatureOverRawTxn(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) { // fixture uses signer.sign()
		t.Run(fixture.name, func(t *testing.T) {
			rawTxnSignature, err := fixture.signer.SignBytes(crypto.HashRep(fixture.txn))
			require.NoError(t, err)

			// Sign(txn) applies HashRep internally, so it must produce the same sig as SignBytes(HashRep(txn))
			require.Equal(t, fixture.hsig.Signature, rawTxnSignature)

			hsig := fixture.hsig
			hsig.Signature = rawTxnSignature
			require.NoError(t, hsig.Verify(fixture.proto, fixture.txn, fixture.authorizer))

			require.NoError(t, fixture.signer.Verify(fixture.txn, rawTxnSignature))
			require.NoError(t, fixture.signer.VerifyBytes(crypto.HashRep(fixture.txn), rawTxnSignature))

			// A signature over the txid (the pre-hashed payload) must not verify:
			// the payload is the raw canonical encoding, not its digest.
			txid := crypto.Digest(fixture.txn.ID())
			txidSignature, err := fixture.signer.SignBytes(txid[:])
			require.NoError(t, err)
			require.False(t, bytes.Equal(txidSignature, rawTxnSignature))

			hsig.Signature = txidSignature
			require.ErrorIs(t, hsig.Verify(fixture.proto, fixture.txn, fixture.authorizer), crypto.ErrSigInvalid)
		})
	}
}

func TestHashedKeySigVerifyChecksConsensusParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.NoError(t, fixture.hsig.Verify(fixture.proto, fixture.txn, fixture.authorizer))

			disabledProto := fixture.protoWithSchemeDisabled(t)
			require.ErrorIs(t, fixture.hsig.Verify(disabledProto, fixture.txn, fixture.authorizer), ErrSigSchemeNotEnabled)
		})
	}
}

func TestHashedKeySigVerifyRejectsBlank(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			require.ErrorIs(t, (HashedKeySig{}).Verify(fixture.proto, fixture.txn, fixture.authorizer), errHashedKeySigBlank)
		})
	}
}

func TestHashedKeySigVerifyRejectsEmptySignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			hsig := fixture.hsig
			hsig.Signature = nil

			require.ErrorIs(t, hsig.Verify(fixture.proto, fixture.txn, fixture.authorizer), errHashedKeySigEmpty)
		})
	}
}

func TestHashedKeySigVerifyRejectsUnsupportedScheme(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			hsig := fixture.hsig
			hsig.Scheme = protocol.SigScheme{'x', '1'}
			hsig.Signature = []byte{1}

			require.ErrorIs(t, hsig.Verify(fixture.proto, fixture.txn, hsig.Address()), ErrSigSchemeNotSupported)
		})
	}
}

func TestHashedKeySigVerifyRejectsAuthorizerMismatch(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			var wrongAuthorizer basics.Address
			wrongAuthorizer[0] = 1
			require.NotEqual(t, fixture.authorizer, wrongAuthorizer)

			require.ErrorIs(t, fixture.hsig.Verify(fixture.proto, fixture.txn, wrongAuthorizer), errHashedKeySigAuthorizerMismatch)
		})
	}
}

func TestHashedKeySigVerifyRejectsMalformedPublicKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			hsig := fixture.hsig
			hsig.PublicKey = hsig.PublicKey[:len(hsig.PublicKey)-1]

			err := hsig.Verify(fixture.proto, fixture.txn, hsig.Address())
			require.Error(t, err)
			require.NotErrorIs(t, err, errHashedKeySigAuthorizerMismatch)
		})
	}
}

func TestHashedKeySigVerifyRejectsMalformedSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			// A signature too long for the scheme never reaches its verifier.
			hsig := fixture.hsig
			hsig.Signature = make([]byte, sigSchemes[hsig.Scheme].maxSignatureSize()+1)
			err := hsig.Verify(fixture.proto, fixture.txn, fixture.authorizer)
			require.ErrorIs(t, err, errHashedKeySigTooLarge)

			// One that fits, but is garbage, is rejected by the verifier.
			hsig.Signature = make([]byte, sigSchemes[hsig.Scheme].maxSignatureSize())
			err = hsig.Verify(fixture.proto, fixture.txn, fixture.authorizer)
			require.ErrorIs(t, err, crypto.ErrSigInvalid)
		})
	}
}

func TestHashedKeySigVerifyRejectsChangedTransaction(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			txn := fixture.txn
			txn.Note = []byte("changed")

			require.ErrorIs(t, fixture.hsig.Verify(fixture.proto, txn, fixture.authorizer), crypto.ErrSigInvalid)
		})
	}
}

func TestHashedKeySigVerifyRejectsChangedSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, fixture := range makeHashedKeySigTestFixtures(t, 0) {
		t.Run(fixture.name, func(t *testing.T) {
			hsig := fixture.hsig
			hsig.Signature = slices.Clone(hsig.Signature)
			hsig.Signature[len(hsig.Signature)-1] ^= 1

			require.ErrorIs(t, hsig.Verify(fixture.proto, fixture.txn, fixture.authorizer), crypto.ErrSigInvalid)
		})
	}
}
