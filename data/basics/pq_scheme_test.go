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

package basics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type pqSchemeTestParams map[protocol.PQScheme]bool

func (params pqSchemeTestParams) PQSchemeEnabled(scheme protocol.PQScheme) bool {
	return params[scheme]
}

type pqSchemeTestMessage []byte

func (message pqSchemeTestMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TestHashable, message
}

func makePQSchemeTestSigner(t *testing.T, firstSeedByte byte) crypto.FalconSigner {
	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	signer, err := crypto.GenerateFalconSigner(seed)
	require.NoError(t, err)
	return signer
}

func TestLookupPQSchemeFalcon1024(t *testing.T) {
	partitiontest.PartitionTest(t)

	spec, ok := LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)
	require.Equal(t, uint64(crypto.FalconPublicKeySize), spec.PublicKeySize)
	require.Equal(t, uint64(crypto.FalconPrivateKeySize), spec.PrivateKeySize)
	require.Equal(t, uint64(crypto.FalconMaxSignatureSize), spec.SignatureSize)
	require.Equal(t, PQSchemeFalcon1024FeeContribution, spec.FeeContribution)
	require.NotNil(t, spec.Enabled)
	require.NotNil(t, spec.ValidatePublicKey)
	require.NotNil(t, spec.Verify)

	_, ok = LookupPQScheme(protocol.PQScheme("x1"))
	require.False(t, ok)
}

func TestPQSchemeEnabledUsesConsensusParams(t *testing.T) {
	partitiontest.PartitionTest(t)

	spec, ok := LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)

	require.True(t, spec.Enabled(pqSchemeTestParams{
		protocol.PQSchemeFalcon1024: true,
	}))
	require.False(t, spec.Enabled(pqSchemeTestParams{
		protocol.PQSchemeFalcon1024: false,
	}))
	require.False(t, spec.Enabled(pqSchemeTestParams{
		protocol.PQSchemeFalcon512: true,
	}))
}

func TestPQSchemeMaxSizes(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.Equal(t, uint64(crypto.FalconPublicKeySize), MaxPQPublicKeySize())
	require.Equal(t, uint64(crypto.FalconMaxSignatureSize), MaxPQSignatureSize())
}

func TestValidatePQPublicKeyFalcon1024(t *testing.T) {
	partitiontest.PartitionTest(t)

	signer := makePQSchemeTestSigner(t, 0)
	publicKey := signer.PublicKey[:]

	require.NoError(t, ValidatePQPublicKey(protocol.PQSchemeFalcon1024, publicKey))

	err := ValidatePQPublicKey(protocol.PQSchemeFalcon1024, publicKey[:len(publicKey)-1])
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrPQSchemeNotSupported)

	err = ValidatePQPublicKey(protocol.PQScheme("x1"), publicKey)
	require.ErrorIs(t, err, ErrPQSchemeNotSupported)
}

func TestPQSchemeVerifyFalcon1024(t *testing.T) {
	partitiontest.PartitionTest(t)

	message := pqSchemeTestMessage("verify falcon-1024 through basics scheme registry")
	signer := makePQSchemeTestSigner(t, 1)
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	spec, ok := LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)

	require.NoError(t, spec.Verify(message, signer.PublicKey[:], signature))
}

func TestPQSchemeVerifyFalcon1024RejectsMalformedInputs(t *testing.T) {
	partitiontest.PartitionTest(t)

	message := pqSchemeTestMessage("malformed input checks")
	signer := makePQSchemeTestSigner(t, 2)
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	spec, ok := LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)

	err = spec.Verify(message, signer.PublicKey[:len(signer.PublicKey)-1], signature)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrPQFalcon1024SigInvalid)

	err = spec.Verify(message, signer.PublicKey[:], nil)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrPQFalcon1024SigInvalid)

	err = spec.Verify(message, signer.PublicKey[:], make([]byte, crypto.FalconMaxSignatureSize+1))
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrPQFalcon1024SigInvalid)
}

func TestPQSchemeVerifyFalcon1024RejectsInvalidSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	message := pqSchemeTestMessage("valid message")
	signer := makePQSchemeTestSigner(t, 3)
	signature, err := signer.Sign(message)
	require.NoError(t, err)

	spec, ok := LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)

	err = spec.Verify(pqSchemeTestMessage("different message"), signer.PublicKey[:], signature)
	require.ErrorIs(t, err, ErrPQFalcon1024SigInvalid)
}
