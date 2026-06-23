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
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type pqSchemeTestMessage []byte

func (message pqSchemeTestMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TestHashable, message
}

func supportedPQSchemes() []protocol.PQScheme {
	schemes := slices.Collect(maps.Keys(pqSchemeSpecs))
	slices.Sort(schemes)
	return schemes
}

func makePQSchemeTestSigner(t *testing.T, firstSeedByte byte) crypto.FalconSigner {
	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	signer, err := crypto.GenerateFalconSigner(seed)
	require.NoError(t, err)
	return signer
}

func TestPQSchemeRegistryComplete(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.NotEmpty(t, pqSchemeSpecs)

	for scheme, spec := range pqSchemeSpecs {
		require.NotNil(t, spec.Verify, "scheme %q", scheme)
		require.NotZero(t, spec.PublicKeySize, "scheme %q", scheme)
		require.NotZero(t, spec.SignatureSize, "scheme %q", scheme)
		require.NotZero(t, spec.FeeContribution, "scheme %q", scheme)

		lookup, ok := LookupPQScheme(scheme)
		require.True(t, ok, "scheme %q", scheme)
		require.Equal(t, spec.PublicKeySize, lookup.PublicKeySize, "scheme %q", scheme)
		require.Equal(t, spec.SignatureSize, lookup.SignatureSize, "scheme %q", scheme)
		require.Equal(t, spec.FeeContribution, lookup.FeeContribution, "scheme %q", scheme)
	}

	schemes := supportedPQSchemes()
	require.ElementsMatch(t, slices.Collect(maps.Keys(pqSchemeSpecs)), schemes)
	require.True(t, slices.IsSorted(schemes))
}

func TestLookupPQSchemeFalcon1024(t *testing.T) {
	partitiontest.PartitionTest(t)

	spec, ok := LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)
	require.Equal(t, uint64(crypto.FalconPublicKeySize), spec.PublicKeySize)
	require.Equal(t, uint64(crypto.FalconMaxSignatureSize), spec.SignatureSize)
	require.Equal(t, PQSchemeFalcon1024FeeContribution, spec.FeeContribution)
	require.NotNil(t, spec.Verify)

	_, ok = LookupPQScheme(protocol.PQScheme("x1"))
	require.False(t, ok)
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
	require.ErrorIs(t, err, ErrPQFalcon1024SigInvalid)

	err = spec.Verify(message, signer.PublicKey[:], nil)
	require.ErrorIs(t, err, ErrPQFalcon1024SigInvalid)

	err = spec.Verify(message, signer.PublicKey[:], make([]byte, crypto.FalconMaxSignatureSize+1))
	require.ErrorIs(t, err, ErrPQFalcon1024SigInvalid)
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
