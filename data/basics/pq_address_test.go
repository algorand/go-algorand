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
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func falconPublicKeyForPQAddressTest(t *testing.T, firstSeedByte byte) []byte {
	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	signer, err := crypto.GenerateFalconSigner(seed)
	require.NoError(t, err)
	return slices.Clone(signer.PublicKey[:])
}

func TestPQAddressPreimage(t *testing.T) {
	partitiontest.PartitionTest(t)

	preimage := pqAddressPreimage{
		scheme: protocol.PQSchemeFalcon1024,
		salt:   PQAddressSalt(0x7f),
		pk:     []byte{0xab, 0xcd, 0xef},
	}

	hashID, payload := preimage.ToBeHashed()
	require.Equal(t, protocol.PostQuantumAddress, hashID)
	require.Equal(t, []byte{'f', '1', 0x7f, 0xab, 0xcd, 0xef}, payload)
}

func TestPQAddressKnownAnswers(t *testing.T) {
	partitiontest.PartitionTest(t)

	testCases := []struct {
		name            string
		firstSeedByte   byte
		salt            PQAddressSalt
		expectedAddress string
		compliant       bool
	}{
		{
			name:            "zero salt",
			firstSeedByte:   0,
			salt:            0,
			expectedAddress: "7ZQ6VZDWW5NECRV3XMW6L7YX743PFC55IEVS4X3GDHIW4NBMYLYTJT4VTA",
			compliant:       true,
		},
		{
			name:            "nonzero salt",
			firstSeedByte:   1,
			salt:            1,
			expectedAddress: "4X6LFIO4F7WZFXM24J567HAXW4FHXWKGVGPNCA4SMPPAYMZYSHYTB6XXC4",
			compliant:       true,
		},
		{
			name:            "max salt",
			firstSeedByte:   0,
			salt:            255,
			expectedAddress: "PFVGXUXMOHPMNTUMR67BYBUYCUCLD4ZSFRPCJOGI7BUGCX5CL47TZKFFWA",
			compliant:       true,
		},
		{
			name:            "different seed",
			firstSeedByte:   2,
			salt:            2,
			expectedAddress: "2K52PWFN2AWITVDB2QHWBQ6ZW4VMJK2LVFQMDFYG2Y32NDH37GHTYFQG2Y",
			compliant:       true,
		},
		{
			name:            "max seed and salt",
			firstSeedByte:   255,
			salt:            255,
			expectedAddress: "SVR2WW4Y3SUONROBQUBQX5T2R6IQQAINOHMDAADUPI4JCWR4XYELDRUZDU",
			compliant:       true,
		},
		{
			name:            "non-compliant on-curve address",
			firstSeedByte:   1,
			salt:            0,
			expectedAddress: "RJANW5CPBRBB3QK5XBPA3YWCFV2VQLD3HWV4KFMPMBJ7XFN2BPLKGU35KA",
			compliant:       false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			publicKey := falconPublicKeyForPQAddressTest(t, tc.firstSeedByte)

			addr := PQAddress(protocol.PQSchemeFalcon1024, tc.salt, publicKey)
			require.Equal(t, tc.expectedAddress, addr.String())
			require.Equal(t, tc.compliant, addr.IsPQCompliant())
			require.Equal(t, !tc.compliant, crypto.IsEdwards25519Point(addr[:]))

			addrAgain := PQAddress(protocol.PQSchemeFalcon1024, tc.salt, publicKey)
			require.Equal(t, addr, addrAgain)
		})
	}
}

func TestCanonicalPQAddressSalt(t *testing.T) {
	partitiontest.PartitionTest(t)

	publicKey := falconPublicKeyForPQAddressTest(t, 1)

	salt, addr, err := CanonicalPQAddressSalt(protocol.PQSchemeFalcon1024, publicKey)
	require.NoError(t, err)
	require.Equal(t, PQAddressSalt(1), salt)
	require.Equal(t, "4X6LFIO4F7WZFXM24J567HAXW4FHXWKGVGPNCA4SMPPAYMZYSHYTB6XXC4", addr.String())
	require.True(t, addr.IsPQCompliant())

	for lowerSalt := 0; lowerSalt < int(salt); lowerSalt++ {
		lowerAddr := PQAddress(protocol.PQSchemeFalcon1024, PQAddressSalt(lowerSalt), publicKey)
		require.False(t, lowerAddr.IsPQCompliant())
	}
}

func TestCanonicalPQAddressSaltDoesNotRequireRegisteredSchemeOrValidatedKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	publicKey := []byte{0xab, 0xcd, 0xef}
	scheme := protocol.PQScheme("x1")

	salt, addr, err := CanonicalPQAddressSalt(scheme, publicKey)
	require.NoError(t, err)
	require.Equal(t, PQAddress(scheme, salt, publicKey), addr)
	require.True(t, addr.IsPQCompliant())

	for lowerSalt := 0; lowerSalt < int(salt); lowerSalt++ {
		lowerAddr := PQAddress(scheme, PQAddressSalt(lowerSalt), publicKey)
		require.False(t, lowerAddr.IsPQCompliant())
	}
}

func TestCanonicalPQAddressSaltRejectsInvalidSchemeLength(t *testing.T) {
	partitiontest.PartitionTest(t)

	publicKey := falconPublicKeyForPQAddressTest(t, 0)

	for _, scheme := range []protocol.PQScheme{"", "x", "xyz"} {
		_, _, err := CanonicalPQAddressSalt(scheme, publicKey)
		require.ErrorIs(t, err, errPQSchemeLength)
	}
}
