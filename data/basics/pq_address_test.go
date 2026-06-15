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

func falconPublicKeyForPQAddressTest(t *testing.T, firstSeedByte byte) []byte {
	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	signer, err := crypto.GenerateFalconSigner(seed)
	require.NoError(t, err)
	return append([]byte(nil), signer.PublicKey[:]...)
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
	}{
		{
			name:            "zero salt",
			firstSeedByte:   0,
			salt:            0,
			expectedAddress: "7ZQ6VZDWW5NECRV3XMW6L7YX743PFC55IEVS4X3GDHIW4NBMYLYTJT4VTA",
		},
		{
			name:            "nonzero salt",
			firstSeedByte:   1,
			salt:            1,
			expectedAddress: "4X6LFIO4F7WZFXM24J567HAXW4FHXWKGVGPNCA4SMPPAYMZYSHYTB6XXC4",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			publicKey := falconPublicKeyForPQAddressTest(t, tc.firstSeedByte)

			addr := PQAddress(protocol.PQSchemeFalcon1024, tc.salt, publicKey)
			require.Equal(t, tc.expectedAddress, addr.String())
			require.False(t, crypto.IsEdwards25519Point(addr[:]))
			require.True(t, addr.IsPQCompliant())

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

func TestCanonicalPQAddressSaltRejectsInvalidInputs(t *testing.T) {
	partitiontest.PartitionTest(t)

	publicKey := falconPublicKeyForPQAddressTest(t, 0)

	_, _, err := CanonicalPQAddressSalt(protocol.PQSchemeFalcon1024, publicKey[:len(publicKey)-1])
	require.Error(t, err)

	_, _, err = CanonicalPQAddressSalt(protocol.PQScheme("x1"), publicKey)
	require.ErrorIs(t, err, ErrPQSchemeNotSupported)
}
