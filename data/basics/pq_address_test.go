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

func falconPublicKeyForPQAddressTest(t *testing.T, scheme protocol.PQScheme, firstSeedByte byte) []byte {
	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	switch scheme {
	case protocol.PQSchemeFalcon1024:
		signer, err := crypto.GenerateFalcon1024Signer(seed)
		require.NoError(t, err)
		return signer.PublicKey[:]
	case protocol.PQSchemeFalcon512:
		signer, err := crypto.GenerateFalcon512Signer(seed)
		require.NoError(t, err)
		return signer.PublicKey[:]
	}
	t.Fatalf("unknown scheme %s", scheme)
	return nil
}

func TestPQAddressPreimage(t *testing.T) {
	partitiontest.PartitionTest(t)

	testCases := []struct {
		name            string
		scheme          protocol.PQScheme
		expectedPayload []byte
	}{
		{
			name:            "falcon-1024",
			scheme:          protocol.PQSchemeFalcon1024,
			expectedPayload: []byte{'f', '1', 0x7f, 0xab, 0xcd, 0xef},
		},
		{
			name:            "falcon-512",
			scheme:          protocol.PQSchemeFalcon512,
			expectedPayload: []byte{'f', '5', 0x7f, 0xab, 0xcd, 0xef},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			preimage := pqAddressPreimage{
				scheme: tc.scheme,
				salt:   PQAddressSalt(0x7f),
				pk:     []byte{0xab, 0xcd, 0xef},
			}

			hashID, payload := preimage.ToBeHashed()
			require.Equal(t, protocol.PostQuantumAddress, hashID)
			require.Equal(t, tc.expectedPayload, payload)
		})
	}
}

func TestPQAddressKnownAnswers(t *testing.T) {
	partitiontest.PartitionTest(t)

	type knownAnswer struct {
		name            string
		firstSeedByte   byte
		salt            PQAddressSalt
		expectedAddress string
		compliant       bool
	}

	testCases := []struct {
		name    string
		scheme  protocol.PQScheme
		answers []knownAnswer
	}{
		{
			name:   "falcon-1024",
			scheme: protocol.PQSchemeFalcon1024,
			answers: []knownAnswer{
				{
					name:            "zero salt",
					firstSeedByte:   3,
					salt:            0,
					expectedAddress: "KJGJA2DTCQH6LT2I2OH2YO5GIIBFC6JHX5O6UPA5ZZ5ZURFT3LHKMTRCEM",
					compliant:       true,
				},
				{
					name:            "nonzero salt",
					firstSeedByte:   1,
					salt:            1,
					expectedAddress: "GYBWVYVQIQF6CO7BUMG4UQ66DQYHASFOCA2P7PBYOIPKGWUZIBX4KA3TP4",
					compliant:       true,
				},
				{
					name:            "max salt",
					firstSeedByte:   0,
					salt:            255,
					expectedAddress: "YJFADDEP6Z3WAWY6ZMLN6MF4T4NK3BXKCVLPCYB6C4SQHE76LLQSZ5JG7Q",
					compliant:       true,
				},
				{
					name:            "different seed",
					firstSeedByte:   2,
					salt:            2,
					expectedAddress: "II4DO6IIP3EAEQMWJEOLOUU3VBRVCH3WF4MX6UCRUD36DOQJ3YSHA2DV5A",
					compliant:       true,
				},
				{
					name:            "max seed and salt",
					firstSeedByte:   255,
					salt:            255,
					expectedAddress: "3JXWI6BYYEO6WO6M7TC4SOZAZUWAD4RQO5GJ2ED6MYIEVVLOVJOETMGG4A",
					compliant:       true,
				},
				{
					name:            "non-compliant on-curve address",
					firstSeedByte:   1,
					salt:            0,
					expectedAddress: "FLX4VRWXQ65HD5G5BI2EPHJWMERHA2EBBQ7XMTZLATXH4XEOWPQSIYVIF4",
					compliant:       false,
				},
			},
		},
		{
			name:   "falcon-512",
			scheme: protocol.PQSchemeFalcon512,
			answers: []knownAnswer{
				{
					name:            "zero salt",
					firstSeedByte:   3,
					salt:            0,
					expectedAddress: "L3E466XEV24FAQ3GYW4NDWNVVQG5SKNW4P7FO7JB72AL35WU4BYIUBWFLQ",
					compliant:       true,
				},
				{
					name:            "nonzero salt",
					firstSeedByte:   1,
					salt:            1,
					expectedAddress: "NQHOCVCR45XKZ5LMJSBDWGPZ6QZQIDKQU26KNQ3O4A3EGIRR7BPIX4CW3A",
					compliant:       true,
				},
				{
					name:            "max salt",
					firstSeedByte:   0,
					salt:            255,
					expectedAddress: "6SNBFGF6MKPQZMP5QFTXJQVMNB2VYT4DCKVTGH3UN3KDSF3BXSNX75ZTJE",
					compliant:       true,
				},
				{
					name:            "different seed",
					firstSeedByte:   2,
					salt:            2,
					expectedAddress: "WZMDFDVTJIFGANZKOIHUDI2TIATEIMGA7RPGAOGURFWOH6KTN3DHTLXCBU",
					compliant:       false,
				},
				{
					name:            "max seed and salt",
					firstSeedByte:   255,
					salt:            255,
					expectedAddress: "HIUU22OZWNLI6MBXNQ4DFUUXMG4ASF7CIUIWRLQC4WDTUGNCAXSCRUHUME",
					compliant:       true,
				},
				{
					name:            "non-compliant on-curve address",
					firstSeedByte:   1,
					salt:            0,
					expectedAddress: "AFNGS72MUDN72N5MQREE57URNHIH3MSDZZS42WGNPAXKTC3JZSC22S7CBA",
					compliant:       false,
				},
			},
		},
	}

	for _, sc := range testCases {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range sc.answers {
				t.Run(tc.name, func(t *testing.T) {
					publicKey := falconPublicKeyForPQAddressTest(t, sc.scheme, tc.firstSeedByte)

					addr := PQAddress(sc.scheme, tc.salt, publicKey)
					require.Equal(t, tc.expectedAddress, addr.String())
					require.Equal(t, tc.compliant, addr.IsPQCompliant())
					require.Equal(t, !tc.compliant, crypto.IsEdwards25519Point(addr[:]))

					addrAgain := PQAddress(sc.scheme, tc.salt, publicKey)
					require.Equal(t, addr, addrAgain)
				})
			}
		})
	}
}

func TestCanonicalPQAddressSalt(t *testing.T) {
	partitiontest.PartitionTest(t)

	testCases := []struct {
		name            string
		scheme          protocol.PQScheme
		expectedSalt    PQAddressSalt
		expectedAddress string
	}{
		{
			name:            "falcon-1024",
			scheme:          protocol.PQSchemeFalcon1024,
			expectedSalt:    1,
			expectedAddress: "GYBWVYVQIQF6CO7BUMG4UQ66DQYHASFOCA2P7PBYOIPKGWUZIBX4KA3TP4",
		},
		{
			name:            "falcon-512",
			scheme:          protocol.PQSchemeFalcon512,
			expectedSalt:    1,
			expectedAddress: "NQHOCVCR45XKZ5LMJSBDWGPZ6QZQIDKQU26KNQ3O4A3EGIRR7BPIX4CW3A",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			publicKey := falconPublicKeyForPQAddressTest(t, tc.scheme, 1)

			salt, addr, err := CanonicalPQAddressSalt(tc.scheme, publicKey)
			require.NoError(t, err)
			require.Equal(t, tc.expectedSalt, salt)
			require.Equal(t, tc.expectedAddress, addr.String())
			require.True(t, addr.IsPQCompliant())

			for lowerSalt := 0; lowerSalt < int(salt); lowerSalt++ {
				lowerAddr := PQAddress(tc.scheme, PQAddressSalt(lowerSalt), publicKey)
				require.False(t, lowerAddr.IsPQCompliant())
			}
		})
	}
}

func TestCanonicalPQAddressSaltDoesNotRequireRegisteredSchemeOrValidatedKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	publicKey := []byte{0xab, 0xcd, 0xef}
	scheme := protocol.PQScheme{'x', '1'}

	salt, addr, err := CanonicalPQAddressSalt(scheme, publicKey)
	require.NoError(t, err)
	require.Equal(t, PQAddress(scheme, salt, publicKey), addr)
	require.True(t, addr.IsPQCompliant())

	for lowerSalt := 0; lowerSalt < int(salt); lowerSalt++ {
		lowerAddr := PQAddress(scheme, PQAddressSalt(lowerSalt), publicKey)
		require.False(t, lowerAddr.IsPQCompliant())
	}
}
