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

func publicKeyForSaltedAddressTest(t *testing.T, scheme protocol.SigScheme, firstSeedByte byte) []byte {
	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	switch scheme {
	case protocol.SigSchemeFalcon1024:
		signer, err := crypto.GenerateFalcon1024Signer(seed)
		require.NoError(t, err)
		return signer.PublicKey[:]
	case protocol.SigSchemeFalcon512:
		signer, err := crypto.GenerateFalcon512Signer(seed)
		require.NoError(t, err)
		return signer.PublicKey[:]
	case protocol.SigSchemeEd25519:
		signer := crypto.GenerateSignatureSecrets(crypto.Seed{firstSeedByte})
		return signer.SignatureVerifier[:]
	}
	t.Fatalf("unknown scheme %s", scheme)
	return nil
}

func TestSaltedAddressPreimage(t *testing.T) {
	partitiontest.PartitionTest(t)

	testCases := []struct {
		name            string
		scheme          protocol.SigScheme
		expectedPayload []byte
	}{
		{
			name:            "falcon-1024",
			scheme:          protocol.SigSchemeFalcon1024,
			expectedPayload: []byte{'f', '1', 0x7f, 0xab, 0xcd, 0xef},
		},
		{
			name:            "falcon-512",
			scheme:          protocol.SigSchemeFalcon512,
			expectedPayload: []byte{'f', '5', 0x7f, 0xab, 0xcd, 0xef},
		},
		{
			name:            "ed25519",
			scheme:          protocol.SigSchemeEd25519,
			expectedPayload: []byte{'e', 'd', 0x7f, 0xab, 0xcd, 0xef},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			preimage := saltedAddressPreimage{
				scheme: tc.scheme,
				salt:   AddressSalt(0x7f),
				pk:     []byte{0xab, 0xcd, 0xef},
			}

			hashID, payload := preimage.ToBeHashed()
			require.Equal(t, protocol.PostQuantumAddress, hashID)
			require.Equal(t, tc.expectedPayload, payload)
		})
	}
}

func TestSaltedAddressKnownAnswers(t *testing.T) {
	partitiontest.PartitionTest(t)

	type knownAnswer struct {
		name            string
		firstSeedByte   byte
		salt            AddressSalt
		expectedAddress string
		compliant       bool
	}

	testCases := []struct {
		name    string
		scheme  protocol.SigScheme
		answers []knownAnswer
	}{
		{
			name:   "falcon-1024",
			scheme: protocol.SigSchemeFalcon1024,
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
			scheme: protocol.SigSchemeFalcon512,
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
		{
			name:   "ed25519",
			scheme: protocol.SigSchemeEd25519,
			answers: []knownAnswer{
				{
					name:            "zero salt",
					firstSeedByte:   3,
					salt:            0,
					expectedAddress: "BS24KS3PNANVECBJECXBRKSCEYCHY2KUQFAAGX6DR2JMYITDN3W5A3M3M4",
					compliant:       false,
				},
				{
					name:            "nonzero salt",
					firstSeedByte:   1,
					salt:            1,
					expectedAddress: "76X26JCOZ6KBTLL4LLIYHBGM5THQPWVNOMRFBVK43MWTWRFBYCLZHACW2M",
					compliant:       false,
				},
				{
					name:            "max salt",
					firstSeedByte:   0,
					salt:            255,
					expectedAddress: "RVYDADZDRDSIHWI4R4TTALJPGGBO4ZWGK2R4YTGQGUMKJCVKHQETODHA5Q",
					compliant:       true,
				},
				{
					name:            "different seed",
					firstSeedByte:   2,
					salt:            2,
					expectedAddress: "JDIRZBWHK6SDOXKRGSNRCO7I4BF6ACVN4ACPHLNGINQNKFZOMHC2YY5TQM",
					compliant:       false,
				},
				{
					name:            "max seed and salt",
					firstSeedByte:   255,
					salt:            255,
					expectedAddress: "XVNRCMCRAYGJ3RUGN57YX2SKDLAJ6DNBO2LE5YLVG4OGQEC6SXMSO7V7EE",
					compliant:       true,
				},
				{
					name:            "different salt",
					firstSeedByte:   1,
					salt:            0,
					expectedAddress: "52TWNOHFPAIAQPARIGBF3SXBHZ6NEX6QURSOTXYBUI5JXIO4DEBMZEF5AQ",
					compliant:       true,
				},
			},
		},
	}

	for _, sc := range testCases {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range sc.answers {
				t.Run(tc.name, func(t *testing.T) {
					publicKey := publicKeyForSaltedAddressTest(t, sc.scheme, tc.firstSeedByte)

					addr := SaltedAddress(sc.scheme, tc.salt, publicKey)
					require.Equal(t, tc.expectedAddress, addr.String())
					require.Equal(t, tc.compliant, addr.IsOffEd25519Curve())
					require.Equal(t, !tc.compliant, crypto.IsEdwards25519Point(addr[:]))

					addrAgain := SaltedAddress(sc.scheme, tc.salt, publicKey)
					require.Equal(t, addr, addrAgain)
				})
			}
		})
	}
}

func TestCanonicalAddressSalt(t *testing.T) {
	partitiontest.PartitionTest(t)

	testCases := []struct {
		name            string
		scheme          protocol.SigScheme
		expectedSalt    AddressSalt
		expectedAddress string
	}{
		{
			name:            "falcon-1024",
			scheme:          protocol.SigSchemeFalcon1024,
			expectedSalt:    1,
			expectedAddress: "GYBWVYVQIQF6CO7BUMG4UQ66DQYHASFOCA2P7PBYOIPKGWUZIBX4KA3TP4",
		},
		{
			name:            "falcon-512",
			scheme:          protocol.SigSchemeFalcon512,
			expectedSalt:    1,
			expectedAddress: "NQHOCVCR45XKZ5LMJSBDWGPZ6QZQIDKQU26KNQ3O4A3EGIRR7BPIX4CW3A",
		},
		{
			name:            "ed25519",
			scheme:          protocol.SigSchemeEd25519,
			expectedSalt:    0,
			expectedAddress: "52TWNOHFPAIAQPARIGBF3SXBHZ6NEX6QURSOTXYBUI5JXIO4DEBMZEF5AQ",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			publicKey := publicKeyForSaltedAddressTest(t, tc.scheme, 1)

			salt, addr, err := CanonicalAddressSalt(tc.scheme, publicKey)
			require.NoError(t, err)
			require.Equal(t, tc.expectedSalt, salt)
			require.Equal(t, tc.expectedAddress, addr.String())
			require.True(t, addr.IsOffEd25519Curve())

			for lowerSalt := 0; lowerSalt < int(salt); lowerSalt++ {
				lowerAddr := SaltedAddress(tc.scheme, AddressSalt(lowerSalt), publicKey)
				require.False(t, lowerAddr.IsOffEd25519Curve())
			}
		})
	}
}

func TestLogicSigSaltedAddress(t *testing.T) {
	partitiontest.PartitionTest(t)

	program := []byte{0x02, 0x81, 0x01} // #pragma version 2; int 1

	salt, addr, err := CanonicalAddressSalt(protocol.SigSchemeLogicSig, program)
	require.NoError(t, err)
	require.True(t, addr.IsOffEd25519Curve())
	require.Equal(t, SaltedAddress(protocol.SigSchemeLogicSig, salt, program), addr)

	// The salt is derived from the program, so the address can always be
	// recovered from the program alone.
	againSalt, againAddr, err := CanonicalAddressSalt(protocol.SigSchemeLogicSig, program)
	require.NoError(t, err)
	require.Equal(t, salt, againSalt)
	require.Equal(t, addr, againAddr)

	for lowerSalt := 0; lowerSalt < int(salt); lowerSalt++ {
		lowerAddr := SaltedAddress(protocol.SigSchemeLogicSig, AddressSalt(lowerSalt), program)
		require.False(t, lowerAddr.IsOffEd25519Curve())
	}

	// The scheme is part of the preimage, so a program's address cannot collide
	// with the address a Falcon key of the same bytes would derive.
	require.NotEqual(t, SaltedAddress(protocol.SigSchemeFalcon1024, salt, program), addr)

	// Known answers pin the derivation, since an ls address is the account a
	// program's funds live in.
	knownAnswers := []struct {
		name    string
		program []byte
		salt    AddressSalt
		address string
	}{
		{"salt 0", []byte{0x02, 0x81, 0x00}, 0, "ZTVEN2GVT6W3DYVZT5KO4PSY7AXRSFGUIKLH4YD4KGZTFYKBP2RWDRXDIQ"},
		{"salt 1", []byte{0x02, 0x81, 0x01}, 1, "7YFBCWMMRGDBDM6VRV7YSK4TNOJK46BJHT26DKBOQALMSW6LC4PT2JVDRQ"},
		// #pragma version 14; pushbytes "open sesame"; arg_0; ==
		{"salt 2", []byte{0x0e, 0x80, 0x0b, 'o', 'p', 'e', 'n', ' ', 's', 'e', 's', 'a', 'm', 'e', 0x2d, 0x12}, 2,
			"X27OL4EPK5EQO6BAINO3NSJ7IRYP4JL4R4FGEINIABZIVOZBLS2WFHRTTM"},
	}
	for _, ka := range knownAnswers {
		t.Run(ka.name, func(t *testing.T) {
			salt, addr, err := CanonicalAddressSalt(protocol.SigSchemeLogicSig, ka.program)
			require.NoError(t, err)
			require.Equal(t, ka.salt, salt)
			require.Equal(t, ka.address, addr.String())
		})
	}
}

func TestCanonicalAddressSaltDoesNotRequireRegisteredSchemeOrValidatedKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	publicKey := []byte{0xab, 0xcd, 0xef}
	scheme := protocol.SigScheme{'x', '1'}

	salt, addr, err := CanonicalAddressSalt(scheme, publicKey)
	require.NoError(t, err)
	require.Equal(t, SaltedAddress(scheme, salt, publicKey), addr)
	require.True(t, addr.IsOffEd25519Curve())

	for lowerSalt := 0; lowerSalt < int(salt); lowerSalt++ {
		lowerAddr := SaltedAddress(scheme, AddressSalt(lowerSalt), publicKey)
		require.False(t, lowerAddr.IsOffEd25519Curve())
	}
}
