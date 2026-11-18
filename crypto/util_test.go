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

package crypto

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestEncodeDecode(t *testing.T) {
	partitiontest.PartitionTest(t)
	toBeHashed := []byte("this is a test")
	hashed := Hash(toBeHashed)
	hashedStr := hashed.String()
	recovered, err := DigestFromString(hashedStr)

	require.Equal(t, nil, err)
	require.Equal(t, recovered, hashed)
}

func TestDigest_IsZero(t *testing.T) {
	partitiontest.PartitionTest(t)
	d := Digest{}
	require.True(t, d.IsZero())
	require.Zero(t, d)

	d2 := Digest{}
	RandBytes(d2[:])
	require.False(t, d2.IsZero())
	require.NotZero(t, d2)

}

type testToBeHashed struct {
	i int
}

func (tbh *testToBeHashed) ToBeHashed() (protocol.HashID, []byte) {
	data := make([]byte, tbh.i)
	for x := 0; x < tbh.i; x++ {
		data[x] = byte(tbh.i)
	}
	return protocol.HashID(fmt.Sprintf("ID%d", tbh.i)), data
}

func TestHashRepToBuff(t *testing.T) {
	partitiontest.PartitionTest(t)
	values := []int{32, 64, 512, 1024}
	buffer := make([]byte, 0, 128)
	for _, val := range values {
		tbh := &testToBeHashed{i: val}
		buffer = HashRepToBuff(tbh, buffer)
	}
	pos := 0
	for _, val := range values {
		tbh := &testToBeHashed{i: val}
		data := HashRep(tbh)
		require.Equal(t, data, buffer[pos:pos+len(data)])
		pos = pos + len(data)
	}
}

// TestByteTypesFormatAsHex checks that %v and %s print these types as hex
// rather than as one decimal number per byte.
func TestByteTypesFormatAsHex(t *testing.T) {
	partitiontest.PartitionTest(t)

	var pk VrfPubkey
	pk[0], pk[1] = 0x01, 0xab
	var proof VrfProof
	proof[0], proof[1] = 0x01, 0xab
	var d512 Sha512Digest
	d512[0], d512[1] = 0x01, 0xab
	var otsv OneTimeSignatureVerifier
	otsv[0], otsv[1] = 0x01, 0xab
	gd := GenericDigest{0x01, 0xab, 0x00}
	var sig Signature
	sig[0], sig[1] = 0x01, 0xab

	tests := []struct {
		name string
		v    any
		want string
	}{
		{"VrfPubkey", pk, "01ab" + strings.Repeat("00", 30)},
		{"VRFVerifier", VRFVerifier(pk), "01ab" + strings.Repeat("00", 30)},
		{"VrfProof", proof, "01ab" + strings.Repeat("00", 78)},
		{"Sha512Digest", d512, "01ab" + strings.Repeat("00", 62)},
		{"OneTimeSignatureVerifier", otsv, "01ab" + strings.Repeat("00", 30)},
		{"GenericDigest", gd, "01ab00"},
		{"empty GenericDigest", GenericDigest(nil), ""},
		{"PublicKey", PublicKey(otsv), "01ab" + strings.Repeat("00", 30)},
		{"ed25519PublicKey", ed25519PublicKey(otsv), "01ab" + strings.Repeat("00", 30)},
		{"Signature", sig, "01ab" + strings.Repeat("00", 62)},
		{"ed25519Signature", ed25519Signature(sig), "01ab" + strings.Repeat("00", 62)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, fmt.Sprintf("%v", tc.v))
			require.Equal(t, tc.want, fmt.Sprintf("%s", tc.v))
		})
	}
}
