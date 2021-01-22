// Copyright (C) 2019-2021 Algorand, Inc.
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
)

func TestChecksumAddress_Unmarshal(t *testing.T) {
	address := crypto.Hash([]byte("randomString"))
	shortAddress := Address(address)

	addr, err := UnmarshalChecksumAddress(shortAddress.String())

	require.Nil(t, err)

	require.Equal(t, addr, shortAddress)
}

func TestAddressChecksumMalformedWrongChecksum(t *testing.T) {
	address := crypto.Hash([]byte("randomString"))
	shortAddress := Address(address)

	// Change it slightly
	_, err := UnmarshalChecksumAddress(shortAddress.String() + "r")

	require.NotNil(t, err)
}

func TestAddressChecksumShort(t *testing.T) {
	var address string
	_, err := UnmarshalChecksumAddress(address)
	require.NotNil(t, err)
}

func TestAddressChecksumMalformedWrongChecksumSpace(t *testing.T) {
	address := crypto.Hash([]byte("randomString"))
	shortAddress := Address(address)

	// Flip a bit
	_, err := UnmarshalChecksumAddress(shortAddress.String() + " ")

	require.NotNil(t, err)
}

func TestAddressChecksumMalformedWrongAddress(t *testing.T) {
	address := crypto.Hash([]byte("randomString"))
	shortAddress := Address(address)

	// Flip a bit
	_, err := UnmarshalChecksumAddress("4" + shortAddress.String())

	require.NotNil(t, err)
}

func TestAddressChecksumMalformedWrongAddressSpaces(t *testing.T) {
	address := crypto.Hash([]byte("randomString"))
	shortAddress := Address(address)

	// Flip a bit
	_, err := UnmarshalChecksumAddress(" " + shortAddress.String())

	require.NotNil(t, err)
}

func TestAddressChecksumCanonical(t *testing.T) {
	addr := "J5YDZLPOHWB5O6MVRHNFGY4JXIQAYYM6NUJWPBSYBBIXH5ENQ4Z5LTJELU"
	nonCanonical := "J5YDZLPOHWB5O6MVRHNFGY4JXIQAYYM6NUJWPBSYBBIXH5ENQ4Z5LTJELV"

	_, err := UnmarshalChecksumAddress(addr)
	require.NoError(t, err)

	_, err = UnmarshalChecksumAddress(nonCanonical)
	require.Error(t, err)
}

type TestOb struct {
	Aaaa Address `codec:"aaaa,omitempty"`
}

func TestAddressMarshalUnmarshal(t *testing.T) {
	var addr Address
	crypto.RandBytes(addr[:])
	testob := TestOb{Aaaa: addr}
	data := protocol.EncodeJSON(testob)
	var nob TestOb
	err := protocol.DecodeJSON(data, &nob)
	require.NoError(t, err)
	require.Equal(t, testob, nob)
}

func BenchmarkAddressFormatting(b *testing.B) {
	addr := "J5YDZLPOHWB5O6MVRHNFGY4JXIQAYYM6NUJWPBSYBBIXH5ENQ4Z5LTJELU"
	uaddr, err := UnmarshalChecksumAddress(addr)
	require.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		stringed := uaddr.String()
		if len(stringed) == 0 {
			break
		}
	}
}

func BenchmarkUnmarshalChecksumAddress(b *testing.B) {
	addr := "J5YDZLPOHWB5O6MVRHNFGY4JXIQAYYM6NUJWPBSYBBIXH5ENQ4Z5LTJELU"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := UnmarshalChecksumAddress(addr)
		if err != nil {
			break
		}
	}
}
