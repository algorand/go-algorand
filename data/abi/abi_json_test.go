// Copyright (C) 2019-2022 Algorand, Inc.
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

package abi

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			addressString   string
			addressBytes    [32]byte
			addressChecksum [4]byte
		}{
			{
				addressString:   "CAFFDSU6TYXNDC6V6R5XAOHBWBD4MH36TNUWCW4D6HKV7EKHP33Q74JAFM",
				addressBytes:    [32]byte{16, 10, 81, 202, 158, 158, 46, 209, 139, 213, 244, 123, 112, 56, 225, 176, 71, 198, 31, 126, 155, 105, 97, 91, 131, 241, 213, 95, 145, 71, 126, 247},
				addressChecksum: [4]byte{15, 241, 32, 43},
			},
			{
				addressString:   "OXV2VEY7QJUXGOHEVFSL7LTBMOTYI4VORBJ37CGCHKBPJSH6IZQMHDPFRA",
				addressBytes:    [32]byte{117, 235, 170, 147, 31, 130, 105, 115, 56, 228, 169, 100, 191, 174, 97, 99, 167, 132, 114, 174, 136, 83, 191, 136, 194, 58, 130, 244, 200, 254, 70, 96},
				addressChecksum: [4]byte{195, 141, 229, 136},
			},
			{
				addressString:   "BFLADE6DETJQU7DABJANLCKH3PEFTWQQGZ34YHRPRKWYNEYC3DRWKJWZZA",
				addressBytes:    [32]byte{9, 86, 1, 147, 195, 36, 211, 10, 124, 96, 10, 64, 213, 137, 71, 219, 200, 89, 218, 16, 54, 119, 204, 30, 47, 138, 173, 134, 147, 2, 216, 227},
				addressChecksum: [4]byte{101, 38, 217, 200},
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.addressString, func(t *testing.T) {
				require.Equal(t, testCase.addressChecksum[:], addressCheckSum(testCase.addressBytes))
				require.Equal(t, testCase.addressString, addressToString(testCase.addressBytes))

				actualBytes, err := addressFromString(testCase.addressString)
				require.NoError(t, err)
				require.Equal(t, testCase.addressBytes, actualBytes)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			addressString string
			expectedError string
		}{
			{
				// incorrect checksum
				addressString: "CAFFDSU6TYXNDC6V6R5XAOHBWBD4MH36TNUWCW4D6HKV7EKHP33Q74JAQM",
				expectedError: "decoded checksum mismatch",
			},
			{
				// too many bytes
				addressString: "CAFFDSU6TYXNDC6V6R5XAOHBWBD4MH36TNUWCW4D6HKV7EKHP33Q74JAFMFM",
				expectedError: "decoded byte length should equal 36 with address and checksum",
			},
			{
				// too few bytes
				addressString: "CAFFDSU6TYXNDC6V6R5XAOHBWBD4MH36TNUWCW4D6HKV7EKHP33Q74JA",
				expectedError: "decoded byte length should equal 36 with address and checksum",
			},
			{
				// not base32
				addressString: "!!!",
				expectedError: "base32 decode error",
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.addressString, func(t *testing.T) {
				_, err := addressFromString(testCase.addressString)
				require.ErrorContains(t, err, testCase.expectedError)
			})
		}
	})
}

func TestUnmarshalFromJSON(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	var testCases = []struct {
		input    string
		typeStr  string
		expected interface{}
	}{
		{
			input:   `[true, [0, 1, 2], 17]`,
			typeStr: `(bool,byte[],uint64)`,
			expected: []interface{}{
				true,
				[]interface{}{byte(0), byte(1), byte(2)},
				uint64(17),
			},
		},
		{
			input:   `[true, "AAEC", 17]`,
			typeStr: `(bool,byte[],uint64)`,
			expected: []interface{}{
				true,
				[]interface{}{byte(0), byte(1), byte(2)},
				uint64(17),
			},
		},
		{
			input:    `"AQEEBQEE"`,
			typeStr:  `byte[6]`,
			expected: []interface{}{byte(1), byte(1), byte(4), byte(5), byte(1), byte(4)},
		},
		{
			input:   `[[0, [true, false], "utf-8"], [18446744073709551615, [false, true], "pistachio"]]`,
			typeStr: `(uint64,bool[2],string)[]`,
			expected: []interface{}{
				[]interface{}{uint64(0), []interface{}{true, false}, "utf-8"},
				[]interface{}{^uint64(0), []interface{}{false, true}, "pistachio"},
			},
		},
		{
			input:    `[]`,
			typeStr:  `(uint64,bool[2],string)[]`,
			expected: []interface{}{},
		},
		{
			input:    "[]",
			typeStr:  "()",
			expected: []interface{}{},
		},
		{
			input:    "[65, 66, 67]",
			typeStr:  "string",
			expected: "ABC",
		},
		{
			input:    "[]",
			typeStr:  "string",
			expected: "",
		},
		{
			input:    "123.456",
			typeStr:  "ufixed64x3",
			expected: uint64(123456),
		},
		{
			input:    `"optin"`,
			typeStr:  "string",
			expected: "optin",
		},
		{
			input:    `"AAEC"`,
			typeStr:  "byte[3]",
			expected: []interface{}{byte(0), byte(1), byte(2)},
		},
		{
			input:    `["uwu",["AAEC",12.34]]`,
			typeStr:  "(string,(byte[3],ufixed64x3))",
			expected: []interface{}{"uwu", []interface{}{[]interface{}{byte(0), byte(1), byte(2)}, uint64(12340)}},
		},
		{
			input:    `[399,"should pass",[true,false,false,true]]`,
			typeStr:  "(uint64,string,bool[])",
			expected: []interface{}{uint64(399), "should pass", []interface{}{true, false, false, true}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.input, func(t *testing.T) {
			abiT, err := TypeOf(testCase.typeStr)
			require.NoError(t, err, "fail to construct ABI type: %s", testCase.typeStr)

			res, err := abiT.UnmarshalFromJSON([]byte(testCase.input))
			require.NoError(t, err, "fail to unmarshal JSON to interface: (%s): %v", testCase.input, err)
			require.Equal(t, testCase.expected, res, "%v not matching with expected value %v", res, testCase.expected)

			resEncoded, err := abiT.Encode(res)
			require.NoError(t, err, "fail to encode %v to ABI bytes: %v", res, err)
			resDecoded, err := abiT.Decode(resEncoded)
			require.NoError(t, err, "fail to decode ABI bytes of %v: %v", res, err)
			require.Equal(t, res, resDecoded, "ABI encode-decode round trip: %v not match with expected %v", resDecoded, res)
		})
	}
}

func TestMarshalToJSON(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	var testCases = []struct {
		input    interface{}
		typeStr  string
		expected string
	}{
		{
			input:    true,
			typeStr:  `bool`,
			expected: `true`,
		},
		{
			input:    false,
			typeStr:  `bool`,
			expected: `false`,
		},
		{
			input:    uint64(117),
			typeStr:  `uint64`,
			expected: `117`,
		},
		{
			input:    big.NewInt(5834),
			typeStr:  `uint128`,
			expected: `5834`,
		},
		{
			input:    []interface{}{uint8(0), big.NewInt(1), uint32(2)},
			typeStr:  `(uint8,uint64,uint32)`,
			expected: `[0,1,2]`,
		},
		{
			input:    [3]interface{}{uint8(0), big.NewInt(1), uint32(2)},
			typeStr:  `(uint8,uint64,uint32)`,
			expected: `[0,1,2]`,
		},
		{
			input:    []uint8{0, 1, 2},
			typeStr:  `(uint8,uint64,uint32)`,
			expected: `[0,1,2]`,
		},
		{
			input:    [3]uint8{0, 1, 2},
			typeStr:  `(uint8,uint64,uint32)`,
			expected: `[0,1,2]`,
		},
		{
			input:    []uint64{0, 1, 2},
			typeStr:  `(uint8,uint64,uint32)`,
			expected: `[0,1,2]`,
		},
		{
			input:    [3]uint64{0, 1, 2},
			typeStr:  `(uint8,uint64,uint32)`,
			expected: `[0,1,2]`,
		},
		{
			input:    []interface{}{uint8(0), big.NewInt(1), uint32(2)},
			typeStr:  `uint8[]`,
			expected: `[0,1,2]`,
		},
		{
			input:    [3]interface{}{uint8(0), big.NewInt(1), uint32(2)},
			typeStr:  `uint8[]`,
			expected: `[0,1,2]`,
		},
		{
			input:    []uint8{0, 1, 2},
			typeStr:  `uint8[]`,
			expected: `[0,1,2]`,
		},
		{
			input:    [3]uint8{0, 1, 2},
			typeStr:  `uint8[]`,
			expected: `[0,1,2]`,
		},
		{
			input:    []uint64{0, 1, 2},
			typeStr:  `uint8[]`,
			expected: `[0,1,2]`,
		},
		{
			input:    [3]uint64{0, 1, 2},
			typeStr:  `uint8[]`,
			expected: `[0,1,2]`,
		},
		{
			input:    []interface{}{byte(0), byte(1), byte(2)},
			typeStr:  `byte[]`,
			expected: `"AAEC"`,
		},
		{
			input:    [3]interface{}{byte(0), byte(1), byte(2)},
			typeStr:  `byte[]`,
			expected: `"AAEC"`,
		},
		{
			input:    []byte{0, 1, 2},
			typeStr:  `byte[]`,
			expected: `"AAEC"`,
		},
		{
			input:    [3]byte{0, 1, 2},
			typeStr:  `byte[]`,
			expected: `"AAEC"`,
		},
		{
			input:    []byte{16, 10, 81, 202, 158, 158, 46, 209, 139, 213, 244, 123, 112, 56, 225, 176, 71, 198, 31, 126, 155, 105, 97, 91, 131, 241, 213, 95, 145, 71, 126, 247},
			typeStr:  `address`,
			expected: `"CAFFDSU6TYXNDC6V6R5XAOHBWBD4MH36TNUWCW4D6HKV7EKHP33Q74JAFM"`,
		},
		{
			input:    [32]byte{16, 10, 81, 202, 158, 158, 46, 209, 139, 213, 244, 123, 112, 56, 225, 176, 71, 198, 31, 126, 155, 105, 97, 91, 131, 241, 213, 95, 145, 71, 126, 247},
			typeStr:  `address`,
			expected: `"CAFFDSU6TYXNDC6V6R5XAOHBWBD4MH36TNUWCW4D6HKV7EKHP33Q74JAFM"`,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("i=%d", i), func(t *testing.T) {
			abiT, err := TypeOf(testCase.typeStr)
			require.NoError(t, err, "fail to construct ABI type: %s", testCase.typeStr)

			actualJSON, err := abiT.MarshalToJSON(testCase.input)
			require.NoError(t, err)

			require.Equal(t, testCase.expected, string(actualJSON))
		})
	}
}
