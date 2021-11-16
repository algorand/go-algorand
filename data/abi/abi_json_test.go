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

package abi

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestJSONtoInterfaceValid(t *testing.T) {
	partitiontest.PartitionTest(t)
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
		abiT, err := TypeOf(testCase.typeStr)
		require.NoError(t, err, "fail to construct ABI type (%s): %v", testCase.typeStr, err)
		res, err := abiT.UnmarshalFromJSON([]byte(testCase.input))
		require.NoError(t, err, "fail to unmarshal JSON to interface: (%s): %v", testCase.input, err)
		require.Equal(t, testCase.expected, res, "%v not matching with expected value %v", res, testCase.expected)
		resEncoded, err := abiT.Encode(res)
		require.NoError(t, err, "fail to encode %v to ABI bytes: %v", res, err)
		resDecoded, err := abiT.Decode(resEncoded)
		require.NoError(t, err, "fail to decode ABI bytes of %v: %v", res, err)
		require.Equal(t, res, resDecoded, "ABI encode-decode round trip: %v not match with expected %v", resDecoded, res)
	}
}
