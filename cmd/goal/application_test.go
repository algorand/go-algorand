// Copyright (C) 2019-2024 Algorand, Inc.
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

package main

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestParseMethodArgJSONtoByteSlice(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	makeRepeatSlice := func(size int, value string) []string {
		slice := make([]string, size)
		for i := range slice {
			slice[i] = value
		}
		return slice
	}

	tests := []struct {
		argTypes        []string
		jsonArgs        []string
		expectedAppArgs [][]byte
	}{
		{
			argTypes:        []string{},
			jsonArgs:        []string{},
			expectedAppArgs: [][]byte{},
		},
		{
			argTypes:        []string{"uint8"},
			jsonArgs:        []string{"100"},
			expectedAppArgs: [][]byte{{100}},
		},
		{
			argTypes:        []string{"uint8", "uint16"},
			jsonArgs:        []string{"100", "65535"},
			expectedAppArgs: [][]byte{{100}, {255, 255}},
		},
		{
			argTypes: makeRepeatSlice(15, "string"),
			jsonArgs: []string{
				`"a"`,
				`"b"`,
				`"c"`,
				`"d"`,
				`"e"`,
				`"f"`,
				`"g"`,
				`"h"`,
				`"i"`,
				`"j"`,
				`"k"`,
				`"l"`,
				`"m"`,
				`"n"`,
				`"o"`,
			},
			expectedAppArgs: [][]byte{
				{00, 01, 97},
				{00, 01, 98},
				{00, 01, 99},
				{00, 01, 100},
				{00, 01, 101},
				{00, 01, 102},
				{00, 01, 103},
				{00, 01, 104},
				{00, 01, 105},
				{00, 01, 106},
				{00, 01, 107},
				{00, 01, 108},
				{00, 01, 109},
				{00, 01, 110},
				{00, 01, 111},
			},
		},
		{
			argTypes: makeRepeatSlice(16, "string"),
			jsonArgs: []string{
				`"a"`,
				`"b"`,
				`"c"`,
				`"d"`,
				`"e"`,
				`"f"`,
				`"g"`,
				`"h"`,
				`"i"`,
				`"j"`,
				`"k"`,
				`"l"`,
				`"m"`,
				`"n"`,
				`"o"`,
				`"p"`,
			},
			expectedAppArgs: [][]byte{
				{00, 01, 97},
				{00, 01, 98},
				{00, 01, 99},
				{00, 01, 100},
				{00, 01, 101},
				{00, 01, 102},
				{00, 01, 103},
				{00, 01, 104},
				{00, 01, 105},
				{00, 01, 106},
				{00, 01, 107},
				{00, 01, 108},
				{00, 01, 109},
				{00, 01, 110},
				{00, 04, 00, 07, 00, 01, 111, 00, 01, 112},
			},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("index=%d", i), func(t *testing.T) {
			t.Parallel()
			applicationArgs := [][]byte{}
			err := parseMethodArgJSONtoByteSlice(test.argTypes, test.jsonArgs, &applicationArgs)
			require.NoError(t, err)
			require.Equal(t, test.expectedAppArgs, applicationArgs)
		})
	}
}
