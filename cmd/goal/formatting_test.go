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
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestUnicodePrintable(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testUnicodePrintableStrings := []struct {
		testString      string
		isPrintable     bool
		printableString string
	}{
		{"abc", true, "abc"},
		{"", true, ""},
		{"אבג", true, "אבג"},
		{"\u001b[31mABC\u001b[0m", false, "[31mABC[0m"},
		{"ab\nc", false, "abc"},
	}
	for _, testElement := range testUnicodePrintableStrings {
		isPrintable, printableString := unicodePrintable(testElement.testString)
		require.Equalf(t, testElement.isPrintable, isPrintable, "test string:%s", testElement.testString)
		require.Equalf(t, testElement.printableString, printableString, "test string:%s", testElement.testString)
	}
}

func TestNewAppCallBytes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	acb := newAppCallBytes("int:3")
	require.Equal(t, "int", acb.Encoding)
	require.Equal(t, "3", acb.Value)
	_, err := acb.Raw()
	require.NoError(t, err)

	require.Panics(t, func() { newAppCallBytes("hello") })
}

func TestNewBoxRef(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	br := newBoxRef("str:hello")
	require.EqualValues(t, 0, br.appID)
	require.Equal(t, "str", br.name.Encoding)
	require.Equal(t, "hello", br.name.Value)

	require.Panics(t, func() { newBoxRef("1,hello") })
	require.Panics(t, func() { newBoxRef("hello") })

	br = newBoxRef("2,str:hello")
	require.EqualValues(t, 2, br.appID)
	require.Equal(t, "str", br.name.Encoding)
	require.Equal(t, "hello", br.name.Value)
}

func TestStringsToBoxRefs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	brs := stringsToBoxRefs([]string{"77,str:hello", "55,int:6", "int:88"})
	require.EqualValues(t, 77, brs[0].appID)
	require.EqualValues(t, 55, brs[1].appID)
	require.EqualValues(t, 0, brs[2].appID)

	tbrs := translateBoxRefs(brs, []uint64{55, 77})
	require.EqualValues(t, 2, tbrs[0].Index)
	require.EqualValues(t, 1, tbrs[1].Index)
	require.EqualValues(t, 0, tbrs[2].Index)

	require.Panics(t, func() { translateBoxRefs(stringsToBoxRefs([]string{"addr:88"}), nil) })
	translateBoxRefs(stringsToBoxRefs([]string{"addr:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"}), nil)
	// if we're here, that didn't panic/exit

	tbrs = translateBoxRefs(brs, []uint64{77, 55})
	require.EqualValues(t, 1, tbrs[0].Index)
	require.EqualValues(t, 2, tbrs[1].Index)
	require.EqualValues(t, 0, tbrs[2].Index)

	require.Panics(t, func() { translateBoxRefs(brs, []uint64{55, 78}) })
	require.Panics(t, func() { translateBoxRefs(brs, []uint64{51, 77}) })
}

func TestBytesToAppCallBytes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testCases := []struct {
		input    []byte
		expected string
	}{
		{[]byte("unicode"), "str:unicode"},
		{[]byte{1, 2, 3, 4}, "b64:AQIDBA=="},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			t.Parallel()
			acb := encodeBytesAsAppCallBytes(tc.input)
			require.Equal(t, tc.expected, acb)
		})
	}
}
