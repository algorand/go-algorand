// Copyright (C) 2019-2025 Algorand, Inc.
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
	"github.com/stretchr/testify/assert"
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

func TestParseBoxRef(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	br := parseBoxRef("str:hello")
	require.EqualValues(t, 0, br.appID)
	require.Equal(t, "str", br.name.Encoding)
	require.Equal(t, "hello", br.name.Value)

	require.Panics(t, func() { parseBoxRef("1,hello") })
	require.Panics(t, func() { parseBoxRef("hello") })

	br = parseBoxRef("2,str:hello")
	require.EqualValues(t, 2, br.appID)
	require.Equal(t, "str", br.name.Encoding)
	require.Equal(t, "hello", br.name.Value)
}

func TestParseHoldingRef(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	hr := parseHoldingRef("12")
	require.EqualValues(t, 12, hr.assetID)
	require.Zero(t, hr.address)

	hr = parseHoldingRef("1232+JUNK")
	require.EqualValues(t, 1232, hr.assetID)
	require.Equal(t, "JUNK", hr.address)
}

func TestParseLocalRef(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	lr := parseLocalRef("12")
	assert.EqualValues(t, 12, lr.appID)
	assert.Zero(t, lr.address)

	lr = parseLocalRef("1232+JUNK")
	assert.EqualValues(t, 1232, lr.appID)
	assert.Equal(t, "JUNK", lr.address)

	lr = parseLocalRef("0+JUNK")
	assert.Zero(t, lr.appID)
	assert.Equal(t, "JUNK", lr.address)

	lr = parseLocalRef("STUFF")
	assert.Zero(t, lr.appID)
	assert.Equal(t, "STUFF", lr.address)
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
