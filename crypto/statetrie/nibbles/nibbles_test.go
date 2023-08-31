// Copyright (C) 2019-2023 Algorand, Inc.
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

package nibbles

import (
	"bytes"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNibbles(t *testing.T) { // nolint:paralleltest // Serial tests for trie for the moment
	partitiontest.PartitionTest(t)
	// t.Parallel()
	sampleNibbles := []Nibbles{
		{0x0, 0x1, 0x2, 0x3, 0x4},
		{0x4, 0x1, 0x2, 0x3, 0x4},
		{0x0, 0x0, 0x2, 0x3, 0x5},
		{0x0, 0x1, 0x2, 0x3, 0x4, 0x5},
		{},
		{0x1},
	}

	sampleNibblesPacked := [][]byte{
		{0x01, 0x23, 0x40},
		{0x41, 0x23, 0x40},
		{0x00, 0x23, 0x50},
		{0x01, 0x23, 0x45},
		{},
		{0x10},
	}

	sampleNibblesShifted1 := []Nibbles{
		{0x1, 0x2, 0x3, 0x4},
		{0x1, 0x2, 0x3, 0x4},
		{0x0, 0x2, 0x3, 0x5},
		{0x1, 0x2, 0x3, 0x4, 0x5},
		{},
		{},
	}

	sampleNibblesShifted2 := []Nibbles{
		{0x2, 0x3, 0x4},
		{0x2, 0x3, 0x4},
		{0x2, 0x3, 0x5},
		{0x2, 0x3, 0x4, 0x5},
		{},
		{},
	}

	for i, n := range sampleNibbles {
		b, oddLength := Pack(n)
		if oddLength {
			// require that oddLength packs returns a byte slice with the last nibble set to 0x0
			require.Equal(t, b[len(b)-1]&0x0f == 0x00, true)
		}

		require.Equal(t, oddLength == (len(n)%2 == 1), true)
		require.Equal(t, bytes.Equal(b, sampleNibblesPacked[i]), true)

		unp := Unpack(b, oddLength)
		require.Equal(t, bytes.Equal(unp, n), true)

	}
	for i, n := range sampleNibbles {
		require.Equal(t, bytes.Equal(ShiftLeft(n, -2), sampleNibbles[i]), true)
		require.Equal(t, bytes.Equal(ShiftLeft(n, -1), sampleNibbles[i]), true)
		require.Equal(t, bytes.Equal(ShiftLeft(n, 0), sampleNibbles[i]), true)
		require.Equal(t, bytes.Equal(ShiftLeft(n, 1), sampleNibblesShifted1[i]), true)
		require.Equal(t, bytes.Equal(ShiftLeft(n, 2), sampleNibblesShifted2[i]), true)
	}

	sampleSharedNibbles := [][]Nibbles{
		{{0x0, 0x1, 0x2, 0x9, 0x2}, {0x0, 0x1, 0x2}},
		{{0x4, 0x1}, {0x4, 0x1}},
		{{0x9, 0x2, 0x3}, {}},
		{{0x0}, {0x0}},
		{{}, {}},
	}
	for i, n := range sampleSharedNibbles {
		shared := SharedPrefix(n[0], sampleNibbles[i])
		require.Equal(t, bytes.Equal(shared, n[1]), true)
		shared = SharedPrefix(sampleNibbles[i], n[0])
		require.Equal(t, bytes.Equal(shared, n[1]), true)
	}

	sampleSerialization := []Nibbles{
		{0x0, 0x1, 0x2, 0x9, 0x2},
		{0x4, 0x1},
		{0x4, 0x1, 0x4, 0xf},
		{0x4, 0x1, 0x4, 0xf, 0x0},
		{0x9, 0x2, 0x3},
		{},
		{0x05},
		{},
	}

	for _, n := range sampleSerialization {
		nbytes := Serialize(n)
		n2, err := DeserializeNibbles(nbytes)
		require.NoError(t, err)
		require.Equal(t, bytes.Equal(n, n2), true)
	}

	makeNibblesTestExpected := Nibbles{0x0, 0x1, 0x2, 0x9, 0x2}
	makeNibblesTestData := []byte{0x01, 0x29, 0x20}
	mntr := MakeNibbles(makeNibblesTestData, true)
	require.Equal(t, bytes.Equal(mntr, makeNibblesTestExpected), true)
	makeNibblesTestExpectedFW := Nibbles{0x0, 0x1, 0x2, 0x9, 0x2, 0x0}
	mntr2 := MakeNibbles(makeNibblesTestData, false)
	require.Equal(t, bytes.Equal(mntr2, makeNibblesTestExpectedFW), true)

	sampleEqualFalse := [][]Nibbles{
		{{0x0, 0x1, 0x2, 0x9, 0x2}, {0x0, 0x1, 0x2, 0x9}},
		{{0x0, 0x1, 0x2, 0x9}, {0x0, 0x1, 0x2, 0x9, 0x2}},
		{{0x0, 0x1, 0x2, 0x9, 0x2}, {}},
		{{}, {0x0, 0x1, 0x2, 0x9, 0x2}},
		{{0x0}, {}},
		{{}, {0x0}},
		{{}, {0x1}},
	}
	for _, n := range sampleEqualFalse {
		ds := Serialize(n[0])
		us, e := DeserializeNibbles(ds)
		require.NoError(t, e)
		require.Equal(t, Equal(n[0], us), true)
		require.Equal(t, Equal(n[0], n[0]), true)
		require.Equal(t, Equal(us, n[0]), true)
		require.Equal(t, Equal(n[0], n[1]), false)
		require.Equal(t, Equal(us, n[1]), false)
		require.Equal(t, Equal(n[1], n[0]), false)
		require.Equal(t, Equal(n[1], us), false)
	}

	_, e := DeserializeNibbles([]byte{})
	require.Error(t, e)
	_, e = DeserializeNibbles([]byte{0x02})
	require.Error(t, e)

}
