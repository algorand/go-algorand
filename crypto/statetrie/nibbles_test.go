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

package statetrie

import (
	"bytes"
	"fmt"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNibbles(t *testing.T) {
	partitiontest.PartitionTest(t)

	fmt.Printf(t.Name())
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
		b, half := n.pack()
		if half {
			// require that half packs returns a byte slice with the last nibble set to 0x0
			require.True(t, b[len(b)-1]&0x0f == 0x00)
		}

		// checks the half flag automatically
		require.True(t, half == (len(n)%2 == 1))
		require.True(t, bytes.Equal(b, sampleNibblesPacked[i]))

		unp := unpack(b, half)
		require.True(t, bytes.Equal(unp, n))

	}
	for i, n := range sampleNibbles {
		require.True(t, bytes.Equal(shiftNibbles(n, 1), sampleNibblesShifted1[i]))
		require.True(t, bytes.Equal(shiftNibbles(n, 2), sampleNibblesShifted2[i]))
	}

	sampleSharedNibbles := [][]Nibbles{
		{{0x0, 0x1, 0x2, 0x9, 0x2}, {0x0, 0x1, 0x2}},
		{{0x4, 0x1}, {0x4, 0x1}},
		{{0x9, 0x2, 0x3}, {}},
		{{0x0}, {0x0}},
		{{}, {}},
	}
	for i, n := range sampleSharedNibbles {
		// n[1] is the expected shared nibble between n[0] and sampleNibbles[i]
		shared := sharedNibbles(n[0], sampleNibbles[i])
		require.True(t, bytes.Equal(shared, n[1]))

		// either direction should work
		shared = sharedNibbles(sampleNibbles[i], n[0])
		require.True(t, bytes.Equal(shared, n[1]))
	}

	// Test some shifts
	require.True(t, bytes.Equal(shiftNibbles(sampleNibbles[0], -2), sampleNibbles[0]))
	require.True(t, bytes.Equal(shiftNibbles(sampleNibbles[0], -1), sampleNibbles[0]))
	require.True(t, bytes.Equal(shiftNibbles(sampleNibbles[0], 0), sampleNibbles[0]))

	// n[0] is the input nibble, n[1] is the expected serialized output
	sampleSerialization := [][]Nibbles{
		{{0x0, 0x1, 0x2, 0x9, 0x2}, {0x01, 0x29, 0x20, 0x01}},
		{{0x4, 0x1}, {0x41, 0x03}},
		{{0x4, 0x1, 0x4, 0xf}, {0x41, 0x4f, 0x03}},
		{{0x4, 0x1, 0x4, 0xf, 0x0}, {0x41, 0x4f, 0x00, 0x01}},
		{{0x9, 0x2, 0x3}, {0x92, 0x30, 0x01}},
		{{}, {0x03}},
		{{0x05}, {0x50, 0x01}},
	}

	for _, n := range sampleSerialization {
		nbytes := n[0].serialize()
		// check the expected
		require.True(t, bytes.Equal(nbytes, n[1]))

		// check that it deserializes to the same thing
		n2, err := deserializeNibbles(nbytes)
		require.NoError(t, err)
		require.True(t, bytes.Equal(n[0], n2))
	}

	// Test some errors
	_, err := deserializeNibbles([]byte{})
	require.Error(t, err)
	_, err = deserializeNibbles([]byte{0x02})
	require.Error(t, err)
	_, err = deserializeNibbles([]byte{0x00, 0x02})
	require.Error(t, err)
	_, err = deserializeNibbles([]byte{0x01, 0x01})
	require.Error(t, err)

	// Test MakeNibbles
	makeNibblesTestData := []byte{0x01, 0x29, 0x20}
	// Half width test
	makeNibblesTestExpected := Nibbles{0x0, 0x1, 0x2, 0x9, 0x2}
	mntr := MakeNibbles(makeNibblesTestData, true)
	require.True(t, bytes.Equal(mntr, makeNibblesTestExpected))

	// Full width test
	makeNibblesTestExpectedFW := Nibbles{0x0, 0x1, 0x2, 0x9, 0x2, 0x0}
	mntr2 := MakeNibbles(makeNibblesTestData, false)
	require.True(t, bytes.Equal(mntr2, makeNibblesTestExpectedFW))

}
