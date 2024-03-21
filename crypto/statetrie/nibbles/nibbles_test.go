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

package nibbles

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestNibblesRandom(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	seed := time.Now().UnixNano()
	localRand := rand.New(rand.NewSource(seed))
	defer func() {
		if t.Failed() {
			t.Logf("The seed was %d", seed)
		}
	}()

	for i := 0; i < 1_000; i++ {
		length := localRand.Intn(8192) + 1
		data := make([]byte, length)
		localRand.Read(data)
		half := localRand.Intn(2) == 0 // half of the time, we have an odd number of nibbles
		if half && localRand.Intn(2) == 0 {
			data[len(data)-1] &= 0xf0 // sometimes clear the last nibble, sometimes do not
		}
		nibbles := makeNibbles(data, half)

		data2 := Serialize(nibbles)
		nibbles2, err := Deserialize(data2)
		require.NoError(t, err)
		require.Equal(t, nibbles, nibbles2)

		if half {
			data[len(data)-1] &= 0xf0 // clear last nibble
		}
		packed, odd := Pack(nibbles)
		require.Equal(t, odd, half)
		require.Equal(t, packed, data)
		unpacked := makeNibbles(packed, odd)
		require.Equal(t, nibbles, unpacked)

		packed, odd = Pack(nibbles2)
		require.Equal(t, odd, half)
		require.Equal(t, packed, data)
		unpacked = makeNibbles(packed, odd)
		require.Equal(t, nibbles2, unpacked)
	}
}

func TestNibblesDeserialize(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	enc := []byte{0x01}
	_, err := Deserialize(enc)
	require.Error(t, err, "should return invalid encoding error")
}

func TestNibbles(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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

		unp := makeNibbles(b, oddLength)
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
		n2, err := Deserialize(nbytes)
		require.NoError(t, err)
		require.True(t, bytes.Equal(n, n2))
		require.Equal(t, len(nbytes), len(n)/2+len(n)%2+1, fmt.Sprintf("nbytes: %v, n: %v", nbytes, n))
		if len(n)%2 == 0 {
			require.Equal(t, nbytes[len(nbytes)-1], uint8(evenIndicator))
		} else {
			require.Equal(t, nbytes[len(nbytes)-1], uint8(oddIndicator))
			require.Equal(t, nbytes[len(nbytes)-2]&0x0F, uint8(0))
		}
	}

	makeNibblesTestExpected := Nibbles{0x0, 0x1, 0x2, 0x9, 0x2}
	makeNibblesTestData := []byte{0x01, 0x29, 0x20}
	mntr := makeNibbles(makeNibblesTestData, true)
	require.Equal(t, bytes.Equal(mntr, makeNibblesTestExpected), true)
	makeNibblesTestExpectedFW := Nibbles{0x0, 0x1, 0x2, 0x9, 0x2, 0x0}
	mntr2 := makeNibbles(makeNibblesTestData, false)
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
		us, e := Deserialize(ds)
		require.NoError(t, e)
		require.Equal(t, Equal(n[0], us), true)
		require.Equal(t, Equal(n[0], n[0]), true)
		require.Equal(t, Equal(us, n[0]), true)
		require.Equal(t, Equal(n[0], n[1]), false)
		require.Equal(t, Equal(us, n[1]), false)
		require.Equal(t, Equal(n[1], n[0]), false)
		require.Equal(t, Equal(n[1], us), false)
	}

	_, e := Deserialize([]byte{})
	require.Error(t, e)
	_, e = Deserialize([]byte{0x02})
	require.Error(t, e)
}
