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

package txnsync

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestTrimBitmaskNi(t *testing.T) {
	partitiontest.PartitionTest(t)

	var b bitmask
	b.trimBitmask(0)
	require.Nil(t, b)
}

func TestIterateExceptions(t *testing.T) {
	partitiontest.PartitionTest(t)

	var b bitmask
	require.Nil(t, b.iterate(0, 0, nil))

}

func TestBitmaskType0(t *testing.T) {
	partitiontest.PartitionTest(t)

	setBits := make([]int, 0, 5)
	setBits = append(setBits, 0)
	setBits = append(setBits, 2)
	setBits = append(setBits, 3)
	setBits = append(setBits, 10)

	trimIterateHelper(t, setBits)
}

func TestBitmaskType1(t *testing.T) {
	partitiontest.PartitionTest(t)

	setBits := make([]int, 0, 80)
	entries := 80
	for i := 0; i < entries; i++ {
		if i%3 != 0 || i > entries-10 {
			setBits = append(setBits, i)
		}
	}
	trimIterateHelper(t, setBits)
}

func TestBitmaskType2(t *testing.T) {
	partitiontest.PartitionTest(t)

	setBits := make([]int, 0, 5)
	setBits = append(setBits, 0)
	setBits = append(setBits, 2)
	setBits = append(setBits, 69)

	trimIterateHelper(t, setBits)
}

func TestBitmaskType3(t *testing.T) {
	partitiontest.PartitionTest(t)

	entries := 80
	setBits := make([]int, 0, entries)
	for i := 0; i < entries; i++ {
		if i != 0 && i != 2 && i != 3 && i != 71 {
			setBits = append(setBits, i)
		}
	}
	trimIterateHelper(t, setBits)
}

// Test for corrupted bitmask
func TestBitmaskType3Corrupted(t *testing.T) {

	// 10 entries, bitmask has 3 compliment bits (case 3): 10-3=7 set bits,
	// last valid index should be 6
	maxIndex := 7
	entries := 10

	var b bitmask
	b = make([]byte, 7)
	b[0] = 3
	b[1] = 0
	b[3] = 0
	b[5] = 0

	b[2] = 1 // index 1 is not set
	b[4] = 1 // index 2 is not set
	b[6] = 8 // index 2+8=10 is not set. 10 is outside the entries, and does not count
	// set bits: 0, 3, 4, 5, 6, 7, 8, 9

	require.Equal(t, errIndexNotFound, b.iterate(entries, maxIndex, func(entry, index int) error {
		return nil
	}))
}

func TestBitmaskTypeX(t *testing.T) {
	partitiontest.PartitionTest(t)

	b := make(bitmask, bytesNeededBitmask(80))
	b[0] = 4
	require.Equal(t, b.iterate(0, 0, nil), errInvalidBitmaskType)
}

func trimIterateHelper(t *testing.T, setBits []int) {
	entries := 80
	b := make(bitmask, bytesNeededBitmask(entries))

	for _, x := range setBits {
		b.setBit(x)
	}
	iterated := make([]bool, entries)
	iterfunc := func(i int, index int) error {
		iterated[i] = true
		return nil
	}
	var errTestError = errors.New("some error")
	errorAfter := 0
	errfunc := func(i int, index int) error {
		if index > errorAfter {
			return errTestError
		}
		return nil
	}

	require.Equal(t, errTestError, b.iterate(entries, len(setBits), errfunc))
	require.Equal(t, errDataMissing, b.iterate(entries, len(setBits)-1, iterfunc)) // less than set bits
	require.NoError(t, b.iterate(entries, len(setBits), iterfunc))

	s := 0
	for i := 0; i < entries; i++ {
		if s < len(setBits) && i == setBits[s] {
			require.True(t, iterated[i], i)
			s++
		} else {
			require.False(t, iterated[i], i)
		}
	}
	b.trimBitmask(entries)
	if int(b[0]) < 2 {
		// make sure TrimRight is behaving as expected
		require.True(t, int(b[len(b)-1]) > 0)
	}
	iterated = make([]bool, entries)

	require.Equal(t, errTestError, b.iterate(entries, len(setBits), errfunc))
	require.Equal(t, errDataMissing, b.iterate(entries, len(setBits)-1, iterfunc))

	// For types 0 and 2, let the entries be smaller than what the bitmap will provide
	// This is the edge case, and will not be a problem for the compliment set bitmasks
	if int((b)[0]) == 0 || int((b)[0]) == 2 {
		require.Equal(t, errIndexNotFound, b.iterate(setBits[len(setBits)-1], len(setBits), iterfunc))
		require.Nil(t, b.iterate(setBits[len(setBits)-1]+1, len(setBits), iterfunc))
	}

	// For types 1 and 3, let the entries be smaller than what the bitmap will provide
	// This requires a much smaller entries limit, since it is only checked in the first stage
	if int((b)[0]) == 1 || int((b)[0]) == 3 {
		require.Equal(t, errIndexNotFound, b.iterate(70, len(setBits), iterfunc))
	}

	// For types 1 and 3, test the error handling in the second stage.
	errorAfter = len(setBits) - 1 - 8
	require.Equal(t, errTestError, b.iterate(entries, len(setBits), errfunc))
	require.Equal(t, errDataMissing, b.iterate(entries, len(setBits)-1-8, iterfunc))

	require.NoError(t, b.iterate(entries, len(setBits), func(i int, index int) error {
		iterated[i] = true
		return nil
	}))

	s = 0
	for i := 0; i < entries; i++ {
		if s < len(setBits) && i == setBits[s] {
			require.True(t, iterated[i], i)
			s++
		} else {
			require.False(t, iterated[i], i)
		}
	}
}

func TestFuzzBitmask(t *testing.T) {
	randSeed := uint64(0)
	rand := func() byte {
		bytes := [16]byte{}
		l := binary.PutUvarint(bytes[:], randSeed)
		h := crypto.Hash(bytes[:l])
		randSeed = 0
		for i := 0; i < 8; i++ {
			randSeed += uint64(h[i]) << (i * 8)
		}
		return byte(h[0])
	}
	for iterationsCount := 0; iterationsCount < 1000; iterationsCount++ {
		bitmaskType := rand() % 4
		blen := int(rand()%33) + 1
		var b bitmask
		b = make([]byte, blen)
		b[0] = byte(bitmaskType)
		for i := 1; i < blen; i++ {
			b[i] = rand()
		}
		entries := int(rand())
		maxIndex := int(rand())
		lastEntryIndex := -1
		b.iterate(entries, maxIndex, func(i, j int) error {
			require.Greater(t, i, lastEntryIndex)
			lastEntryIndex = i
			require.Less(t, i, entries)
			require.Less(t, j, maxIndex)
			return nil
		})
		// reset to mode 0
		b[0] = 0
		entries = (blen - 1) * 8
		err1 := b.iterate(entries, maxIndex, func(i, j int) error {
			return nil
		})
		b.trimBitmask(entries)
		err2 := b.iterate(entries, maxIndex, func(i, j int) error {
			return nil
		})
		require.Equal(t, err1, err2)
	}
}
