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
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// test entryExists exceptions
func TestEntryExistsExceptions(t *testing.T) {

	// case of empty bitmask
	var b bitmask
	require.False(t, b.entryExists(0, 0))

	// case of non-empty bitmask
	entries := 5
	bm := make(bitmask, 3)

	// byteIndex == len(bitmask)
	require.False(t, bm.entryExists(entries, entries))

	// expandBitmask fails
	bm[0] = 2
	bm[2] = 8
	require.False(t, bm.entryExists(entries, entries))
}

func TestTrimBitmaskNilError(t *testing.T) {
	var b bitmask
	require.NoError(t, b.trimBitmask(0))
	require.Nil(t, b)
	bb := make(bitmask, 2)
	require.Equal(t, bb.trimBitmask(9), errIndexOutOfBounds)
	require.Equal(t, bb.trimBitmask(-1), errIndexOutOfBounds)
}

func TestExpandBitmaskExceptions(t *testing.T) {
	var b bitmask
	require.Nil(t, b.expandBitmask(0))

	bm := make(bitmask, 3)
	bm[0] = 2
	require.Equal(t, bm.expandBitmask(0), errIndexOutOfBounds)

	bm[0] = 3
	require.Equal(t, bm.expandBitmask(0), errIndexOutOfBounds)
}

func TestIterateExceptions(t *testing.T) {
	var b bitmask
	require.Nil(t, b.iterate(0, 0, nil))

}

func TestBitmaskType0(t *testing.T) {
	setBits := make([]int, 0, 5)
	setBits = append(setBits, 0)
	setBits = append(setBits, 2)
	setBits = append(setBits, 3)
	setBits = append(setBits, 10)

	trimIterateHelper(t, setBits)

	// expandBitmask should not fail
	b := make(bitmask, 12)
	require.NoError(t, b.expandBitmask(3))
}

func TestBitmaskType1(t *testing.T) {
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
	setBits := make([]int, 0, 5)
	setBits = append(setBits, 0)
	setBits = append(setBits, 2)
	setBits = append(setBits, 69)

	trimIterateHelper(t, setBits)
}

func TestBitmaskType3(t *testing.T) {
	setBits := make([]int, 0, 5)
	entries := 80
	for i := 0; i < entries; i++ {
		if i != 0 && i != 2 && i != 71 {
			setBits = append(setBits, i)
		}
	}

	trimIterateHelper(t, setBits)
}

func TestBitmaksTypeX(t *testing.T) {
	b := make(bitmask, bytesNeededBitmask(80))
	b[0] = 4
	require.Equal(t, b.iterate(0, 0, nil), errInvalidBitmaskType)
}

func trimIterateHelper(t *testing.T, setBits []int) {
	b := make(bitmask, bytesNeededBitmask(80))
	entries := 80

	setBits = append(setBits, -1)   // end of set bits
	setBits = append(setBits, 1000) // over the bound value

	for _, x := range setBits {
		if x < 0 || bytesNeededBitmask(x) > len(b) {
			require.Equal(t, b.setBit(x), errIndexOutOfBounds)
			continue
		}
		require.NoError(t, b.setBit(x))
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
	require.Equal(t, errDataMissing, b.iterate(entries, len(setBits)-3, iterfunc)) // less than set bits
	require.NoError(t, b.iterate(entries, len(setBits)-2, iterfunc))

	s := 0
	for i := 0; i < entries; i++ {
		exists := b.entryExists(i, entries)
		if i == setBits[s] {
			require.True(t, exists)
			require.True(t, iterated[i], i)
			s++
		} else {
			require.False(t, exists)
			require.False(t, iterated[i], i)
		}
	}
	require.NoError(t, b.trimBitmask(entries))
	if int(b[0]) < 2 {
		// make sure TrimRight is behaving as expected
		require.True(t, int(b[len(b)-1]) > 0)
	}
	iterated = make([]bool, entries)

	require.Equal(t, errTestError, b.iterate(entries, len(setBits), errfunc))
	require.Equal(t, errDataMissing, b.iterate(entries, len(setBits)-3, iterfunc))

	// For types 2, let the sum exceed entries
	if int((b)[0]) == 2 {
		require.Equal(t, errIndexNotFound, b.iterate(setBits[len(setBits)-3], len(setBits)-3, iterfunc))
	}

	// For types 1 and 3, test the error handling in the first stage.
	errorAfter = len(setBits) - 3 - 8
	require.Equal(t, errTestError, b.iterate(entries, len(setBits), errfunc))
	require.Equal(t, errDataMissing, b.iterate(entries, len(setBits)-3-8, iterfunc))

	require.NoError(t, b.iterate(entries, len(setBits)-2, func(i int, index int) error {
		iterated[i] = true
		return nil
	}))
	s = 0
	for i := 0; i < entries; i++ {
		exists := b.entryExists(i, entries)
		if i == setBits[s] {
			require.True(t, exists)
			require.True(t, iterated[i], i)
			s++
		} else {
			require.False(t, exists)
			require.False(t, iterated[i], i)
		}
	}
}
