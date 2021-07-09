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

func TestTrimBitmaskNi(t *testing.T) {
	var b bitmask
	b.trimBitmask(0)
	require.Nil(t, b)
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

	entryExist := make([]bool, entries)
	b.iterate(entries, entries, func(setIndex int, counter int) error {
		entryExist[setIndex] = true
		return nil
	})

	s := 0
	for i := 0; i < entries; i++ {
		exists := entryExist[i]
		if s < len(setBits) && i == setBits[s] {
			require.True(t, exists)
			require.True(t, iterated[i], i)
			s++
		} else {
			require.False(t, exists)
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

	// For types 2, let the sum exceed entries
	if int((b)[0]) == 2 {
		require.Equal(t, errIndexNotFound, b.iterate(setBits[len(setBits)-1], len(setBits)-1, iterfunc))
	}

	// For types 1 and 3, test the error handling in the first stage.
	errorAfter = len(setBits) - 1 - 8
	require.Equal(t, errTestError, b.iterate(entries, len(setBits), errfunc))
	require.Equal(t, errDataMissing, b.iterate(entries, len(setBits)-1-8, iterfunc))

	require.NoError(t, b.iterate(entries, len(setBits), func(i int, index int) error {
		iterated[i] = true
		return nil
	}))

	entryExist = make([]bool, entries)
	b.iterate(entries, entries, func(setIndex int, counter int) error {
		entryExist[setIndex] = true
		return nil
	})

	s = 0
	for i := 0; i < entries; i++ {
		exists := entryExist[i]
		if s < len(setBits) && i == setBits[s] {
			require.True(t, exists)
			require.True(t, iterated[i], i)
			s++
		} else {
			require.False(t, exists)
			require.False(t, iterated[i], i)
		}
	}
}
