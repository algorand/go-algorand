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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitmaskType0And2(t *testing.T) {
	entries := 80
	b := make(bitmask, 12)
	b.setBit(0)
	b.setBit(2)
	b.setBit(69)
	iterated := make([]bool, entries)
	b.iterate(entries, 3, func(i int, index int) error {
		iterated[i] = true
		return nil
	})
	for i := 0; i < entries; i++ {
		exists := b.entryExists(i, entries)
		if i == 0 || i == 2 || i == 69 {
			require.True(t, exists)
			require.True(t, iterated[i], i)
		} else {
			require.False(t, exists)
			require.False(t, iterated[i], i)
		}
	}
	b.trimBitmask(entries)
	iterated = make([]bool, entries)
	b.iterate(entries, 3, func(i int, index int) error {
		iterated[i] = true
		return nil
	})
	for i := 0; i < entries; i++ {
		exists := b.entryExists(i, entries)
		if i == 0 || i == 2 || i == 69 {
			require.True(t, exists)
			require.True(t, iterated[i], i)
		} else {
			require.False(t, exists)
			require.False(t, iterated[i], i)
		}
	}
}

func TestBitmaskType1(t *testing.T) {
	entries := 80
	b := make(bitmask, 12)
	for i := 0; i < entries; i++ {
		if i%3 != 0 {
			b.setBit(i)
		}
	}
	b.trimBitmask(entries)
	iterated := make([]bool, entries)
	b.iterate(entries, 53, func(i int, index int) error {
		iterated[i] = true
		return nil
	})
	for i := 0; i < entries; i++ {
		exists := b.entryExists(i, entries)
		if i%3 == 0 {
			require.False(t, exists)
			require.False(t, iterated[i], i)
		} else {
			require.True(t, exists)
			require.True(t, iterated[i], i)
		}
	}
}

func TestBitmaskType3(t *testing.T) {
	entries := 80
	b := make(bitmask, 12)
	for i := 0; i < entries; i++ {
		if i != 0 && i != 2 && i != 69 {
			b.setBit(i)
		}
	}
	b.trimBitmask(entries)
	iterated := make([]bool, entries)
	b.iterate(entries, 77, func(i int, index int) error {
		iterated[i] = true
		return nil
	})
	for i := 0; i < entries; i++ {
		exists := b.entryExists(i, entries)
		if i == 0 || i == 2 || i == 69 {
			require.False(t, exists)
			require.False(t, iterated[i], i)
		} else {
			require.True(t, exists)
			require.True(t, iterated[i], i)
		}
	}
}
