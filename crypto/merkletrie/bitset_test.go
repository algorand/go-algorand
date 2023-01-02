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

package merkletrie

import (
	"math/bits"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestBitSet(t *testing.T) {
	partitiontest.PartitionTest(t)

	var a, b bitset

	// set the bits in a different order, and see if we're ending with the same set.
	for i := 0; i <= 255; i += 2 {
		a.SetBit(byte(i))
		b.SetBit(byte(256 - i))
	}
	require.Equal(t, a, b)

	for i := 0; i <= 255; i += 2 {
		require.NotZero(t, a.Bit(byte(i)))
	}

	for i := 1; i <= 255; i += 2 {
		require.Zero(t, a.Bit(byte(i)))
	}

	// clear the bits at different order, and testing that the bits were cleared correctly.
	for i := 0; i <= 255; i += 32 {
		a.ClearBit(byte(i))
		b.ClearBit(byte(256 - i))
	}
	require.Equal(t, a, b)

	for i := 0; i <= 255; i += 32 {
		require.Zero(t, a.Bit(byte(i)))
	}

	// clear all bits ( some would get cleared more than once )
	for i := 0; i <= 255; i += 2 {
		a.ClearBit(byte(i))
	}

	// check that the bitset is zero.
	require.True(t, a.IsZero())
}

// TestBitSetOneBit test that only one bit is being set when we call SetBit
func TestBitSetOneBit(t *testing.T) {
	partitiontest.PartitionTest(t)

	for i := 0; i < 256; i++ {
		var a bitset
		a.SetBit(byte(i))
		require.Equal(t, 1, bits.OnesCount64(a.d[0])+bits.OnesCount64(a.d[1])+bits.OnesCount64(a.d[2])+bits.OnesCount64(a.d[3]))
	}
}
