// Copyright (C) 2019-2022 Algorand, Inc.
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

package basics

import (
	"math"
	"math/big"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestSubSaturate(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := Round(1)
	b := Round(2)
	require.Equal(t, a.SubSaturate(b), Round(0))
	require.Equal(t, a.SubSaturate(a), Round(0))
	require.Equal(t, b.SubSaturate(a), Round(1))
}

func TestSubSaturate32(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.Equal(t, uint32(0), SubSaturate32(0, 1))
	require.Equal(t, uint32(0), SubSaturate32(1, 2))
	require.Equal(t, uint32(0), SubSaturate32(1, 1))
	require.Equal(t, uint32(0), SubSaturate32(1, math.MaxUint32))
	require.Equal(t, uint32(1), SubSaturate32(2, 1))
	require.Equal(t, uint32(math.MaxUint32-1), SubSaturate32(math.MaxUint32, 1))
}

func TestAddSaturate32(t *testing.T) {
	partitiontest.PartitionTest(t)

	require.Equal(t, uint32(1), AddSaturate32(0, 1))
	require.Equal(t, uint32(math.MaxUint32-1), AddSaturate32(math.MaxUint32-2, 1))
	require.Equal(t, uint32(math.MaxUint32), AddSaturate32(math.MaxUint32, 0))
	require.Equal(t, uint32(math.MaxUint32), AddSaturate32(math.MaxUint32-1, 1))
	require.Equal(t, uint32(math.MaxUint32), AddSaturate32(math.MaxUint32, 2))
}

func TestRoundUpToMultipleOf(t *testing.T) {
	partitiontest.PartitionTest(t)

	r := Round(24)
	for n := Round(1); n < Round(100); n++ {
		nextMul := r.RoundUpToMultipleOf(n)
		require.True(t, r <= nextMul)
		require.Equal(t, nextMul%n, Round(0))
		if n < r {
			prevMul := nextMul - n
			require.True(t, prevMul < r)
		}
	}
}

func OldMuldiv(a uint64, b uint64, c uint64) (res uint64, overflow bool) {
	var aa big.Int
	aa.SetUint64(a)

	var bb big.Int
	bb.SetUint64(b)

	var cc big.Int
	cc.SetUint64(c)

	aa.Mul(&aa, &bb)
	aa.Div(&aa, &cc)

	return aa.Uint64(), !aa.IsUint64()
}

func BenchmarkOldMuldiv(b *testing.B) {
	for i := 0; i < b.N; i++ {
		u64 := uint64(i + 1)
		OldMuldiv(u64, u64, u64)
		OldMuldiv(math.MaxUint64, u64, u64)
		OldMuldiv(u64, math.MaxUint64, u64)
		OldMuldiv(math.MaxInt64, math.MaxInt64, u64)
	}
}

func BenchmarkNewMuldiv(b *testing.B) {
	for i := 0; i < b.N; i++ {
		u64 := uint64(i + 1)
		Muldiv(u64, u64, u64)
		Muldiv(math.MaxUint64, u64, u64)
		Muldiv(u64, math.MaxUint64, u64)
		Muldiv(math.MaxInt64, math.MaxInt64, u64)
	}
}

func TestNewMuldiv(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	test := func(a, b, c uint64) {
		r1, o1 := OldMuldiv(a, b, c)
		r2, o2 := Muldiv(a, b, c)
		require.Equal(t, o1, o2)
		// implementations differ in r1,r2 if overflow. old implemention is
		// returning an unspecified value
		if !o1 {
			require.Equal(t, r1, r2)
		}
	}
	test(1, 2, 3)
	test(1000000000, 2000000000, 1)
	test(math.MaxUint64, 3, 4)
	test(math.MaxUint64, 4, 3)
	test(3, math.MaxUint64, 4)
	test(4, math.MaxUint64, 3)
	test(math.MaxUint64, math.MaxUint64, math.MaxUint64)
	test(math.MaxUint64, math.MaxUint64, 5)
}
