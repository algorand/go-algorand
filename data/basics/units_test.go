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

package basics

import (
	"math"
	"math/big"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestODiff(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cases := []struct {
		a, b uint64
		diff int64
		o    bool
	}{
		{10, 8, 2, false},
		{10, 0, 10, false},
		{10, 80, -70, false},
		{0, 20, -20, false},

		{math.MaxInt64 + 1, 0, 0, true},
		{math.MaxInt64, 0, math.MaxInt64, false},

		{uint64(math.MaxInt64) + 2, 1, 0, true},
		{uint64(math.MaxInt64) + 2, 2, math.MaxInt64, false},

		// Since minint has higher absolute value than maxint, no overflow here
		{1, uint64(math.MaxInt64) + 2, math.MinInt64, false},
		{2, uint64(math.MaxInt64) + 2, math.MinInt64 + 1, false},

		{math.MaxInt64 + 200, math.MaxInt64, 200, false},
	}

	for i, c := range cases {
		diff, o := ODiff(c.a, c.b)
		assert.Equal(t, c.diff, diff,
			"#%d) %v - %v was %v, not %v", i, c.a, c.b, diff, c.diff)
		assert.Equal(t, c.o, o, i)
	}
}

func TestSubSaturate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := Round(1)
	b := Round(2)
	require.Equal(t, a.SubSaturate(b), Round(0))
	require.Equal(t, a.SubSaturate(a), Round(0))
	require.Equal(t, b.SubSaturate(a), Round(1))
}

func TestSubSaturate32(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, uint32(0), SubSaturate(uint32(0), uint32(1)))
	require.Equal(t, uint32(0), SubSaturate(uint32(1), uint32(2)))
	require.Equal(t, uint32(0), SubSaturate(uint32(1), uint32(1)))
	require.Equal(t, uint32(0), SubSaturate(uint32(1), math.MaxUint32))
	require.Equal(t, uint32(1), SubSaturate(uint32(2), uint32(1)))
	require.Equal(t, uint32(math.MaxUint32-1), SubSaturate(math.MaxUint32, uint32(1)))
}

func TestAddSaturate32(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Equal(t, uint32(1), AddSaturate(uint32(0), uint32(1)))
	require.Equal(t, uint32(math.MaxUint32-1), AddSaturate(math.MaxUint32-2, uint32(1)))
	require.Equal(t, uint32(math.MaxUint32), AddSaturate(math.MaxUint32, uint32(0)))
	require.Equal(t, uint32(math.MaxUint32), AddSaturate(math.MaxUint32-1, uint32(1)))
	require.Equal(t, uint32(math.MaxUint32), AddSaturate(math.MaxUint32, uint32(2)))
}

func BenchmarkAddSaturateGenerics(b *testing.B) {
	startVar := uint64(0xdeadbeef)
	for n := uint64(0); n < uint64(b.N); n++ {
		temp := AddSaturate(n, startVar)
		startVar = temp
	}
}

// oldOAdd adds 2 values with overflow detection
func oldOAdd(a uint64, b uint64) (res uint64, overflowed bool) {
	res = a + b
	overflowed = res < a
	return
}

// addSaturateU64Old adds 2 values with saturation on overflow (OLD IMPLEMENTATION)
func addSaturateU64Old(a uint64, b uint64) uint64 {
	res, overflowed := oldOAdd(a, b)
	if overflowed {
		return math.MaxUint64
	}
	return res
}

func BenchmarkAddSaturateU64Old(b *testing.B) {
	startVar := uint64(0xdeadbeef)
	for n := uint64(0); n < uint64(b.N); n++ {
		temp := addSaturateU64Old(n, startVar)
		startVar = temp
	}
}

func BenchmarkSubSaturateGenerics(b *testing.B) {
	startVar := uint64(0xdeadbeef)
	for n := uint64(0); n < uint64(b.N); n++ {
		temp := SubSaturate(n, startVar)
		startVar = temp
	}
}

// oldOSub subtracts b from a with overflow detection
func oldOSub(a uint64, b uint64) (res uint64, overflowed bool) {
	res = a - b
	overflowed = res > a
	return
}

// subSaturateU64Old subtracts 2 values with saturation on underflow (OLD IMPLEMENTATION)
func subSaturateU64Old(a uint64, b uint64) uint64 {
	res, overflowed := oldOSub(a, b)
	if overflowed {
		return 0
	}
	return res
}

func BenchmarkSubSaturateU64Old(b *testing.B) {
	startVar := uint64(0xdeadbeef)
	for n := uint64(0); n < uint64(b.N); n++ {
		temp := subSaturateU64Old(n, startVar)
		startVar = temp
	}
}

func BenchmarkMulSaturateGenerics(b *testing.B) {
	startVar := uint64(0xdeadbeef)
	for n := uint64(1); n <= uint64(b.N); n++ {
		temp := MulSaturate(n, startVar)
		startVar = temp
	}
}

// oldOMul multiplies 2 values with overflow detection
func oldOMul(a uint64, b uint64) (res uint64, overflowed bool) {
	if b == 0 {
		return 0, false
	}
	c := a * b
	if c/b != a {
		return 0, true
	}
	return c, false
}

// mulSaturateU64Old multiplies 2 values with saturation on overflow (OLD IMPLEMENTATION)
func mulSaturateU64Old(a uint64, b uint64) uint64 {
	res, overflowed := oldOMul(a, b)
	if overflowed {
		return math.MaxUint64
	}
	return res
}

func BenchmarkMulSaturateU64Old(b *testing.B) {
	startVar := uint64(0xdeadbeef)
	for n := uint64(1); n <= uint64(b.N); n++ {
		temp := mulSaturateU64Old(n, startVar)
		startVar = temp
	}
}

func TestRoundUpToMultipleOf(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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

func TestRoundDownToMultipleOf(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	r := Round(24)
	for n := Round(1); n < Round(100); n++ {
		mul := r.RoundDownToMultipleOf(n)
		a.True(mul <= r)
		a.Equal(Round(0), mul%n)
		if r < n {
			a.Equal(Round(0), mul)
		} else if r == n {
			a.Equal(n, mul)
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
