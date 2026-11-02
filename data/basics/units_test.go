// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
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
		Muldiv(uint64(math.MaxUint64), u64, u64)
		Muldiv(u64, uint64(math.MaxUint64), u64)
		Muldiv(uint64(math.MaxInt64), uint64(math.MaxInt64), u64)
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

func TestMuldivOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := uint64(1) << 63
	b := uint64(1) << 63
	c := uint64(1)

	_, overflowed := Muldiv(a, b, c)
	require.True(t, overflowed)
}

func TestMul2div(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	test := func(a, b, c, d uint64, result uint64) {
		t.Helper()
		r, _, o := Mul2div(a, b, c, d)
		assert.False(t, o)
		assert.Equal(t, r, result, "%d != %d", r, result)
	}
	test(1, 1, 1, 1, 1)
	test(2, 1, 1, 1, 2)
	test(1, 2, 1, 1, 2)
	test(1, 1, 2, 1, 2)
	test(1, 1, 2, 2, 1)
	test(10, 20, 5, 2, 500)
	test(100, 200, 50, 2000, 500)
	test(1, math.MaxUint64, 1, math.MaxUint64, 1)
	test(math.MaxUint64, math.MaxUint64, 1, math.MaxUint64, math.MaxUint64)
	test((math.MaxUint64-1)/2, (math.MaxUint64-1)/2, 4, math.MaxUint64-1, math.MaxUint64-1)

	// Zero handling
	test(0, 1, 1, 1, 0)
	test(1, 0, 1, 1, 0)
	test(1, 1, 0, 1, 0)
	test(0, 0, 0, 1, 0)
	test(math.MaxUint64, 0, math.MaxUint64, 1, 0)

	// Division by 1
	test(100, 200, 50, 1, 1000000)
	test(1000, 1000, 1000, 1, 1000000000)

	// Intermediate overflow but final result fits
	// (2^32 * 2^32 * 2) / 2^63 = 2^65 / 2^63 = 4
	test(1<<32, 1<<32, 2, 1<<63, 4)

	// Near-overflow: result is just under 2^64
	test(math.MaxUint64, 1, 1, 1, math.MaxUint64)
	test(1, math.MaxUint64, 1, 1, math.MaxUint64)
	test(1, 1, math.MaxUint64, 1, math.MaxUint64)

	// Large values that don't overflow
	test(1<<32, 1<<20, 1<<10, 1<<32, 1<<30)

	// Rounding behavior: ensure truncation, not rounding
	test(5, 5, 5, 7, 17) // 125/7 = 17.857... -> 17
	test(3, 3, 3, 10, 2) // 27/10 = 2.7 -> 2

	// Edge case where denominator is just large enough to prevent overflow
	test(1<<63, 10, 10, 100, 1<<63)
}

func TestMul2divOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testOverflowMaxUint64 := func(a, b, c, d uint64) {
		t.Helper()
		r, _, o := Mul2div(a, b, c, d)
		assert.True(t, o, "expected overflow for %d*%d*%d/%d", a, b, c, d)
		assert.Equal(t, uint64(math.MaxUint64), r, "overflow should saturate to MaxUint64")
	}

	// tooHi > 0 case: when a*b*c needs more than 128 bits (saturates to MaxUint64)
	testOverflowMaxUint64(math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64)
	testOverflowMaxUint64(math.MaxUint64, math.MaxUint64, math.MaxUint64, 1)
	testOverflowMaxUint64(math.MaxUint64, math.MaxUint64, math.MaxUint64/2+1, 1)
	testOverflowMaxUint64(math.MaxUint64, math.MaxUint64, 2, 1)
	testOverflowMaxUint64(math.MaxUint64, math.MaxUint64, 2, math.MaxUint64)
	testOverflowMaxUint64(1<<43, 1<<43, 1<<43, 1<<63)

	// Overflow in middle digit addition (M + J >= 2^64 with L = 0)
	// a*b = 2 * MaxUint64 gives X=1, Y=MaxUint64-1
	// With c = 2^63+2: M = 2^63+2, and Y*c produces J = 2^63+1
	// M + J = 2^64 + 3, which overflows without AddSaturate
	testOverflowMaxUint64(2, math.MaxUint64, (1<<63)+2, 4)
}

func TestFeeForUsage(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	minFee := MicroAlgos{Raw: 1000}

	// With no starting residue, FeeForUsage is just a ceiling. An exact result
	// (1000 * 1.001 = 1001 microalgos exactly) leaves the residue untouched.
	fee, residue, o := minFee.FeeForUsage(Micros(1e6+1000), 1e6, 0)
	require.False(t, o)
	require.Equal(t, MicroAlgos{Raw: 1001}, fee)
	require.EqualValues(t, 0, residue)

	// 1000 * (1e6+1001) / 1e6 = 1001.001 rounds up to 1002, and the leftover
	// residue is the complement of the 0.001 fraction (1e9 over 1e12).
	fee, residue, o = minFee.FeeForUsage(Micros(1e6+1001), 1e6, 0)
	require.False(t, o)
	require.Equal(t, MicroAlgos{Raw: 1002}, fee)
	require.EqualValues(t, feeResidueScale-1e9, residue)

	// Feeding that residue into a second charge whose fraction it covers avoids a
	// second round-up. 1000 * (1e6+1) / 1e6 = 1000.001; fraction 0.001 (1e9 over
	// 1e12) < residue 0.999, so charge floor 1000 and shrink the residue.
	fee, residue2, o := minFee.FeeForUsage(Micros(1e6+1), 1e6, residue)
	require.False(t, o)
	require.Equal(t, MicroAlgos{Raw: 1000}, fee)
	require.EqualValues(t, residue-1e9, residue2)

	// A zero base or zero usage yields a zero fee and no residue.
	fee, residue, o = MicroAlgos{Raw: 0}.FeeForUsage(Micros(1e6+1001), 1e6, 0)
	require.False(t, o)
	require.Equal(t, MicroAlgos{Raw: 0}, fee)
	require.EqualValues(t, 0, residue)

	fee, residue, o = minFee.FeeForUsage(0, 1e6, 0)
	require.False(t, o)
	require.Equal(t, MicroAlgos{Raw: 0}, fee)
	require.EqualValues(t, 0, residue)

	// A round-up that would carry the result past MaxUint64 is reported as overflow.
	fee, _, o = MicroAlgos{Raw: math.MaxUint32}.FeeForUsage(Micros(math.MaxUint32), Micros(1.00000001e12), 0)
	require.True(t, o)
	require.Equal(t, MicroAlgos{Raw: math.MaxUint64}, fee)
}

// TestFeeForUsagePrecise verifies the central guarantee: charging a sequence of
// groups while threading the residue costs exactly a single ceiling of the
// aggregate exact fee, no matter how the usage is split across groups.
func TestFeeForUsagePrecise(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	scale := big.NewInt(feeResidueScale)

	check := func(minFee uint64, groups [][2]uint64) {
		fee := MicroAlgos{Raw: minFee}
		exactNum := big.NewInt(0) // Σ minFee*usage*multiplier, over feeResidueScale
		var charged uint64
		residue := uint64(0)
		for _, g := range groups {
			usage, mult := g[0], g[1]
			f, newResidue, o := fee.FeeForUsage(Micros(usage), Micros(mult), residue)
			require.False(t, o)
			require.Less(t, newResidue, uint64(feeResidueScale)) // residue stays in range
			charged += f.Raw
			residue = newResidue

			term := new(big.Int).Mul(big.NewInt(int64(minFee)), big.NewInt(int64(usage)))
			term.Mul(term, big.NewInt(int64(mult)))
			exactNum.Add(exactNum, term)
		}
		// ceil(exactNum / scale) == the total we actually charged.
		want := new(big.Int).Add(exactNum, new(big.Int).Sub(scale, big.NewInt(1)))
		want.Div(want, scale)
		require.Equal(t, want.Uint64(), charged,
			"minFee=%d groups=%v: charged %d, want ceil of exact", minFee, groups, charged)
	}

	// A handful of hand-picked splits, including the worked example from the plan
	// (1010.5 then 2002.3 should total ceil(3012.8)=3013, not 1011+2003).
	check(1000, [][2]uint64{{1010500, 1e6}, {2002300, 1e6}})
	check(1000, [][2]uint64{{1e6 + 1, 1e6}, {1e6 + 1, 1e6}, {1e6 + 1, 1e6}})
	check(773, [][2]uint64{{333333, 1e6}, {333333, 1e6}, {333334, 1e6}})

	// Many random splits with varied multipliers; deterministic via a fixed seed.
	gen := newSplitGen(1)
	for trial := 0; trial < 500; trial++ {
		n := 1 + gen.intn(8)
		groups := make([][2]uint64, n)
		for i := range groups {
			groups[i] = [2]uint64{1 + gen.uint64n(5_000_000), 1 + gen.uint64n(2_000_000)}
		}
		check(1+gen.uint64n(10000), groups)
	}
}

// splitGen is a tiny deterministic PRNG so the property test is reproducible
// without depending on math/rand's global stream.
type splitGen struct{ state uint64 }

func newSplitGen(seed uint64) *splitGen { return &splitGen{state: seed*2862933555777941757 + 1} }

func (g *splitGen) next() uint64 {
	g.state = g.state*6364136223846793005 + 1442695040888963407
	return g.state
}
func (g *splitGen) uint64n(n uint64) uint64 { return g.next() % n }
func (g *splitGen) intn(n int) int          { return int(g.next() % uint64(n)) }
