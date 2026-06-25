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
	"math/bits"

	"golang.org/x/exp/constraints"
)

// OverflowTracker is used to track when an operation causes an overflow
type OverflowTracker struct {
	Overflowed bool
}

// OAdd adds 2 values with overflow detection
func OAdd[T constraints.Unsigned](a, b T) (res T, overflowed bool) {
	res = a + b
	overflowed = res < a
	return
}

// OSub subtracts b from a with overflow detection
func OSub[T constraints.Unsigned](a, b T) (res T, overflowed bool) {
	res = a - b
	overflowed = res > a
	return
}

// ODiff should be used when you really do want the signed difference between
// uint64s, but still care about detecting overflow.  I don't _think_ it can be
// generic to different bit widths.
func ODiff(a, b uint64) (res int64, overflowed bool) {
	if a >= b {
		if a-b > math.MaxInt64 {
			return 0, true
		}
		return int64(a - b), false
	}
	if b-a > uint64(math.MaxInt64)+1 {
		return 0, true
	}
	return -int64(b - a), false
}

// OMul multiplies 2 values with overflow detection
func OMul[T constraints.Unsigned](a, b T) (res T, overflowed bool) {
	if b == 0 {
		return 0, false
	}

	c := a * b
	if c/b != a {
		return 0, true
	}
	return c, false
}

// MulSaturate multiplies 2 values with saturation on overflow
func MulSaturate[T constraints.Unsigned](a, b T) T {
	res, overflowed := OMul(a, b)
	if overflowed {
		var defaultT T
		return ^defaultT
	}
	return res
}

// AddSaturate adds 2 values with saturation on overflow
func AddSaturate[T constraints.Unsigned](a, b T) T {
	res, overflowed := OAdd(a, b)
	if overflowed {
		var defaultT T
		return ^defaultT
	}
	return res
}

// SubSaturate subtracts 2 values with saturation on underflow
func SubSaturate[T constraints.Unsigned](a, b T) T {
	res, overflowed := OSub(a, b)
	if overflowed {
		return 0
	}
	return res
}

// Add adds 2 values with overflow detection
func (t *OverflowTracker) Add(a, b uint64) uint64 {
	res, overflowed := OAdd(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// Sub subtracts b from a with overflow detection
func (t *OverflowTracker) Sub(a, b uint64) uint64 {
	res, overflowed := OSub(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// Mul multiplies b by a with overflow detection
func (t *OverflowTracker) Mul(a, b uint64) uint64 {
	res, overflowed := OMul(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// OAddA adds 2 MicroAlgos values with overflow tracking
func OAddA(a, b MicroAlgos) (res MicroAlgos, overflowed bool) {
	res.Raw, overflowed = OAdd(a.Raw, b.Raw)
	return
}

// OSubA subtracts b from a with overflow tracking
func OSubA(a, b MicroAlgos) (res MicroAlgos, overflowed bool) {
	res.Raw, overflowed = OSub(a.Raw, b.Raw)
	return
}

// MulAIntSaturate uses MulSaturate to multiply b (int) with a (MicroAlgos)
func MulAIntSaturate(a MicroAlgos, b int) MicroAlgos {
	return MicroAlgos{Raw: MulSaturate(a.Raw, uint64(b))}
}

// AddA adds 2 MicroAlgos values with overflow tracking
func (t *OverflowTracker) AddA(a, b MicroAlgos) MicroAlgos {
	return MicroAlgos{Raw: t.Add(a.Raw, b.Raw)}
}

// SubA subtracts b from a with overflow tracking
func (t *OverflowTracker) SubA(a, b MicroAlgos) MicroAlgos {
	return MicroAlgos{Raw: t.Sub(a.Raw, b.Raw)}
}

// ScalarMulA multiplies an Algo amount by a scalar
func (t *OverflowTracker) ScalarMulA(a MicroAlgos, b uint64) MicroAlgos {
	return MicroAlgos{Raw: t.Mul(a.Raw, b)}
}

// MinA returns the smaller of 2 MicroAlgos values
func MinA(a, b MicroAlgos) MicroAlgos {
	if a.Raw < b.Raw {
		return a
	}
	return b
}

// muldiv computes a*b/c. It returns (quotient, remainder, overflow). The
// overflow flag indicates that the result was 2^64 or greater.
func muldiv[A ~uint64, B ~uint64](a A, b B, c uint64) (A, A, bool) {
	hi, lo := bits.Mul64(uint64(a), uint64(b))
	if c <= hi {
		// It would often be useful if we returned math.MaxUint64 in case of
		// overflow, but before changing it, we need to inspect current users
		// carefully.
		return 0, 0, true
	}
	quo, rem := bits.Div64(hi, lo, c)
	return A(quo), A(rem), false
}

// Muldiv computes a*b/c.  The overflow flag indicates that the result was 2^64
// or greater. `c` is not generic, because most call sites use a constant. Making
// `c` generic forced casting it to uint64, as Go makes it an int.
func Muldiv[A ~uint64, B ~uint64](a A, b B, c uint64) (A, bool) {
	quo, _, overflow := muldiv(a, b, c)
	return quo, overflow
}

// Mul2div computes a*b*c/d. It returns (quotient, remainder, overflow). On
// overflow, the returned quotient is saturated and remainder is 0.
func Mul2div[A ~uint64, B ~uint64, C ~uint64](a A, b B, c C, d uint64) (A, A, bool) {
	/*
	    A     Y   X0     XY
	  x B   x C  x C    x C
	  ---   ---  ---    ---
	   XY    JK  LM0    JK+LM0
	*/

	X, Y := bits.Mul64(uint64(a), uint64(b))
	J, K := bits.Mul64(Y, uint64(c))
	L, M := bits.Mul64(X, uint64(c))
	if L > 0 { // L is the third "digit", no divisor will get us down to one "digit"
		return math.MaxUint64, 0, true
	}

	JplusM := AddSaturate(J, M) // "J" + "M"

	// This test ensures the division won't overflow AND that there's no carry
	// into the "L" part (since `JplusM` is MaxUint64 in that case). Dividing by
	// d can't get us down to one "digit".
	if d <= JplusM {
		return math.MaxUint64, 0, true
	}

	quo, rem := bits.Div64(JplusM, K, d)
	return A(quo), A(rem), false
}

// MulMicros multiplies a MicroAlgos amount by a Micros amount. It saturates AND
// reports overflow.
func (base MicroAlgos) MulMicros(m Micros) (MicroAlgos, bool) {
	res, overflowed := Muldiv(base.Raw, m, 1e6)
	if overflowed {
		res = math.MaxUint64
	}
	return MicroAlgos{Raw: res}, overflowed
}

// feeResidueScale is the denominator of a feeResidue: residues are fractional
// microAlgos held to 1e-12 precision, so they always live in [0, feeResidueScale).
// It matches the divisor Mul2div uses below, so the two-factor multiply's
// remainder is already expressed at this scale.
const feeResidueScale = 1e12

// FeeForUsage returns the fee to charge for `usage` scaled by `multiplier`,
// given the running `residue` (fractional microAlgos over feeResidueScale
// already paid by earlier round-ups). It returns the fee and the updated
// residue. Because it only rounds up when the residue cannot absorb the
// fraction, fees charged across a sequence of (possibly nested) groups round up
// just once in aggregate. It saturates and reports overflow.
func (base MicroAlgos) FeeForUsage(usage, multiplier Micros, residue uint64) (fee MicroAlgos, newResidue uint64, overflow bool) {
	quo, rem, overflowed := Mul2div(base.Raw, usage, multiplier, feeResidueScale)
	if overflowed {
		return MicroAlgos{Raw: math.MaxUint64}, residue, true
	}
	// A round-up that would carry quo past MaxUint64 is itself an overflow.
	if quo == math.MaxUint64 && rem > residue {
		return MicroAlgos{Raw: quo}, residue, true
	}
	if rem == 0 {
		return MicroAlgos{Raw: quo}, residue, false // exact; residue untouched
	}
	if rem <= residue {
		return MicroAlgos{Raw: quo}, residue - rem, false // prior round-up already paid for this fraction
	}
	// Must round up. The overpayment becomes the residue available to later charges.
	return MicroAlgos{Raw: quo + 1}, feeResidueScale - (rem - residue), false
}

// DivCeil provides `math.Ceil` semantics using integer division.  The technique
// avoids slower floating point operations as suggested in https://stackoverflow.com/a/2745086.
//
// The method assumes both numbers are positive and does _not_ check for divide-by-zero.
func DivCeil[T constraints.Integer](numerator, denominator T) T {
	return (numerator + denominator - 1) / denominator
}
