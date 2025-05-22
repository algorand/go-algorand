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

// Muldiv computes a*b/c.  The overflow flag indicates that
// the result was 2^64 or greater.
func Muldiv(a uint64, b uint64, c uint64) (res uint64, overflow bool) {
	hi, lo := bits.Mul64(a, b)
	if c <= hi {
		return 0, true
	}
	quo, _ := bits.Div64(hi, lo, c)
	return quo, false
}

// DivCeil provides `math.Ceil` semantics using integer division.  The technique
// avoids slower floating point operations as suggested in https://stackoverflow.com/a/2745086.
//
// The method assumes both numbers are positive and does _not_ check for divide-by-zero.
func DivCeil[T constraints.Integer](numerator, denominator T) T {
	return (numerator + denominator - 1) / denominator
}
