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

package basics

import (
	"math/bits"

	"golang.org/x/exp/constraints"
)

// OverflowTracker is used to track when an operation causes an overflow
type OverflowTracker[T constraints.Unsigned] struct {
	Overflowed bool
}

// OverflowTrackerU64 is the u64 instantiation for OverflowTracker
type OverflowTrackerU64 = OverflowTracker[uint64]

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
func (t *OverflowTracker[T]) Add(a, b T) T {
	res, overflowed := OAdd(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// Sub subtracts b from a with overflow detection
func (t *OverflowTracker[T]) Sub(a, b T) T {
	res, overflowed := OSub(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// Mul multiplies b by a with overflow detection
func (t *OverflowTracker[T]) Mul(a, b T) T {
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
func (t *OverflowTracker[T]) AddA(a, b MicroAlgos) MicroAlgos {
	return MicroAlgos{Raw: uint64(t.Add(T(a.Raw), T(b.Raw)))}
}

// SubA subtracts b from a with overflow tracking
func (t *OverflowTracker[T]) SubA(a, b MicroAlgos) MicroAlgos {
	return MicroAlgos{Raw: uint64(t.Sub(T(a.Raw), T(b.Raw)))}
}

// AddR adds 2 Round values with overflow tracking
func (t *OverflowTracker[T]) AddR(a, b Round) Round {
	return Round(t.Add(T(a), T(b)))
}

// SubR subtracts b from a with overflow tracking
func (t *OverflowTracker[T]) SubR(a, b Round) Round {
	return Round(t.Sub(T(a), T(b)))
}

// ScalarMulA multiplies an Algo amount by a scalar
func (t *OverflowTracker[T]) ScalarMulA(a MicroAlgos, b uint64) MicroAlgos {
	return MicroAlgos{Raw: uint64(t.Mul(T(a.Raw), T(b)))}
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
