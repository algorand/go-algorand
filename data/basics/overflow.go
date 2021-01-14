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

package basics

import (
	"math"
	"math/big"
)

// OverflowTracker is used to track when an operation causes an overflow
type OverflowTracker struct {
	Overflowed bool
}

// OAdd16 adds 2 uint16 values with overflow detection
func OAdd16(a uint16, b uint16) (res uint16, overflowed bool) {
	res = a + b
	overflowed = res < a
	return
}

// OAdd adds 2 values with overflow detection
func OAdd(a uint64, b uint64) (res uint64, overflowed bool) {
	res = a + b
	overflowed = res < a
	return
}

// OSub subtracts b from a with overflow detection
func OSub(a uint64, b uint64) (res uint64, overflowed bool) {
	res = a - b
	overflowed = res > a
	return
}

// OMul multiplies 2 values with overflow detection
func OMul(a uint64, b uint64) (res uint64, overflowed bool) {
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
func MulSaturate(a uint64, b uint64) uint64 {
	res, overflowed := OMul(a, b)
	if overflowed {
		return math.MaxUint64
	}
	return res
}

// AddSaturate adds 2 values with saturation on overflow
func AddSaturate(a uint64, b uint64) uint64 {
	res, overflowed := OAdd(a, b)
	if overflowed {
		return math.MaxUint64
	}
	return res
}

// SubSaturate subtracts 2 values with saturation on underflow
func SubSaturate(a uint64, b uint64) uint64 {
	res, overflowed := OSub(a, b)
	if overflowed {
		return 0
	}
	return res
}

// Add16 adds 2 uint16 values with overflow detection
func (t *OverflowTracker) Add16(a uint16, b uint16) uint16 {
	res, overflowed := OAdd16(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// Add adds 2 values with overflow detection
func (t *OverflowTracker) Add(a uint64, b uint64) uint64 {
	res, overflowed := OAdd(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// Sub subtracts b from a with overflow detection
func (t *OverflowTracker) Sub(a uint64, b uint64) uint64 {
	res, overflowed := OSub(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// Mul multiplies b from a with overflow detection
func (t *OverflowTracker) Mul(a uint64, b uint64) uint64 {
	res, overflowed := OMul(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// OAddA adds 2 MicroAlgos values with overflow tracking
func OAddA(a MicroAlgos, b MicroAlgos) (res MicroAlgos, overflowed bool) {
	res.Raw, overflowed = OAdd(a.Raw, b.Raw)
	return
}

// OSubA subtracts b from a with overflow tracking
func OSubA(a MicroAlgos, b MicroAlgos) (res MicroAlgos, overflowed bool) {
	res.Raw, overflowed = OSub(a.Raw, b.Raw)
	return
}

// MulAIntSaturate uses MulSaturate to multiply b (int) with a (MicroAlgos)
func MulAIntSaturate(a MicroAlgos, b int) MicroAlgos {
	return MicroAlgos{Raw: MulSaturate(a.Raw, uint64(b))}
}

// AddA adds 2 MicroAlgos values with overflow tracking
func (t *OverflowTracker) AddA(a MicroAlgos, b MicroAlgos) MicroAlgos {
	return MicroAlgos{Raw: t.Add(a.Raw, b.Raw)}
}

// SubA subtracts b from a with overflow tracking
func (t *OverflowTracker) SubA(a MicroAlgos, b MicroAlgos) MicroAlgos {
	return MicroAlgos{Raw: t.Sub(a.Raw, b.Raw)}
}

// AddR adds 2 Round values with overflow tracking
func (t *OverflowTracker) AddR(a Round, b Round) Round {
	return Round(t.Add(uint64(a), uint64(b)))
}

// SubR subtracts b from a with overflow tracking
func (t *OverflowTracker) SubR(a Round, b Round) Round {
	return Round(t.Sub(uint64(a), uint64(b)))
}

// ScalarMulA multiplies an Algo amount by a scalar
func (t *OverflowTracker) ScalarMulA(a MicroAlgos, b uint64) MicroAlgos {
	return MicroAlgos{Raw: t.Mul(a.Raw, b)}
}

// Muldiv computes a*b/c.  The overflow flag indicates that
// the result was 2^64 or greater.
func Muldiv(a uint64, b uint64, c uint64) (res uint64, overflow bool) {
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
