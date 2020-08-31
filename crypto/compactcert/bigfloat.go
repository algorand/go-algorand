// Copyright (C) 2019-2020 Algorand, Inc.
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

package compactcert

import (
	"fmt"
	"math/bits"
)

// A bigFloat represents the number mantissa*2^exp, which must be non-zero.
//
// A canonical representation is one where the highest bit of mantissa is
// set.  Every operation enforces canonicality of results.
//
// We use 32-bit values here to avoid requiring a 64bit-by-64bit-to-128bit
// multiply operation for anyone that needs to implement this (even though
// Go has this operation, as bits.Mul64).
type bigFloat struct {
	mantissa uint32
	exp      int32
}

// Each bigFloat is associated with a rounding mode (up, away from zero, or
// down, towards zero).  This is reflected by these two types of bigFloat.
type bigFloatUp struct {
	bigFloat
}

type bigFloatDn struct {
	bigFloat
}

// canonicalize() ensures that the bigFloat is canonical.
func (a *bigFloat) canonicalize() {
	if a.mantissa == 0 {
		// Just to avoid infinite loops in some error case.
		return
	}

	for (a.mantissa & (1 << 31)) == 0 {
		a.mantissa = a.mantissa << 1
		a.exp = a.exp - 1
	}
}

// doRoundUp adds one to the mantissa of a canonical bigFloat
// to implement the rounding-up when there are leftover low bits.
func (a *bigFloatUp) doRoundUp() {
	if a.mantissa == (1<<32)-1 {
		a.mantissa = 1 << 31
		a.exp++
	} else {
		a.mantissa++
	}
}

// geRaw returns whether a>=b.  The Raw suffix indicates that
// this comparison does not take rounding into account, and might
// not be true if done with arbitrary-precision numbers.
func (a *bigFloat) geRaw(b *bigFloat) bool {
	if a.exp > b.exp {
		return true
	}

	if a.exp < b.exp {
		return false
	}

	return a.mantissa >= b.mantissa
}

// ge returns whether a>=b.  It requires that a was computed with
// rounding-down and b was computed with rounding-up, so that if
// ge returns true, the arbitrary-precision computation would have
// also been >=.
func (a *bigFloatDn) ge(b *bigFloatUp) bool {
	return a.geRaw(&b.bigFloat)
}

// setu64Dn sets the value to the supplied uint64 (which might get
// rounded down in the process).  x must not be zero.  truncated
// returns whether any non-zero bits were truncated (rounded down).
func (a *bigFloat) setu64Dn(x uint64) (truncated bool, err error) {
	if x == 0 {
		return false, fmt.Errorf("bigFloat cannot be zero")
	}

	e := int32(0)

	for x >= (1 << 32) {
		if (x & 1) != 0 {
			truncated = true
		}

		x = x >> 1
		e = e + 1
	}

	a.mantissa = uint32(x)
	a.exp = e
	a.canonicalize()
	return
}

// setu64 calls setu64Dn and implements rounding based on the type.
func (a *bigFloatUp) setu64(x uint64) error {
	truncated, err := a.setu64Dn(x)
	if truncated {
		a.doRoundUp()
	}
	return err
}

func (a *bigFloatDn) setu64(x uint64) error {
	_, err := a.setu64Dn(x)
	return err
}

// setu32 sets the value to the supplied uint32.
func (a *bigFloat) setu32(x uint32) error {
	if x == 0 {
		return fmt.Errorf("bigFloat cannot be zero")
	}

	a.mantissa = x
	a.exp = 0
	a.canonicalize()
	return nil
}

// setpow2 sets the value to 2^x.
func (a *bigFloat) setpow2(x int32) {
	a.mantissa = 1
	a.exp = x
	a.canonicalize()
}

// mulDn sets a to the product a*b, keeping the most significant 32 bits
// of the product's mantissa.  The return value indicates if any non-zero
// bits were discarded (rounded down).
func (a *bigFloat) mulDn(b *bigFloat) bool {
	hi, lo := bits.Mul32(a.mantissa, b.mantissa)

	a.mantissa = hi
	a.exp = a.exp + b.exp + 32

	if (a.mantissa & (1 << 31)) == 0 {
		a.mantissa = (a.mantissa << 1) | (lo >> 31)
		a.exp = a.exp - 1
		lo = lo << 1
	}

	return lo != 0
}

// mul calls mulDn and implements appropriate rounding.
// Types prevent multiplying two values with different rounding types.
func (a *bigFloatUp) mul(b *bigFloatUp) {
	truncated := a.mulDn(&b.bigFloat)
	if truncated {
		a.doRoundUp()
	}
}

func (a *bigFloatDn) mul(b *bigFloatDn) {
	a.mulDn(&b.bigFloat)
}

// String returns a string representation of a.
func (a *bigFloat) String() string {
	return fmt.Sprintf("%d*2^%d", a.mantissa, a.exp)
}
