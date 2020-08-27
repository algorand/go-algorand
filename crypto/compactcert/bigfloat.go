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

// A bigFloat represents the number base*2^exp, which must be non-zero.
// A canonical representation is one where the highest bit of base is
// set, or where base=0 and exp=0.  Every operation enforces canonicality
// of results.  We use 32-bit values here to avoid requiring access
// to a 64bit-by-64bit-to-128bit multiply operation for anyone that
// needs to implement this (even though Go has this operation, as
// bits.Mul64).
type bigFloat struct {
	base uint32
	exp  int32
}

// canonicalize() ensures that the bigFloat is canonical.
func (a *bigFloat) canonicalize() {
	if a.base == 0 {
		// Just to avoid infinite loops in some error case.
		return
	}

	for (a.base & (1 << 31)) == 0 {
		a.base = a.base << 1
		a.exp = a.exp - 1
	}
}

// ge returns whether a>=b.
func (a *bigFloat) ge(b *bigFloat) bool {
	if a.exp > b.exp {
		return true
	}

	if a.exp < b.exp {
		return false
	}

	return a.base >= b.base
}

// setu64 sets the value to the supplied uint64 (which might get
// rounded down in the process).  x must not be zero.
func (a *bigFloat) setu64(x uint64) error {
	if x == 0 {
		return fmt.Errorf("bigFloat cannot be zero")
	}

	e := int32(0)

	for x >= (1 << 32) {
		x = x >> 1
		e = e + 1
	}

	a.base = uint32(x)
	a.exp = e
	a.canonicalize()
	return nil
}

// setu32 sets the value to the supplied uint32.
func (a *bigFloat) setu32(x uint32) error {
	if x == 0 {
		return fmt.Errorf("bigFloat cannot be zero")
	}

	a.base = x
	a.exp = 0
	a.canonicalize()
	return nil
}

// setpow2 sets the value to 2^x.
func (a *bigFloat) setpow2(x int32) {
	a.base = 1
	a.exp = x
	a.canonicalize()
}

// mul sets a to the product a*b, keeping the most significant 32 bits
// of the product's base.
func (a *bigFloat) mul(b *bigFloat) {
	hi, lo := bits.Mul32(a.base, b.base)

	a.base = hi
	a.exp = a.exp + b.exp + 32

	if (a.base & (1 << 31)) == 0 {
		a.base = (a.base << 1) | (lo >> 31)
		a.exp = a.exp - 1
	}
}

// String returns a string representation of a.
func (a *bigFloat) String() string {
	return fmt.Sprintf("%d*2^%d", a.base, a.exp)
}
