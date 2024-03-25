// Copyright (C) 2019-2024 Algorand, Inc.
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
	"fmt"
)

// Fraction represents the mathematical notion of rational number, but is much
// simpler than `big.Rat`. It only supports numerators and denominators of
// uint64.
type Fraction struct {
	Numerator   uint64
	Denominator uint64
}

// NewFraction creates the obvious Fraction, and checks that is not improper,
// nor divides by zero.
func NewFraction(numerator uint64, denominator uint64) Fraction {
	if denominator == 0 {
		panic("/0")
	}
	if numerator > denominator {
		panic("improper fraction")
	}
	return Fraction{numerator, denominator}
}

// NewPercent creates a fraction reflecting the given percentage.
func NewPercent(pct uint64) Fraction {
	return NewFraction(pct, 100)
}

// String returns a string representation of Fraction
func (frac Fraction) String() string {
	return fmt.Sprintf("%d/%d", frac.Numerator, frac.Denominator)
}

// Divvy separates a quantity into two parts according to the fraction. The first
// value is floor(q * frac), the second is q - first.
func (frac Fraction) Divvy(q uint64) (uint64, uint64) {
	// can't overflow on proper fractions
	first, o := Muldiv(q, frac.Numerator, frac.Denominator)
	if o {
		panic("overflow")
	}
	second := q - first
	return first, second
}

// DivvyAlgos is Divvy, but operates on MicroAlgos
func (frac Fraction) DivvyAlgos(q MicroAlgos) (MicroAlgos, MicroAlgos) {
	first, second := frac.Divvy(q.Raw)
	return MicroAlgos{first}, MicroAlgos{second}
}
