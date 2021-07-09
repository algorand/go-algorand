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

package sortition

// #cgo CFLAGS: -O3
// #cgo CXXFLAGS: -std=c++11
// #include <stdint.h>
// #include <stdlib.h>
// #include "sortition.h"
import "C"
import (
	"math/big"

	"github.com/vsivsi/bigbinomial"
	"gonum.org/v1/gonum/stat/distuv"

	"github.com/algorand/go-algorand/crypto"
)

// Select runs the sortition function and returns the number of time the key was selected
func Select(money uint64, totalMoney uint64, expectedSize float64, vrfOutput crypto.Digest) uint64 {
	binomialN := float64(money)
	binomialP := expectedSize / float64(totalMoney)

	t := &big.Int{}
	t.SetBytes(vrfOutput[:])

	precision := uint(8 * (len(vrfOutput) + 1))
	max, b, err := big.ParseFloat("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0, precision, big.ToNearestEven)
	if b != 16 || err != nil {
		panic("failed to parse big float constant in sortition")
	}

	h := big.Float{}
	h.SetPrec(precision)
	h.SetInt(t)

	ratio := big.Float{}
	cratio, _ := ratio.Quo(&h, max).Float64()

	//return uint64(C.sortition_binomial_cdf_walk(C.double(binomialN), C.double(binomialP), C.double(cratio), C.uint64_t(money)))
	return boostCdfWalk(binomialN, binomialP, cratio, money)
}

func boostCdfWalk(binomialN, binomialP, cratio float64, money uint64) uint64 {
	return uint64(C.sortition_binomial_cdf_walk(C.double(binomialN), C.double(binomialP), C.double(cratio), C.uint64_t(money)))
}

func SelectG(money uint64, totalMoney uint64, expectedSize float64, vrfOutput crypto.Digest) uint64 {
	binomialN := float64(money)
	binomialP := expectedSize / float64(totalMoney)

	t := &big.Int{}
	t.SetBytes(vrfOutput[:])

	precision := uint(8 * (len(vrfOutput) + 1))
	max, b, err := big.ParseFloat("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0, precision, big.ToNearestEven)
	if b != 16 || err != nil {
		panic("failed to parse big float constant in sortition")
	}

	h := big.Float{}
	h.SetPrec(precision)
	h.SetInt(t)

	ratio := big.Float{}
	cratio, _ := ratio.Quo(&h, max).Float64()

	return sortitionBinomialCDFWalk(binomialN, binomialP, cratio, money)
}

func sortitionBinomialCDFWalk(n, p, ratio float64, money uint64) uint64 {
	dist := distuv.Binomial{N: n, P: p} //TODO: rand src?

	for j := uint64(0); j < money; j++ {
		// Get the cdf
		boundary := dist.CDF(float64(j))

		// Found the correct boundary, break
		if ratio <= boundary {
			return j
		}
	}
	return money
}

func sortitionBinomialCDFWalk2(n, p, ratio float64, money uint64) uint64 {
	cdf, _ := bigbinomial.CDF(p, int64(n))

	for j := uint64(0); j < money; j++ {
		// Get the cdf
		boundary := cdf(int64(j))

		// Found the correct boundary, break
		if ratio <= boundary {
			return j
		}
	}
	return money
}
