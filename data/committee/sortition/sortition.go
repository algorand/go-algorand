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

import (
	"math/big"

	"github.com/algorand/go-algorand/crypto"
	"github.com/vsivsi/bigbinomial"
	"gonum.org/v1/gonum/stat/distuv"
)

// Select runs the sortition function and returns the number of time the key was selected
func Select(money uint64, totalMoney uint64, expectedSize float64, vrfOutput crypto.Digest) uint64 {

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

	p := expectedSize / float64(totalMoney)

	return sortitionPoissonCDFWalk(p, cratio, money)
}

func sortitionPoissonCDFWalk(p, ratio float64, n uint64) uint64 {
	var (
		dist = distuv.Poisson{Lambda: float64(n) * p} //TODO: rand src?
		cdf  float64
	)

	for j := uint64(0); j < n; j++ {
		// accumulate the prob
		px := dist.Prob(float64(j))

		if px == 0 {
			return n
		}

		cdf += px

		// Found the correct boundary, break
		if ratio <= cdf {
			return j
		}
	}
	return n
}

func sortitionBinomialCDFWalk(p, ratio float64, n uint64) uint64 {
	var (
		dist = distuv.Binomial{N: float64(n), P: p} //TODO: rand src?
		cdf  float64
	)

	for j := uint64(0); j < n; j++ {
		// accumulate the prob
		px := dist.Prob(float64(j))

		if px == 0 {
			return n
		}
		cdf += px

		// Found the correct boundary, break
		if ratio <= cdf {
			return j
		}
	}
	return n
}

func sortitionBigBinomialCDFWalk(p, ratio float64, n uint64) uint64 {
	pmf, _ := bigbinomial.PMF(p, int64(n))
	var cdf float64

	for j := uint64(0); j < n; j++ {
		px := pmf(int64(j))
		cdf += px
		if ratio <= cdf {
			return j
		}
	}
	return n
}
