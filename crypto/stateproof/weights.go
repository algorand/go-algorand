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

package stateproof

import (
	"errors"
	"math"
	"math/big"
	"math/bits"
)

// errors for the weights verification
var (
	ErrSignedWeightLessThanProvenWeight = errors.New("signed weight is less than or equal to proven weight")
	ErrTooManyReveals                   = errors.New("too many reveals in state proof")
	ErrZeroSignedWeight                 = errors.New("signed weight cannot be zero")
	ErrIllegalInputForLnApprox          = errors.New("cannot calculate a ln integer value for 0")
	ErrInsufficientSignedWeight         = errors.New("the number of reveals is not large enough to prove that the desired weight signed, with the desired security level")
	ErrNegativeNumOfRevealsEquation     = errors.New("state proof creation failed: weights will not be able to satisfy the verification equation")
)

func bigInt(num uint64) *big.Int {
	return (&big.Int{}).SetUint64(num)
}

// LnIntApproximation returns a uint64 approximation
func LnIntApproximation(x uint64) (uint64, error) {
	if x == 0 {
		return 0, ErrIllegalInputForLnApprox
	}
	result := math.Log(float64(x))
	precision := uint64(1 << precisionBits)
	expandWithPrecision := result * float64(precision)
	return uint64(math.Ceil(expandWithPrecision)), nil

}

// verifyWeights makes sure that the number of reveals in the state proof is correct with respect
// to the signedWeight and a provenWeight upper bound.
// This function checks that the following inequality is satisfied
//
// numReveals * (3 * 2^b * (signedWeight^2 - 2^2d) + d * (T-1) * Y) >= ((strengthTarget) * T + numReveals * P) * Y
//
// where signedWeight/(2^d) >=1 for some integer d>=0, p = P/(2^b) >= ln(provenWeight), t = T/(2^b) >= ln(2) >= (T-1)/(2^b)
// for some integers P,T >= 0 and b=16.
//
// T and b are defined in the code as the constants ln2IntApproximation and precisionBits respectively.
// P is set to lnProvenWeight argument
// more details can be found on the Algorand's spec
func verifyWeights(signedWeight uint64, lnProvenWeight uint64, numOfReveals uint64, strengthTarget uint64) error {
	if numOfReveals > MaxReveals {
		return ErrTooManyReveals
	}

	if signedWeight == 0 {
		return ErrZeroSignedWeight
	}

	// in order to make the code more readable and reusable we will define the following expressions:
	// y = signedWeight^2 + 2^(d + 2) * signedWeight + 2^2d
	// x = 3 * 2^b * (signedWeight^2 - 2^2d)
	// w = d * (T - 1)
	//
	//  numReveals * (3 * 2^b * (signedWeight^2 - 2^2d) + d * (T-1) * Y) >= ((strengthTarget) * T + numReveals * P) * Y
	//        /\
	//        ||
	//        \/
	// numReveals * (x + w * y) >= ((strengthTarget) * T + numReveals * P) * y
	y, x, w := getSubExpressions(signedWeight)
	lhs := &big.Int{}
	lhs.Set(w).
		Mul(lhs, y).
		Add(x, lhs).
		Mul(bigInt(numOfReveals), lhs)

	revealsTimesP := &big.Int{}
	revealsTimesP.Set(bigInt(numOfReveals)).Mul(revealsTimesP, bigInt(lnProvenWeight))

	rhs := &big.Int{}
	rhs.Set(bigInt(strengthTarget))
	rhs.Mul(rhs, bigInt(ln2IntApproximation)).
		Add(rhs, revealsTimesP).
		Mul(rhs, y)

	if lhs.Cmp(rhs) < 0 {
		return ErrInsufficientSignedWeight
	}

	return nil
}

// numReveals computes the number of reveals necessary to achieve the desired
// security target. We search for small integer that will satisfy the verification
// inequality checked by the verifyWeights function.
// In order to make sure the number will satisfy the verifier we will use the following inequality
//
// numReveals >= ((strengthTarget) * T * Y / (3 * 2^b * (signedWeight^2 - 2^2d) + (d * (T - 1) - P) * Y))
// where signedWeight/(2^d) >=1 for some integer d>=0, p = P/(2^b) >= ln(provenWeight), t = T/(2^b) >= ln(2) >= (T-1)/(2^b)
// for some integers P,T >= 0 and b=16.
//
// T and b are defined in the code as the constants ln2IntApproximation and precisionBits respectively,
// and P is set to lnProvenWeight argument.
//
// more details can be found on the Algorand's spec
func numReveals(signedWeight uint64, lnProvenWeight uint64, strengthTarget uint64) (uint64, error) {
	// in order to make the code more readable and reusable we will define the following expressions:
	// y = signedWeight^2 + 2^(d + 2) * signedWeight + 2^2d
	// x = 3 * 2^b * (signedWeight^2 - 2^2d)
	// w = d * (T - 1)
	//
	// numReveals >= ((strengthTarget) * T * Y / (3 * 2^b * (signedWeight^2 - 2^2d) + (d * (T - 1) - P) * Y))
	//        /\
	//        ||
	//        \/
	// numReveals >= ((strengthTarget) * T * y / (x + (w - P) * y))
	y, x, w := getSubExpressions(signedWeight)

	// numerator = strengthTarget * ln2IntApproximation * y
	numerator := bigInt(strengthTarget)
	numerator.Mul(numerator, bigInt(ln2IntApproximation)).
		Mul(numerator, y)

	// denom =  x + (w - lnProvenWeight)  * y
	denom := w
	denom.Sub(denom, bigInt(lnProvenWeight)).
		Mul(denom, y).
		Add(x, denom)

	if denom.Sign() <= 0 {
		return 0, ErrNegativeNumOfRevealsEquation
	}

	// numberReveals = (numerator / denom) + 1
	// by adding 1 we guarantee that the return value satisfy the inequality and therefore
	// will satisfy the verifier.
	// + 1 to account for the decimal point value loss due to integer division
	res := numerator.Div(numerator, denom).Uint64() + 1
	if res > MaxReveals {
		return 0, ErrTooManyReveals
	}
	return res, nil
}

// getSubExpressions calculate the following expression to make the code more readable and reusable
// y = signedWeight^2 + 2^(d + 2) * signedWeight + 2^2d
// x = 3 * 2^b * (signedWeight^2 - 2^2d)
// w = d * (T - 1)
func getSubExpressions(signedWeight uint64) (y *big.Int, x *big.Int, w *big.Int) {
	// find d s.t 2^(d+1) >= signedWeight >= 2^(d)
	d := uint(bits.Len64(signedWeight)) - 1

	signedWtPower2 := bigInt(signedWeight)
	signedWtPower2.Mul(signedWtPower2, signedWtPower2)

	//tmp = 2^(d+2)*signedWt
	tmp := bigInt(1)
	tmp.Lsh(tmp, d+2).
		Mul(tmp, bigInt(signedWeight))

	// Y = signedWeight^2 + 2^(d+2)*signedWeight +2^2d == signedWeight^2 + tmp +2^2d
	y = bigInt(1)
	y.Lsh(y, 2*d).
		Add(y, tmp).
		Add(y, signedWtPower2)

	// x =  3*2^b*(signedWeight^2-2^2d)
	x = bigInt(1)
	x.Lsh(x, 2*d).
		Sub(signedWtPower2, x).
		Mul(x, bigInt(3)).
		Mul(x, bigInt(1<<precisionBits))

	// w = d*(T-1)
	w = bigInt(uint64(d))
	w.Mul(w, bigInt(ln2IntApproximation-1))

	return
}
