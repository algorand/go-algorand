// Copyright (C) 2019-2022 Algorand, Inc.
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
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"
)

var (
	ErrSignedWeightLessThanProvenWeight = errors.New("signed weight is less than or equal to proven weight")
	ErrTooManyReveals                   = errors.New("too many reveals in cert")
	ErrZeroSignedWeight                 = errors.New("signed weight can not be zero")
	ErrZeroProvenWeightThreshold        = errors.New("proven weight can not be zero")
	ErrInsufficientImpliedProvenWeight  = errors.New("signed weight and number of reveals yield insufficient proven weight")
)

func bigInt(num uint64) *big.Int {
	return (&big.Int{}).SetUint64(num)
}

func lnIntApproximation(x uint64, precisionBits uint64) uint64 {
	if x == 0 {
		return 0
	}
	result := math.Log(float64(x))
	expendWithPer := result * float64(precisionBits)
	return uint64(math.Ceil(expendWithPer))
}

// verifyWeights makes sure that the number of reveals in the cert is correct with respect
// to the signedWeight and a provenWeight threshold.
// According to the security analysis the number of reveals is given by the following:
//
// numReveals is the smallest number that satisfies
// 2^-k >= 2^q * (provenWeight / signedWeight) ^ numReveals
//
// in order to make the verification SNARK friendly we will not compute the exact number of reveals (as it is done in the build)
// Alternatively, we would use a lower bound on the implied provenWeight using a given numReveals and signedWeight .
// i.e we need to verify that:
// numReveals*(log2(signedWeight)-log2(provenWeightThreshold)) >= k+q
// In addition, we would like to use a friendly log2 approximation. it is sufficient to verify the following inequality:
//
// numReveals * ( 3 * 2^b * (signedWeight^2-2^2d) + d * (T-1) * Y) >= ((k+q) * T + numReveals * P) * Y
// where signedWeight/(2^d) >=1 for some integer d>=0, p = P/(2^b) >= ln(provenWeightThreshold), t = T/(2^b) >= ln(2) >= (T-1)/(2^b)
// for some integers P,T >= 0 and b=16
//
func (v *Verifier) verifyWeights(signedWeight uint64, numOfReveals uint64) error {
	if numOfReveals > MaxReveals {
		return ErrTooManyReveals
	}

	if signedWeight == 0 {
		return ErrZeroSignedWeight
	}

	if v.ProvenWeightThreshold == 0 {
		return ErrZeroProvenWeightThreshold
	}

	if signedWeight <= v.ProvenWeightThreshold {
		return fmt.Errorf("%w - signed weight %d <= proven weight %d", ErrSignedWeightLessThanProvenWeight, signedWeight, v.ProvenWeightThreshold)
	}

	y, a, b := getSubExpressions(signedWeight)
	lhs := &big.Int{}
	lhs.Set(b).
		Mul(lhs, y).
		Add(a, lhs).
		Mul(lhs, bigInt(numOfReveals))

	rhs := bigInt(v.SecKQ * ln2IntApproximation)
	rhs.Add(rhs, bigInt(numOfReveals*v.lnProvenWeightThreshold)).
		Mul(rhs, y)

	if lhs.Cmp(rhs) < 0 {
		return ErrInsufficientImpliedProvenWeight
	}

	return nil
}

// numReveals computes the number of reveals necessary to achieve the desired
// security parameters.  See section 8 of the ``Compact Certificates''
// document for the analysis.
//
// numReveals is the smallest number that satisfies
//
// 2^-k >= 2^q * (provenWeight / signedWeight) ^ numReveals
//
// which is equivalent to the following:
//
// signedWeight ^ numReveals >= 2^(k+q) * provenWeight ^ numReveals
//
// ***********
// numReveals*(3*2^b*(signedWeight^2-2^2d)+d*(T-1)*Y) >= ((k+q)*T+numReveals*P)*Y
// numReveals*(3*2^b*(signedWeight^2-2^2d)+(d*(T-1)-P)*Y) >= (k+q)*T*Y
// numReveals >= (k+q)*T*Y/(3*2^b*(signedWeight^2-2^2d)+(d*(T-1)-P)*Y)
// numReveals =Ceil( (k+q)*T*Y/(3*2^b*(signedWeight^2-2^2d)+(d*(T-1)-P)*Y) )
// To ensure tsdkfjgalskdnglasdg
func numReveals(signedWeight uint64, provenWeight uint64, secKQ uint64, bound uint64) (uint64, error) {
	if provenWeight == 0 {
		return 0, ErrZeroProvenWeightThreshold
	}

	lnProvenWe := lnIntApproximation(provenWeight, precisionBits)

	y, a, b := getSubExpressions(signedWeight)

	numerator := bigInt(secKQ)
	numerator.Mul(numerator, bigInt(ln2IntApproximation)).
		Mul(numerator, y)

	denom := &big.Int{}
	denom.Set(b).
		Sub(denom, bigInt(lnProvenWe)).
		Mul(denom, y).
		Add(a, denom)

	res := numerator.Div(numerator, denom).Uint64() + 1
	if res > MaxReveals {
		return 0, ErrTooManyReveals
	}
	return res, nil
}

func old(signedWeight uint64, provenWeight uint64, secKQ uint64, bound uint64) (uint64, error) {
	n := uint64(0)

	sw := &bigFloatDn{}
	err := sw.setu64(signedWeight)
	if err != nil {
		return 0, err
	}

	pw := &bigFloatUp{}
	err = pw.setu64(provenWeight)
	if err != nil {
		return 0, err
	}

	lhs := &bigFloatDn{}
	err = lhs.setu64(1)
	if err != nil {
		return 0, err
	}

	rhs := &bigFloatUp{}
	rhs.setpow2(int32(secKQ))

	for {
		if lhs.ge(rhs) {
			return n, nil
		}

		if n >= bound {
			return 0, fmt.Errorf("numReveals(%d, %d, %d) > %d", signedWeight, provenWeight, secKQ, bound)
		}

		lhs.mul(sw)
		rhs.mul(pw)
		n++
	}
}
func (p *Builder) numReveals(signedWeight uint64) (uint64, error) {
	return numReveals(signedWeight, p.ProvenWeightThreshold, p.SecKQ, MaxReveals)
}

func getSubExpressions(signedWeight uint64) (*big.Int, *big.Int, *big.Int) {
	// find d s.t 2^(d+1) >= signedWeight >= 2^(d)
	d := uint64(bits.Len64(signedWeight)) - 1

	signedWtPower2 := &big.Int{}
	signedWtPower2.SetUint64(signedWeight)
	signedWtPower2.Mul(signedWtPower2, signedWtPower2)

	//tmp = 2^(d+2)*signedWt == 4*2^d*signedWt
	tmp := (&big.Int{}).Mul(
		bigInt(1<<(d+2)),
		bigInt(signedWeight),
	)

	// Y = signedWt^2 + 2^(d+2)*signedWt +2^2d == signedWt^2 + tmp +2^2d
	y := bigInt(1)
	y.Lsh(y, uint(2*d)).
		Add(y, tmp).
		Add(y, signedWtPower2)

	// a =  3*2^b*(signedWt^2-2^2d)
	a := bigInt(1)
	a.Lsh(a, uint(2*d)).
		Sub(signedWtPower2, a).
		Mul(a, bigInt(3)).
		Mul(a, bigInt(precisionBits))

	// b = d*(T-1)
	b := bigInt(d)
	b.Mul(b, bigInt(ln2IntApproximation-1))

	return y, a, b
}
