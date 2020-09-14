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
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/algorand/go-algorand/crypto"
)

// hashCoin returns a number in [0, signedWeight) with a nearly uniform
// distribution, "randomized" by all of the supplied arguments.
func hashCoin(j uint64, sigcom crypto.Digest, signedWeight uint64) uint64 {
	hashinput := make([]byte, 16+crypto.DigestSize)
	binary.LittleEndian.PutUint64(hashinput[0:], j)
	binary.LittleEndian.PutUint64(hashinput[8:], signedWeight)
	copy(hashinput[16:], sigcom[:])
	h := crypto.Hash(hashinput)

	i := &big.Int{}
	i.SetBytes(h[:])

	w := &big.Int{}
	w.SetUint64(signedWeight)

	res := &big.Int{}
	res.Mod(i, w)
	return res.Uint64()
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
// To ensure that rounding errors do not reduce the security parameter,
// we compute the left-hand side with rounding-down, and compute the
// right-hand side with rounding-up.
func numReveals(signedWeight uint64, provenWeight uint64, secKQ uint64, bound uint64) (uint64, error) {
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

func (p Params) numReveals(signedWeight uint64) (uint64, error) {
	return numReveals(signedWeight, p.ProvenWeight, p.SecKQ, maxReveals)
}
