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

package compactcert

import (
	"fmt"
	"math/big"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// The coinChoice type defines the fields that go into the hash for choosing
// the index of the coin to reveal as part of the compact certificate.
type coinChoice struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	J            uint64        `codec:"j"`
	SignedWeight uint64        `codec:"sigweight"`
	ProvenWeight uint64        `codec:"provenweight"`
	Sigcom       crypto.Digest `codec:"sigcom"`
	Partcom      crypto.Digest `codec:"partcom"`
	MsgHash      crypto.Digest `codec:"msghash"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (cc coinChoice) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.CompactCertCoin, protocol.Encode(&cc)
}

// hashCoin returns a number in [0, choice.SignedWeight) with a nearly uniform
// distribution, "randomized" by all of the fields in choice.
func hashCoin(choice coinChoice) uint64 {
	h := crypto.HashObj(choice)

	i := &big.Int{}
	i.SetBytes(h[:])

	w := &big.Int{}
	w.SetUint64(choice.SignedWeight)

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
