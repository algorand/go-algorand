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
// which is equivalent to the following, which avoids any floating-point math:
//
// signedWeight ^ numReveals >= 2^(k+q) * provenWeight ^ numReveals
func numReveals(signedWeight uint64, provenWeight uint64, secKQ uint64, bound uint64) (uint64, error) {
	n := uint64(0)

	sw := &big.Int{}
	sw.SetUint64(signedWeight)

	pw := &big.Int{}
	pw.SetUint64(provenWeight)

	lhs := big.NewInt(1)
	rhs := &big.Int{}
	rhs.SetBit(rhs, int(secKQ), 1)

	for {
		if lhs.Cmp(rhs) >= 0 {
			return n, nil
		}

		if n >= bound {
			return 0, fmt.Errorf("numReveals(%d, %d, %d) > %d", signedWeight, provenWeight, secKQ, bound)
		}

		lhs.Mul(lhs, sw)
		rhs.Mul(rhs, pw)
		n += 1
	}
}

func (p Params) numReveals(signedWeight uint64) (uint64, error) {
	return numReveals(signedWeight, p.ProvenWeight, p.SecKQ, maxReveals)
}
