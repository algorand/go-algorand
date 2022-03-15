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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"math"
	"math/bits"
)

// Errors for the CompactCert verifier
var (
	ErrCoinNotInRange                   = errors.New("coin is not within slot weight range")
	ErrNoRevealInPos                    = errors.New("no reveal for position")
	ErrSignedWeightLessThanProvenWeight = errors.New("signed weight is less than or equal to proven weight")
	ErrTooManyReveals                   = errors.New("too many reveals in cert")
	ErrInsufficientImpliedProvenWeight  = errors.New("signed weight and number of reveals yield insufficient proven weight")
)

// Verifier is used to verify a compact certificate.
type Verifier struct {
	Params

	partcom crypto.GenericDigest
}

// MkVerifier constructs a verifier to check the compact certificate
// on the message specified in p, with partcom specifying the Merkle
// root of the participants that must sign the message.
func MkVerifier(p Params, partcom crypto.GenericDigest) *Verifier {
	return &Verifier{
		Params:  p,
		partcom: partcom,
	}
}

// Verify checks if c is a valid compact certificate for the message
// and participants that were used to construct the Verifier.
func (v *Verifier) Verify(c *Cert) error {
	nr := uint64(len(c.PositionsToReveal))
	if err := v.verifyWeights(c.SignedWeight, nr); err != nil {
		return err
	}

	version := int(c.MerkleSignatureVersion)
	for _, reveal := range c.Reveals {
		if err := reveal.SigSlot.Sig.ValidateSigVersion(version); err != nil {
			return err
		}
	}

	sigs := make(map[uint64]crypto.Hashable)
	parts := make(map[uint64]crypto.Hashable)

	msghash := v.Params.StateProofMessageHash
	for pos, r := range c.Reveals {
		sig, err := buildCommittableSignature(r.SigSlot)
		if err != nil {
			return err
		}

		sigs[pos] = sig
		parts[pos] = r.Part

		// verify that the msg and the signature is valid under the given participant's Pk
		err = r.Part.PK.VerifyBytes(
			uint64(v.SigRound),
			msghash[:],
			r.SigSlot.Sig,
		)

		if err != nil {
			return fmt.Errorf("signature in reveal pos %d does not verify. error is %w", pos, err)
		}
	}

	// verify all the reveals proofs on the signature tree.
	if err := merklearray.VerifyVectorCommitment(c.SigCommit[:], sigs, &c.SigProofs); err != nil {
		return err
	}

	// verify all the reveals proofs on the participant tree.
	if err := merklearray.VerifyVectorCommitment(v.partcom[:], parts, &c.PartProofs); err != nil {
		return err
	}

	choice := coinChoiceSeed{
		SignedWeight: c.SignedWeight,
		ProvenWeight: v.ProvenWeightThreshold,
		Sigcom:       c.SigCommit,
		Partcom:      v.partcom,
		MsgHash:      v.Msg,
	}

	coinHash := MakeCoinGenerator(choice)
	for j := uint64(0); j < nr; j++ {
		pos := c.PositionsToReveal[j]
		reveal, exists := c.Reveals[pos]
		if !exists {
			return fmt.Errorf("%w: %d", ErrNoRevealInPos, pos)
		}

		coin := coinHash.getNextCoin()
		if !(reveal.SigSlot.L <= coin && coin < reveal.SigSlot.L+reveal.Part.Weight) {
			return fmt.Errorf("%w: for reveal pos %d and coin %d, ", ErrCoinNotInRange, pos, coin)
		}
	}

	return nil
}

func (v *Verifier) verifyWeights(signedWeight uint64, numOfReveals uint64) error {
	if numOfReveals > MaxReveals {
		return ErrTooManyReveals
	}

	if signedWeight <= v.ProvenWeightThreshold {
		return fmt.Errorf("%w - signed weight %d <= proven weight %d", ErrSignedWeightLessThanProvenWeight, signedWeight, v.ProvenWeightThreshold)
	}

	weightLowerBond := log2Up(signedWeight) - log2Down(v.ProvenWeightThreshold)
	fmt.Printf("sw : %f  pw: %f\n", math.Log2(float64(signedWeight)), math.Log2(float64(v.ProvenWeightThreshold)))
	fmt.Printf("func sw : %d  pw: %d\n", log2Down(signedWeight), log2Up(v.ProvenWeightThreshold))
	fmt.Printf("sw - pw=%d\n", log2Up(signedWeight)-log2Down(v.ProvenWeightThreshold))
	fmt.Printf("numRev*(sw-pw) = %d\n", uint64(weightLowerBond)*numOfReveals)
	if uint64(weightLowerBond)*numOfReveals < v.SecKQ {
		return ErrInsufficientImpliedProvenWeight
	}
	return nil
}

func log2Up(x uint64) uint64 {
	bits := uint64(bits.Len64(x))
	if 1<<(bits-1) == x {
		return bits - 1
	}
	return (bits - 1) + 1
}

func log2Down(x uint64) uint64 {
	bits := uint64(bits.Len64(x))
	if 1<<(bits-1) == x {
		return bits - 1
	}
	return bits - 1
}
