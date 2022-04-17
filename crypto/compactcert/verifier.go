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
)

// Errors for the CompactCert verifier
var (
	ErrCoinNotInRange = errors.New("coin is not within slot weight range")
	ErrNoRevealInPos  = errors.New("no reveal for position")
)

// Verifier is used to verify a compact certificate. those fields represent all the verifier's trusted data
type Verifier struct {
	strengthTarget         uint64
	lnProvenWeight         uint64 // ln(provenWeight) as integer with 16 bits of precision
	participantsCommitment crypto.GenericDigest
}

// MkVerifier constructs a verifier to check the compact certificate. the arguments for this function
// represent all the verifier's trusted data
func MkVerifier(partcom crypto.GenericDigest, provenWeight uint64, strengthTarget uint64) (*Verifier, error) {
	lnProvenWt, err := lnIntApproximation(provenWeight)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		strengthTarget:         strengthTarget,
		lnProvenWeight:         lnProvenWt,
		participantsCommitment: partcom,
	}, nil
}

// Verify checks if c is a valid compact certificate for the data on a round.
// it uses the trusted data from the Verifier struct
func (v *Verifier) Verify(round uint64, data StateProofMessageHash, c *Cert) error {
	nr := uint64(len(c.PositionsToReveal))
	if err := verifyWeights(c.SignedWeight, v.lnProvenWeight, nr, v.strengthTarget); err != nil {
		return err
	}

	version := int(c.MerkleSignatureSaltVersion)
	for _, reveal := range c.Reveals {
		if err := reveal.SigSlot.Sig.IsSaltVersionEqual(version); err != nil {
			return err
		}
	}

	sigs := make(map[uint64]crypto.Hashable)
	parts := make(map[uint64]crypto.Hashable)

	for pos, r := range c.Reveals {
		sig, err := buildCommittableSignature(r.SigSlot)
		if err != nil {
			return err
		}

		sigs[pos] = sig
		parts[pos] = r.Part

		// verify that the msg and the signature is valid under the given participant's Pk
		err = r.Part.PK.VerifyBytes(
			round,
			data[:],
			r.SigSlot.Sig,
		)

		if err != nil {
			return fmt.Errorf("signature in reveal pos %d does not verify. error is %w", pos, err)
		}
	}

	// verify all the reveals proofs on the signature commitment.
	if err := merklearray.VerifyVectorCommitment(c.SigCommit[:], sigs, &c.SigProofs); err != nil {
		return err
	}

	// verify all the reveals proofs on the participant commitment.
	if err := merklearray.VerifyVectorCommitment(v.participantsCommitment[:], parts, &c.PartProofs); err != nil {
		return err
	}

	choice := coinChoiceSeed{
		partCommitment: v.participantsCommitment,
		lnProvenWeight: v.lnProvenWeight,
		sigCommitment:  c.SigCommit,
		signedWeight:   c.SignedWeight,
		data:           data,
	}

	coinHash := makeCoinGenerator(&choice)
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
