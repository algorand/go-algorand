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
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
)

// Errors for the StateProof verifier
var (
	ErrCoinNotInRange    = errors.New("coin is not within slot weight range")
	ErrNoRevealInPos     = errors.New("no reveal for position")
	ErrTreeDepthTooLarge = errors.New("tree depth is too large")
)

// Verifier is used to verify a state proof. those fields represent all the verifier's trusted data
type Verifier struct {
	strengthTarget         uint64
	lnProvenWeight         uint64 // ln(provenWeight) as integer with 16 bits of precision
	participantsCommitment crypto.GenericDigest
}

// MkVerifier constructs a verifier to check the state proof. the arguments for this function
// represent all the verifier's trusted data
func MkVerifier(partcom crypto.GenericDigest, provenWeight uint64, strengthTarget uint64) (*Verifier, error) {
	lnProvenWt, err := LnIntApproximation(provenWeight)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		strengthTarget:         strengthTarget,
		lnProvenWeight:         lnProvenWt,
		participantsCommitment: partcom,
	}, nil
}

// MkVerifierWithLnProvenWeight constructs a verifier to check the state proof. the arguments for this function
// represent all the verifier's trusted data. This function uses the Ln(provenWeight) approximation value
func MkVerifierWithLnProvenWeight(partcom crypto.GenericDigest, lnProvenWt uint64, strengthTarget uint64) *Verifier {
	return &Verifier{
		strengthTarget:         strengthTarget,
		lnProvenWeight:         lnProvenWt,
		participantsCommitment: partcom,
	}
}

// Verify checks if s is a valid state proof for the data on a round.
// it uses the trusted data from the Verifier struct
func (v *Verifier) Verify(round uint64, data MessageHash, s *StateProof) error {
	if err := verifyStateProofTreesDepth(s); err != nil {
		return err
	}

	nr := uint64(len(s.PositionsToReveal))
	if err := verifyWeights(s.SignedWeight, v.lnProvenWeight, nr, v.strengthTarget); err != nil {
		return err
	}

	version := s.MerkleSignatureSaltVersion
	for _, reveal := range s.Reveals {
		if err := reveal.SigSlot.Sig.ValidateSaltVersion(version); err != nil {
			return err
		}
	}

	sigs := make(map[uint64]crypto.Hashable)
	parts := make(map[uint64]crypto.Hashable)

	for pos, r := range s.Reveals {
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
			&r.SigSlot.Sig,
		)

		if err != nil {
			return fmt.Errorf("signature in reveal pos %d does not verify. error is %w", pos, err)
		}
	}

	// verify all the reveals proofs on the signature commitment.
	if err := merklearray.VerifyVectorCommitment(s.SigCommit[:], sigs, &s.SigProofs); err != nil {
		return err
	}

	// verify all the reveals proofs on the participant commitment.
	if err := merklearray.VerifyVectorCommitment(v.participantsCommitment[:], parts, &s.PartProofs); err != nil {
		return err
	}

	choice := coinChoiceSeed{
		partCommitment: v.participantsCommitment,
		lnProvenWeight: v.lnProvenWeight,
		sigCommitment:  s.SigCommit,
		signedWeight:   s.SignedWeight,
		data:           data,
	}

	coinHash := makeCoinGenerator(&choice)
	for j := uint64(0); j < nr; j++ {
		pos := s.PositionsToReveal[j]
		reveal, exists := s.Reveals[pos]
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

func verifyStateProofTreesDepth(s *StateProof) error {
	if s.SigProofs.TreeDepth > MaxTreeDepth {
		return fmt.Errorf("%w. sigTree depth is %d", ErrTreeDepthTooLarge, s.SigProofs.TreeDepth)
	}

	if s.PartProofs.TreeDepth > MaxTreeDepth {
		return fmt.Errorf("%w. partTree depth is %d", ErrTreeDepthTooLarge, s.PartProofs.TreeDepth)
	}

	return nil
}
