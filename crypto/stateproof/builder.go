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
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
)

// Errors for the StateProof builder
var (
	ErrPositionOutOfBound     = errors.New("requested position is out of bounds")
	ErrPositionAlreadyPresent = errors.New("requested position is already present")
	ErrPositionWithZeroWeight = errors.New("position has zero weight")
	ErrCoinIndexError         = errors.New("could not find corresponding index for a given coin")
)

// VotersAllocBound should be equal to config.Consensus[protocol.ConsensusCurrentVersion].StateProofTopVoters
const VotersAllocBound = 1024

// BuilderPersistedFields is the set of fields of a Builder that are persisted to disk.
type BuilderPersistedFields struct {
	_struct        struct{}             `codec:",omitempty,omitemptyarray"`
	Data           MessageHash          `codec:"data"`
	Round          uint64               `codec:"rnd"`
	Participants   []basics.Participant `codec:"parts,allocbound=VotersAllocBound"`
	Parttree       *merklearray.Tree    `codec:"parttree"`
	LnProvenWeight uint64               `codec:"lnprv"`
	ProvenWeight   uint64               `codec:"prv"`
	StrengthTarget uint64               `codec:"str"`
}

// Builder keeps track of signatures on a message and eventually produces
// a state proof for that message.
type Builder struct {
	BuilderPersistedFields
	sigs         []sigslot // Indexed by pos in Participants
	signedWeight uint64    // Total weight of signatures so far
	cachedProof  *StateProof
}

// MakeBuilder constructs an empty builder. After adding enough signatures and signed weight, this builder is used to create a stateproof.
func MakeBuilder(data MessageHash, round uint64, provenWeight uint64, part []basics.Participant, parttree *merklearray.Tree, strengthTarget uint64) (*Builder, error) {
	npart := len(part)
	lnProvenWt, err := LnIntApproximation(provenWeight)
	if err != nil {
		return nil, err
	}

	b := &Builder{
		BuilderPersistedFields: BuilderPersistedFields{
			Data:           data,
			Round:          round,
			Participants:   part,
			Parttree:       parttree,
			LnProvenWeight: lnProvenWt,
			ProvenWeight:   provenWeight,
			StrengthTarget: strengthTarget,
		},

		sigs:         make([]sigslot, npart),
		signedWeight: 0,
		cachedProof:  nil,
	}

	return b, nil
}

// Present checks if the builder already contains a signature at a particular
// offset.
func (b *Builder) Present(pos uint64) (bool, error) {
	if pos >= uint64(len(b.sigs)) {
		return false, fmt.Errorf("%w pos %d >= len(b.sigs) %d", ErrPositionOutOfBound, pos, len(b.sigs))
	}

	return b.sigs[pos].Weight != 0, nil
}

// IsValid verifies that the participant along with the signature can be inserted to the builder.
// verifySig can be set to false when the signature is already verified (e.g. loaded from the DB)
func (b *Builder) IsValid(pos uint64, sig *merklesignature.Signature, verifySig bool) error {
	if pos >= uint64(len(b.Participants)) {
		return fmt.Errorf("%w pos %d >= len(participants) %d", ErrPositionOutOfBound, pos, len(b.Participants))
	}

	p := b.Participants[pos]

	if p.Weight == 0 {
		return fmt.Errorf("builder.IsValid: %w: position = %d", ErrPositionWithZeroWeight, pos)
	}

	// Check signature
	if verifySig {
		if err := sig.ValidateSaltVersion(merklesignature.SchemeSaltVersion); err != nil {
			return err
		}
		if err := p.PK.VerifyBytes(b.Round, b.Data[:], sig); err != nil {
			return err
		}
	}
	return nil
}

// Add a signature to the set of signatures available for building a proof.
func (b *Builder) Add(pos uint64, sig merklesignature.Signature) error {
	isPresent, err := b.Present(pos)
	if err != nil {
		return err
	}
	if isPresent {
		return ErrPositionAlreadyPresent
	}

	p := b.Participants[pos]

	// Remember the signature
	b.sigs[pos].Weight = p.Weight
	b.sigs[pos].Sig = sig
	b.signedWeight += p.Weight
	b.cachedProof = nil // can rebuild a more optimized state proof
	return nil
}

// Ready returns whether the state proof is ready to be built.
func (b *Builder) Ready() bool {
	return b.cachedProof != nil || b.signedWeight > b.ProvenWeight
}

// SignedWeight returns the total weight of signatures added so far.
func (b *Builder) SignedWeight() uint64 {
	return b.signedWeight
}

// coinIndex returns the position pos in the sigs array such that the sum
// of all signature weights before pos is less than or equal to coinWeight,
// but the sum of all signature weights up to and including pos exceeds
// coinWeight.
//
// coinIndex works by doing a binary search on the sigs array.
func (b *Builder) coinIndex(coinWeight uint64) (uint64, error) {
	lo := uint64(0)
	hi := uint64(len(b.sigs))

again:
	if lo >= hi {
		return 0, fmt.Errorf("%w: lo %d >= hi %d and coin %d", ErrCoinIndexError, lo, hi, coinWeight)
	}

	mid := (lo + hi) / 2
	if coinWeight < b.sigs[mid].L {
		hi = mid
		goto again
	}

	if coinWeight < b.sigs[mid].L+b.sigs[mid].Weight {
		return mid, nil
	}

	lo = mid + 1
	goto again
}

// Build returns a state proof, if the builder has accumulated
// enough signatures to construct it.
func (b *Builder) Build() (*StateProof, error) {
	if b.cachedProof != nil {
		return b.cachedProof, nil
	}

	if !b.Ready() {
		return nil, fmt.Errorf("%w: %d <= %d", ErrSignedWeightLessThanProvenWeight, b.signedWeight, b.ProvenWeight)
	}

	// Commit to the sigs array
	for i := 1; i < len(b.sigs); i++ {
		b.sigs[i].L = b.sigs[i-1].L + b.sigs[i-1].Weight
	}

	hfactory := crypto.HashFactory{HashType: HashType}
	sigtree, err := merklearray.BuildVectorCommitmentTree(committableSignatureSlotArray(b.sigs), hfactory)
	if err != nil {
		return nil, err
	}

	// Reveal sufficient number of signatures
	s := &StateProof{
		SigCommit:                  sigtree.Root(),
		SignedWeight:               b.signedWeight,
		Reveals:                    make(map[uint64]Reveal),
		MerkleSignatureSaltVersion: merklesignature.SchemeSaltVersion,
	}

	nr, err := numReveals(b.signedWeight, b.LnProvenWeight, b.StrengthTarget)
	if err != nil {
		return nil, err
	}

	choice := coinChoiceSeed{
		partCommitment: b.Parttree.Root(),
		lnProvenWeight: b.LnProvenWeight,
		sigCommitment:  s.SigCommit,
		signedWeight:   s.SignedWeight,
		data:           b.Data,
	}

	coinHash := makeCoinGenerator(&choice)

	var proofPositions []uint64
	revealsSequence := make([]uint64, nr)
	for j := uint64(0); j < nr; j++ {
		coin := coinHash.getNextCoin()
		pos, err := b.coinIndex(coin)
		if err != nil {
			return nil, err
		}

		if pos >= uint64(len(b.Participants)) {
			return nil, fmt.Errorf("%w pos %d >= len(participants) %d", ErrPositionOutOfBound, pos, len(b.Participants))
		}

		revealsSequence[j] = pos

		// If we already revealed pos, no need to do it again
		_, alreadyRevealed := s.Reveals[pos]
		if alreadyRevealed {
			continue
		}

		// Generate the reveal for pos
		s.Reveals[pos] = Reveal{
			SigSlot: b.sigs[pos].sigslotCommit,
			Part:    b.Participants[pos],
		}

		proofPositions = append(proofPositions, pos)
	}

	sigProofs, err := sigtree.Prove(proofPositions)
	if err != nil {
		return nil, err
	}

	partProofs, err := b.Parttree.Prove(proofPositions)
	if err != nil {
		return nil, err
	}

	s.SigProofs = *sigProofs
	s.PartProofs = *partProofs
	s.PositionsToReveal = revealsSequence
	b.cachedProof = s
	return s, nil
}

// AllocSigs should only be used after decoding msgpacked Builder, as the sigs field is not exported and encoded
func (b *Builder) AllocSigs() {
	b.sigs = make([]sigslot, len(b.Participants))
}
