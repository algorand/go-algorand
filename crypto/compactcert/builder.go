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
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
)

//msgp:ignore sigslot
type sigslot struct {
	// Weight is the weight of the participant signing this message.
	// This information is tracked here for convenience, but it does
	// not appear in the commitment to the sigs array; it comes from
	// the Weight field of the corresponding participant.
	Weight uint64

	// Include the parts of the sigslot that form the commitment to
	// the sigs array.
	sigslotCommit
}

// Builder keeps track of signatures on a message and eventually produces
// a compact certificate for that message.
type Builder struct {
	data           StateProofMessageHash
	round          uint64
	sigs           []sigslot // Indexed by pos in participants
	signedWeight   uint64    // Total weight of signatures so far
	participants   []basics.Participant
	parttree       *merklearray.Tree
	lnProvenWeight uint64
	provenWeight   uint64
	strengthTarget uint64
}

// Errors for the CompactCert builder
var (
	ErrPositionOutOfBound     = errors.New("requested position is out of bound")
	ErrPositionWithZeroWeight = errors.New("position has zero weight")
	ErrInternalCoinIndexError = errors.New("error while calculate coin to index")
)

// MkBuilder constructs an empty builder. After adding enough signatures and signed weight, this builder is used to create a compact cert.
func MkBuilder(data StateProofMessageHash, round uint64, provenWeight uint64, part []basics.Participant, parttree *merklearray.Tree, strengthTarget uint64) (*Builder, error) {
	npart := len(part)
	lnProvenWt, err := lnIntApproximation(provenWeight)
	if err != nil {
		return nil, err
	}

	b := &Builder{
		data:           data,
		round:          round,
		sigs:           make([]sigslot, npart),
		signedWeight:   0,
		participants:   part,
		parttree:       parttree,
		lnProvenWeight: lnProvenWt,
		provenWeight:   provenWeight,
		strengthTarget: strengthTarget,
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
func (b *Builder) IsValid(pos uint64, sig merklesignature.Signature, verifySig bool) error {
	if pos >= uint64(len(b.participants)) {
		return fmt.Errorf("%w pos %d >= len(participants) %d", ErrPositionOutOfBound, pos, len(b.participants))
	}

	p := b.participants[pos]

	if p.Weight == 0 {
		return fmt.Errorf("%w :position %d", ErrPositionWithZeroWeight, pos)
	}

	// Check signature
	if verifySig {
		if err := sig.IsSaltVersionEqual(merklesignature.SchemeSaltVersion); err != nil {
			return err
		}

		cpy := make([]byte, len(b.data))
		copy(cpy, b.data[:]) // TODO: once cfalcon is fixed can remove this copy.
		if err := p.PK.VerifyBytes(b.round, cpy, sig); err != nil {
			return err
		}
	}
	return nil
}

// Add a signature to the set of signatures available for building a certificate.
func (b *Builder) Add(pos uint64, sig merklesignature.Signature) error {
	if isPresent, err := b.Present(pos); err != nil || isPresent {
		return err
	}
	p := b.participants[pos]

	// Remember the signature
	b.sigs[pos].Weight = p.Weight
	b.sigs[pos].Sig = sig
	b.signedWeight += p.Weight
	return nil
}

// Ready returns whether the certificate is ready to be built.
func (b *Builder) Ready() bool {
	return b.signedWeight > b.provenWeight
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
		return 0, fmt.Errorf("%w: lo %d >= hi %d", ErrInternalCoinIndexError, lo, hi)
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

// Build returns a compact certificate, if the builder has accumulated
// enough signatures to construct it.
func (b *Builder) Build() (*Cert, error) {

	if b.signedWeight <= b.provenWeight {
		return nil, fmt.Errorf("%w: %d <= %d", ErrSignedWeightLessThanProvenWeight, b.signedWeight, b.provenWeight)
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
	c := &Cert{
		SigCommit:                  sigtree.Root(),
		SignedWeight:               b.signedWeight,
		Reveals:                    make(map[uint64]Reveal),
		MerkleSignatureSaltVersion: merklesignature.SchemeSaltVersion,
	}

	nr, err := numReveals(b.signedWeight, b.lnProvenWeight, b.strengthTarget)
	if err != nil {
		return nil, err
	}

	choice := coinChoiceSeed{
		partCommitment: b.parttree.Root(),
		lnProvenWeight: b.lnProvenWeight,
		sigCommitment:  c.SigCommit,
		signedWeight:   c.SignedWeight,
		data:           b.data,
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

		if pos >= uint64(len(b.participants)) {
			return nil, fmt.Errorf("%w pos %d >= len(participants) %d", ErrPositionOutOfBound, pos, len(b.participants))
		}

		revealsSequence[j] = pos

		// If we already revealed pos, no need to do it again
		_, alreadyRevealed := c.Reveals[pos]
		if alreadyRevealed {
			continue
		}

		// Generate the reveal for pos
		c.Reveals[pos] = Reveal{
			SigSlot: b.sigs[pos].sigslotCommit,
			Part:    b.participants[pos],
		}

		proofPositions = append(proofPositions, pos)
	}

	sigProofs, err := sigtree.Prove(proofPositions)
	if err != nil {
		return nil, err
	}

	partProofs, err := b.parttree.Prove(proofPositions)
	if err != nil {
		return nil, err
	}

	c.SigProofs = *sigProofs
	c.PartProofs = *partProofs
	c.PositionsToReveal = revealsSequence

	return c, nil
}
