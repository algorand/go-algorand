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
	if c.SignedWeight <= v.ProvenWeight {
		return fmt.Errorf("cert signed weight %d <= proven weight %d", c.SignedWeight, v.ProvenWeight)
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

	// Verify that the reveals contain the right coins
	nr, err := v.numReveals(c.SignedWeight)
	if err != nil {
		return err
	}

	choice := coinChoiceSeed{
		SignedWeight: c.SignedWeight,
		ProvenWeight: v.ProvenWeight,
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
