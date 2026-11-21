// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
)

// ErrUnexpectedPathLength is returned for a Merkle proof with more path elements than its tree can need,
// or whose path length does not fit its TreeDepth.
var ErrUnexpectedPathLength = errors.New("unexpected number of Merkle path elements")

// CheckMerklePathLengths bounds the path length of each Merkle proof in s.
func (s *StateProof) CheckMerklePathLengths() error {
	if err := checkMultiLeafProofPath(&s.SigProofs, len(s.Reveals)); err != nil {
		return fmt.Errorf("SigProofs: %w", err)
	}
	if err := checkMultiLeafProofPath(&s.PartProofs, len(s.Reveals)); err != nil {
		return fmt.Errorf("PartProofs: %w", err)
	}
	for pos, r := range s.Reveals {
		if err := checkRevealedSignatureProofPath(&r.SigSlot.Sig); err != nil {
			return fmt.Errorf("reveal %d: %w", pos, err)
		}
	}
	return nil
}

// checkRevealedSignatureProofPath bounds the proof of a signature revealed in
// a state proof, which is checked during block validation. It does not ask for
// exactly TreeDepth elements, to stay compatible with what block validation
// has accepted. A path shorter than TreeDepth is refused by every node already.
func checkRevealedSignatureProofPath(sig *merklesignature.Signature) error {
	if sig.Proof.TreeDepth > merklearray.MaxEncodedTreeDepth {
		return fmt.Errorf("%w: signature proof TreeDepth %d, maximum %d",
			ErrTreeDepthTooLarge, sig.Proof.TreeDepth, merklearray.MaxEncodedTreeDepth)
	}
	if len(sig.Proof.Path) > merklearray.MaxEncodedTreeDepth {
		return fmt.Errorf("%w: signature proof has %d path elements, maximum %d",
			ErrUnexpectedPathLength, len(sig.Proof.Path), merklearray.MaxEncodedTreeDepth)
	}
	if int(sig.Proof.TreeDepth) > len(sig.Proof.Path) {
		return fmt.Errorf("%w: signature proof has %d path elements for TreeDepth %d",
			ErrUnexpectedPathLength, len(sig.Proof.Path), sig.Proof.TreeDepth)
	}
	return nil
}

func checkMultiLeafProofPath(p *merklearray.Proof, numLeaves int) error {
	if uint64(len(p.Path)) > uint64(numLeaves)*uint64(p.TreeDepth) {
		return fmt.Errorf("%w: %d path elements for %d leaves at TreeDepth %d",
			ErrUnexpectedPathLength, len(p.Path), numLeaves, p.TreeDepth)
	}
	return nil
}

// checkSignatureProofPath requires the proof an honest signer produces, with
// exactly TreeDepth path elements. It is for signatures this node would build
// a state proof from, where being strict decides no block's validity.
func checkSignatureProofPath(sig *merklesignature.Signature) error {
	if sig.Proof.TreeDepth > merklearray.MaxEncodedTreeDepth {
		return fmt.Errorf("%w: signature proof TreeDepth %d, maximum %d",
			ErrTreeDepthTooLarge, sig.Proof.TreeDepth, merklearray.MaxEncodedTreeDepth)
	}
	if len(sig.Proof.Path) != int(sig.Proof.TreeDepth) {
		return fmt.Errorf("%w: signature proof has %d path elements for TreeDepth %d",
			ErrUnexpectedPathLength, len(sig.Proof.Path), sig.Proof.TreeDepth)
	}
	return nil
}
