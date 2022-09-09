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

package merklearray

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
)

// Proof is used to convince a verifier about membership of leaves: h0,h1...hn
// at indexes i0,i1...in on a tree. The verifier has a trusted value of the tree
// root hash.
type Proof struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Path is bounded by MaxNumLeavesOnEncodedTree since there could be multiple reveals, and
	// given the distribution of the elt positions and the depth of the tree,
	// the path length can increase up to 2^MaxEncodedTreeDepth / 2
	Path        []crypto.GenericDigest `codec:"pth,allocbound=MaxNumLeavesOnEncodedTree/2"`
	HashFactory crypto.HashFactory     `codec:"hsh"`
	// TreeDepth represents the depth of the tree that is being proven.
	// It is the number of edges from the root to a leaf.
	TreeDepth uint8 `codec:"td"`
}

// SingleLeafProof is used to convince a verifier about membership of a specific
// leaf h at index i on a tree. The verifier has a trusted value of the tree
// root hash. it corresponds to merkle verification path.
type SingleLeafProof struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Proof
}

// GetFixedLengthHashableRepresentation serializes the proof into a sequence of bytes.
// it basically concatenates the elements of the verification path one after another.
// The function returns a fixed length array for each hash function. which is 1 + MaxEncodedTreeDepth * digestsize
//
// the path is guaranteed to be less than MaxEncodedTreeDepth and if the path length is less
// than MaxEncodedTreeDepth, array will have leading zeros (to fill the array to MaxEncodedTreeDepth * digestsize).
// more details could be found in the Algorand's spec.
func (p *SingleLeafProof) GetFixedLengthHashableRepresentation() []byte {
	hash := p.HashFactory.NewHash()

	var binProof = make([]byte, 0, 1+(MaxEncodedTreeDepth*hash.Size()))

	proofLenByte := p.TreeDepth
	binProof = append(binProof, proofLenByte)

	zeroDigest := make([]byte, hash.Size())

	for i := uint8(0); i < (MaxEncodedTreeDepth - proofLenByte); i++ {
		binProof = append(binProof, zeroDigest...)
	}

	for i := uint8(0); i < proofLenByte; i++ {
		if i < proofLenByte && p.Path[i] != nil {
			binProof = append(binProof, p.Path[i]...)
		} else {
			binProof = append(binProof, zeroDigest...)
		}
	}

	return binProof
}

// ToProof export a Proof from a SingleProof. The result is
// used as an input for merklearray.Verify or merklearray.VerifyVectorCommitment
func (p *SingleLeafProof) ToProof() *Proof {
	return &p.Proof
}

// GetConcatenatedProof concatenates the verification path to a single slice
// This function converts an empty element in the path (i.e occurs when the tree is not a full tree)
// into a sequence of digest result of zero.
func (p *SingleLeafProof) GetConcatenatedProof() []byte {
	digestSize := p.HashFactory.NewHash().Size()
	proofconcat := make([]byte, digestSize*int(p.TreeDepth))
	for i := 0; i < int(p.TreeDepth); i++ {
		if p.Path[i] != nil {
			copy(proofconcat[i*digestSize:(i+1)*digestSize], p.Path[i])
		}
	}
	return proofconcat
}

// ProofDataToSingleLeafProof receives serialized proof data and uses it to construct a proof object.
func ProofDataToSingleLeafProof(hashTypeData string, treeDepth uint64, proofBytes []byte) (SingleLeafProof, error) {
	hashType, err := crypto.UnmarshalHashType(hashTypeData)
	if err != nil {
		return SingleLeafProof{}, err
	}

	var proof SingleLeafProof

	proof.HashFactory = crypto.HashFactory{HashType: hashType}
	proof.TreeDepth = uint8(treeDepth)

	digestSize := proof.HashFactory.NewHash().Size()
	if len(proofBytes)%digestSize != 0 {
		return SingleLeafProof{}, fmt.Errorf("proof bytes length is %d, which is not a multiple of "+
			"digest size %d: %w", len(proofBytes), digestSize, ErrProofLengthDigestSizeMismatch)
	}

	var proofPath []crypto.GenericDigest
	for len(proofBytes) > 0 {
		d := make([]byte, digestSize)
		copy(d[:], proofBytes)
		proofPath = append(proofPath, d[:])
		proofBytes = proofBytes[len(d):]
	}

	proof.Path = proofPath
	return proof, nil
}
