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
	"github.com/algorand/go-algorand/crypto"
)

// Proof is used to convince a verifier about membership of leaves: h0,h1...hn
// at indexes i0,i1...in on a tree. The verifier has a trusted value of the tree
// root hash.
type Proof struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Path is bounded by MaxNumLeaves since there could be multiple reveals, and
	// given the distribution of the elt positions and the depth of the tree,
	// the path length can increase up to 2^MaxTreeDepth / 2
	Path        []crypto.GenericDigest `codec:"pth,allocbound=MaxNumLeaves/2"`
	HashFactory crypto.HashFactory     `codec:"hsh"`
	// TreeDepth represents the depth of the tree that is being proven.
	// the root level is not included
	TreeDepth uint8 `codec:"td"`
}

// GetSerializedProof serializes the proof into a sequence of bytes.
// it basically concatenates all the verification path one after another.
// The function returns a fixed length array for each hash function. which is 1 + MaxTreeDepth * digestsize
//
// the path is guaranteed to be less than MaxTreeDepth and if the path length is less
// than MaxTreeDepth, array is padded with zeros.
// more details could be found in the Algorand's spec.
func (p *Proof) GetSerializedProof() []byte {
	hash := p.HashFactory.NewHash()

	var binProof = make([]byte, 0, 1+(MaxTreeDepth*hash.Size()))

	proofLenByte := p.TreeDepth
	binProof = append(binProof, proofLenByte)

	zeroDigest := make([]byte, hash.Size())
	for i := uint8(0); i < MaxTreeDepth; i++ {
		if i < proofLenByte && p.Path[i] != nil {
			binProof = append(binProof, p.Path[i]...)
		} else {
			binProof = append(binProof, zeroDigest...)
		}
	}

	return binProof
}
