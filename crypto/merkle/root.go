// Copyright (C) 2019-2021 Algorand, Inc.
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

package merkle

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
)

// Root returns the root of a merkle tree with the leaves given as input
func Root(leaves [][]byte) crypto.Digest {
	mt := NewInMemoryMerkleTree(DefaultHasher)
	for _, leaf := range leaves {
		mt.AddLeaf(leaf)
	}
	root := mt.CurrentRoot().Hash()
	var out crypto.Digest
	if len(out[:]) != len(root) {
		logging.Base().Panicf("merkleRoot: merkle root hash not the same length as a crypto.Digest: %v != %v", len(root), len(out[:]))
	}
	copy(out[:], root)
	return out
}

// Order returns whether one byte slice is greater than another it returns true if a < b
func Order(a, b []byte) bool {
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return true
		}
		if b[i] < a[i] {
			return false
		}
	}
	return true // eq
}
