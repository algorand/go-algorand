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

package merklearray

import (
	"fmt"
	"hash"

	"github.com/algorand/go-algorand/crypto"
)

// siblings represents the siblings needed to compute the root hash
// given a set of leaf nodes.  This data structure can operate in two
// modes: either build up the set of sibling hints, if tree is not nil,
// or use the set of sibling hints, if tree is nil.
type siblings struct {
	tree  *Tree
	hints []crypto.GenericDigest
}

// get returns the sibling from tree level l (0 being the leaves)
// position i.
func (s *siblings) get(l uint64, i uint64) (res crypto.GenericDigest, err error) {
	if s.tree == nil {
		if len(s.hints) > 0 {
			res = s.hints[0].ToSlice()
			s.hints = s.hints[1:]
			return
		}

		err = fmt.Errorf("no more sibling hints")
		return
	}

	if l >= uint64(len(s.tree.Levels)) {
		err = fmt.Errorf("level %d beyond tree height %d", l, len(s.tree.Levels))
		return
	}

	if i < uint64(len(s.tree.Levels[l])) {
		res = s.tree.Levels[l][i]
	}

	s.hints = append(s.hints, res)
	return
}

// partialLayer represents a subset of a Layer (i.e., nodes at some
// level in the Merkle tree).  layerItem represents one element in the
// partial Layer.
//
//msgp:ignore partialLayer
type partialLayer []layerItem

type layerItem struct {
	pos  uint64
	hash crypto.GenericDigest
}

// up takes a partial Layer at level l, and returns the next-higher (partial)
// level in the tree.  Since the Layer is partial, up() requires siblings.
//
// The implementation is deterministic to ensure that up() asks for siblings
// in the same order both when generating a proof, as well as when checking
// the proof.
//
// If doHash is false, fill in zero hashes, which suffices for constructing
// a proof.
func (pl partialLayer) up(s *siblings, l uint64, doHash bool, hsh hash.Hash) (partialLayer, error) {
	var res partialLayer
	for i := 0; i < len(pl); i++ {
		item := pl[i]
		pos := item.pos
		posHash := item.hash

		siblingPos := pos ^ 1
		var siblingHash crypto.GenericDigest
		if i+1 < len(pl) && pl[i+1].pos == siblingPos {
			// If our sibling is also in the partial Layer, use its
			// hash (and skip over its position).
			siblingHash = pl[i+1].hash
			i++
		} else {
			// Ask for the sibling hash from the tree / proof.
			var err error
			siblingHash, err = s.get(l, siblingPos)
			if err != nil {
				return nil, err
			}
		}

		nextLayerPos := pos / 2
		var nextLayerHash crypto.GenericDigest

		if doHash {
			var p pair
			p.hashDigestSize = hsh.Size()
			if pos&1 == 0 {
				// We are left
				p.l = posHash
				p.r = siblingHash
			} else {
				// We are right
				p.l = siblingHash
				p.r = posHash
			}
			nextLayerHash = crypto.GenericHashObj(hsh, &p)
		}

		res = append(res, layerItem{
			pos:  nextLayerPos,
			hash: nextLayerHash,
		})
	}

	return res, nil
}
