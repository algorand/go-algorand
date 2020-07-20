package merklearray

import (
	"fmt"
	"sort"

	"github.com/algorand/go-algorand/crypto"
)

// siblings represents the siblings needed to compute the root hash
// given a set of leaf nodes.  This data structure can operate in two
// modes: either build up the set of sibling hints, if tree is not nil,
// or use the set of sibling hints, if tree is nil.
type siblings struct {
	tree  *Tree
	hints []crypto.Digest
}

// get returns the sibling from tree level l (0 being the leaves)
// position i.
func (s *siblings) get(l uint64, i uint64) (res crypto.Digest, err error) {
	if s.tree == nil {
		if len(s.hints) > 0 {
			res = s.hints[0]
			s.hints = s.hints[1:]
			return
		}

		err = fmt.Errorf("no more sibling hints")
		return
	}

	if l >= uint64(len(s.tree.levels)) {
		err = fmt.Errorf("level %d beyond tree height %d", l, len(s.tree.levels))
		return
	}

	if i < uint64(len(s.tree.levels[l])) {
		res = s.tree.levels[l][i]
	}

	s.hints = append(s.hints, res)
	return
}

// partialLayer represents a subset of a layer (i.e., nodes at some
// level in the Merkle tree).
type partialLayer map[uint64]crypto.Digest

// up takes a partial layer at level l, and returns the next-higher (partial)
// level in the tree.  Since the layer is partial, up() requires siblings.
//
// The implementation is deterministic to ensure that up() asks for siblings
// in the same order both when generating a proof, as well as when checking
// the proof.
//
// If doHash is false, fill in zero hashes, which suffices for constructing
// a proof.
func (pl partialLayer) up(s *siblings, l uint64, doHash bool) (partialLayer, error) {
	positions := make([]uint64, 0, len(pl))
	for pos := range pl {
		positions = append(positions, pos)
	}
	sort.Slice(positions, func(i, j int) bool { return positions[i] < positions[j] })

	res := make(partialLayer)
	for i := 0; i < len(positions); i++ {
		pos := positions[i]
		posHash := pl[pos]

		siblingPos := pos ^ 1
		siblingHash, ok := pl[siblingPos]
		if ok {
			// If our sibling is also in the partial layer, use its
			// hash (and skip over its position).
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
		var nextLayerHash crypto.Digest

		if doHash {
			var p pair
			if pos&1 == 0 {
				// We are left
				p.l = posHash
				p.r = siblingHash
			} else {
				// We are right
				p.l = siblingHash
				p.r = posHash
			}
			nextLayerHash = crypto.HashObj(&p)
		}

		res[nextLayerPos] = nextLayerHash
	}

	return res, nil
}
