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

package merklearray

import (
	"fmt"
	"sort"

	"github.com/algorand/go-algorand/crypto"
)

// Tree is a Merkle tree, represented by layers of nodes (hashes) in the tree
// at each height.
type Tree struct {
	// Level 0 is the leaves.
	levels []layer
}

func (tree *Tree) topLayer() layer {
	return tree.levels[len(tree.levels)-1]
}

func buildWorker(ws *workerState, array Array, leaves layer, errs chan error) {
	ws.started()
	batchSize := uint64(1)

	for {
		off := ws.next(batchSize)
		if off >= ws.maxidx {
			goto done
		}

		for i := off; i < off+batchSize && i < ws.maxidx; i++ {
			hash, err := array.GetHash(i)
			if err != nil {
				select {
				case errs <- err:
				default:
				}

				goto done
			}

			leaves[i] = hash
		}

		batchSize++
	}

done:
	ws.done()
}

// Build constructs a Merkle tree given an array.
func Build(array Array) (*Tree, error) {
	arraylen := array.Length()
	leaves := make(layer, arraylen)
	errs := make(chan error, 1)

	ws := newWorkerState(arraylen)
	for ws.nextWorker() {
		go buildWorker(ws, array, leaves, errs)
	}
	ws.wait()

	select {
	case err := <-errs:
		return nil, err
	default:
	}

	tree := &Tree{}

	if arraylen > 0 {
		tree.levels = []layer{leaves}

		for len(tree.topLayer()) > 1 {
			tree.levels = append(tree.levels, tree.topLayer().up())
		}
	}

	return tree, nil
}

// Root returns the root hash of the tree.
func (tree *Tree) Root() crypto.Digest {
	// Special case: commitment to zero-length array
	if len(tree.levels) == 0 {
		var zero crypto.Digest
		return zero
	}

	return tree.topLayer()[0]
}

const validateProof = false

// Prove constructs a proof for some set of positions in the array that was
// used to construct the tree.
func (tree *Tree) Prove(idxs []uint64) ([]crypto.Digest, error) {
	if len(idxs) == 0 {
		return nil, nil
	}

	// Special case: commitment to zero-length array
	if len(tree.levels) == 0 {
		return nil, fmt.Errorf("proving in zero-length commitment")
	}

	sort.Slice(idxs, func(i, j int) bool { return idxs[i] < idxs[j] })

	pl := make(partialLayer, 0, len(idxs))
	for _, pos := range idxs {
		if pos >= uint64(len(tree.levels[0])) {
			return nil, fmt.Errorf("pos %d larger than leaf count %d", pos, len(tree.levels[0]))
		}

		// Discard duplicates
		if len(pl) > 0 && pl[len(pl)-1].pos == pos {
			continue
		}

		pl = append(pl, layerItem{
			pos:  pos,
			hash: tree.levels[0][pos],
		})
	}

	s := &siblings{
		tree: tree,
	}

	for l := uint64(0); l < uint64(len(tree.levels)-1); l++ {
		var err error
		pl, err = pl.up(s, l, validateProof)
		if err != nil {
			return nil, err
		}
	}

	// Confirm that we got the same root hash
	if len(pl) != 1 {
		return nil, fmt.Errorf("internal error: partial layer produced %d hashes", len(pl))
	}

	if validateProof {
		computedroot := pl[0]
		if computedroot.pos != 0 || computedroot.hash != tree.topLayer()[0] {
			return nil, fmt.Errorf("internal error: root mismatch during proof")
		}
	}

	return s.hints, nil
}

// Verify ensures that the positions in elems correspond to the hashes of their respective
// crypto.Hashable objects in a tree with the given root hash.  The proof is expected to
// be the proof returned by Prove().
func Verify(root crypto.Digest, elems map[uint64]crypto.Hashable, proof []crypto.Digest) error {
	if len(elems) == 0 {
		if len(proof) != 0 {
			return fmt.Errorf("non-empty proof for empty set of elements")
		}

		return nil
	}

	pl := make(partialLayer, 0, len(elems))
	for pos, elem := range elems {
		pl = append(pl, layerItem{
			pos:  pos,
			hash: crypto.HashObj(elem),
		})
	}

	sort.Slice(pl, func(i, j int) bool { return pl[i].pos < pl[j].pos })

	s := &siblings{
		hints: proof,
	}

	for l := uint64(0); len(s.hints) > 0 || len(pl) > 1; l++ {
		var err error
		pl, err = pl.up(s, l, true)
		if err != nil {
			return err
		}

		if l > 64 {
			return fmt.Errorf("Verify exceeded 64 levels, more than 2^64 leaves not supported")
		}
	}

	computedroot := pl[0]
	if computedroot.pos != 0 || computedroot.hash != root {
		return fmt.Errorf("root mismatch")
	}

	return nil
}
