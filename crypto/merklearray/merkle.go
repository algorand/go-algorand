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
	"bytes"
	"fmt"
	"sort"

	"github.com/algorand/go-algorand/crypto"
)

// Tree is a Merkle tree, represented by layers of nodes (hashes) in the tree
// at each height.
type Tree struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Level 0 is the leaves.
	Levels []Layer            `codec:"lvls,allocbound=-"`
	Hash   crypto.HashFactory `codec:"hsh"`
}

func (tree *Tree) topLayer() Layer {
	return tree.Levels[len(tree.Levels)-1]
}

type errorChannel chan error

func (ch errorChannel) nonBlockingSend(e error) {
	select {
	case ch <- e:
	default:
	}
}

func buildWorker(ws *workerState, array Array, leaves Layer, h crypto.HashFactory, errs errorChannel) {
	defer ws.done()
	ws.started()
	batchSize := uint64(1)
	hash, err := h.NewHash()
	if err != nil {
		errs.nonBlockingSend(err)
		return
	}
	for {
		off := ws.next(batchSize)
		if off >= ws.maxidx {
			return
		}

		for i := off; i < off+batchSize && i < ws.maxidx; i++ {
			m, err := array.Marshal(i)
			if err != nil {
				errs.nonBlockingSend(err)
				return
			}
			leaves[i] = crypto.HashBytes(hash, m)
		}

		batchSize++
	}
}

// Build constructs a Merkle tree given an array.
func Build(array Array, factory crypto.HashFactory) (*Tree, error) {
	arraylen := array.Length()
	leaves := make(Layer, arraylen)
	errs := make(chan error, 1)

	ws := newWorkerState(arraylen)
	for ws.nextWorker() {
		go buildWorker(ws, array, leaves, factory, errs)
	}
	ws.wait()

	select {
	case err := <-errs:
		return nil, err
	default:
	}

	tree := &Tree{
		Levels: nil,
		Hash:   factory,
	}

	if arraylen > 0 {
		tree.Levels = []Layer{leaves}

		for len(tree.topLayer()) > 1 {
			tree.Levels = append(tree.Levels, tree.up())
		}
	}

	return tree, nil
}

// Root returns the root hash of the tree.
func (tree *Tree) Root() TreeDigest {
	// Special case: commitment to zero-length array
	if len(tree.Levels) == 0 {
		return Digest{}
	}

	return tree.topLayer()[0]
}

const validateProof = false

// Prove constructs a proof for some set of positions in the array that was
// used to construct the tree.
func (tree *Tree) Prove(idxs []uint64) (*Proof, error) {
	if len(idxs) == 0 {
		return &Proof{
			HashFactory: crypto.HashFactory{},
		}, nil
	}

	// Special case: commitment to zero-length array
	if len(tree.Levels) == 0 {
		return nil, fmt.Errorf("proving in zero-length commitment")
	}

	sort.Slice(idxs, func(i, j int) bool { return idxs[i] < idxs[j] })

	pl := make(partialLayer, 0, len(idxs))
	for _, pos := range idxs {
		if pos >= uint64(len(tree.Levels[0])) {
			return nil, fmt.Errorf("pos %d larger than leaf count %d", pos, len(tree.Levels[0]))
		}

		// Discard duplicates
		if len(pl) > 0 && pl[len(pl)-1].pos == pos {
			continue
		}

		pl = append(pl, layerItem{
			pos:  pos,
			hash: tree.Levels[0][pos],
		})
	}

	s := &siblings{
		tree: tree,
	}
	hs, err := tree.Hash.NewHash()
	if err != nil {
		return nil, err
	}
	for l := uint64(0); l < uint64(len(tree.Levels)-1); l++ {
		var err error
		pl, err = pl.up(s, l, validateProof, hs)
		if err != nil {
			return nil, err
		}
	}

	// Confirm that we got the same root hash
	if len(pl) != 1 {
		return nil, fmt.Errorf("internal error: partial Layer produced %d hashes", len(pl))
	}

	if validateProof {
		computedroot := pl[0]
		if computedroot.pos != 0 || !bytes.Equal(computedroot.hash, tree.topLayer()[0]) {
			return nil, fmt.Errorf("internal error: root mismatch during proof")
		}
	}

	return &Proof{
		Path:        s.hints,
		HashFactory: tree.Hash,
	}, nil
}

// Verify ensures that the positions in elems correspond to the respective hashes
// in a tree with the given root hash.  The proof is expected to be the proof
// returned by Prove().
func Verify(root TreeDigest, elems map[uint64]Digest, proof *Proof) error {
	if len(elems) == 0 {
		if proof == nil || len(proof.Path) != 0 {
			return fmt.Errorf("non-empty proof for empty set of elements")
		}

		return nil
	}

	pl := make(partialLayer, 0, len(elems))
	for pos, elem := range elems {
		pl = append(pl, layerItem{
			pos:  pos,
			hash: elem.ToSlice(),
		})
	}

	sort.Slice(pl, func(i, j int) bool { return pl[i].pos < pl[j].pos })

	return verify(root, proof, pl)
}

func verify(root TreeDigest, proof *Proof, pl partialLayer) error {
	if proof == nil {
		return inspectRoot(root, pl)
	}

	hints := proof.Path
	hsh, err := proof.HashFactory.NewHash()
	if err != nil {
		return err
	}

	s := &siblings{
		hints: hints,
	}

	for l := uint64(0); len(s.hints) > 0 || len(pl) > 1; l++ {
		if pl, err = pl.up(s, l, true, hsh); err != nil {
			return err
		}

		if l > 64 {
			return fmt.Errorf("Verify exceeded 64 Levels, more than 2^64 leaves not supported")
		}
	}

	return inspectRoot(root, pl)
}

func inspectRoot(root TreeDigest, pl partialLayer) error {
	computedroot := pl[0]
	if computedroot.pos != 0 || !bytes.Equal(computedroot.hash[:], root.ToSlice()) {
		return fmt.Errorf("root mismatch")
	}
	return nil
}
