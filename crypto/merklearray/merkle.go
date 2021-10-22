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
	"hash"
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

// Proof contains the merkle path, along with the hash factory that should be used.
type Proof struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Path        []crypto.GenericDigest `codec:"pth,allocbound=-"`
	HashFactory crypto.HashFactory     `codec:"hsh"`
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
	defer ws.wg.Done()

	ws.started()
	batchSize := uint64(1)
	hash := h.NewHash()

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

	tree.buildLayers(leaves)
	return tree, nil
}

func (tree *Tree) buildLayers(leaves Layer) {
	if len(leaves) == 0 {
		return
	}
	tree.Levels = []Layer{leaves}
	for len(tree.topLayer()) > 1 {
		tree.buildNextLayer()
	}
}

// Root returns the root hash of the tree.
func (tree *Tree) Root() crypto.GenericDigest {
	// Special case: commitment to zero-length array
	if len(tree.Levels) == 0 {
		return crypto.GenericDigest{}
	}

	return tree.topLayer()[0]
}

const validateProof = false

// Prove constructs a proof for some set of positions in the array that was
// used to construct the tree.
func (tree *Tree) Prove(idxs []uint64) (*Proof, error) {
	if len(idxs) == 0 {
		return &Proof{
			HashFactory: tree.Hash,
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
	hs := tree.Hash.NewHash()

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
		if err := inspectRoot(tree.topLayer()[0], pl); err != nil {
			return nil, err
		}
	}

	return &Proof{
		Path:        s.hints,
		HashFactory: tree.Hash,
	}, nil
}

func (tree *Tree) buildNextLayer() {
	l := tree.topLayer()
	n := len(l)
	newLayer := make(Layer, (uint64(n)+1)/2)

	ws := newWorkerState(uint64(n))
	for ws.nextWorker() {
		// no need to inspect error here -
		// the factory should've been used to generate hash func in the first layer build
		go upWorker(ws, l, newLayer, tree.Hash.NewHash())
	}
	ws.wait()
	tree.Levels = append(tree.Levels, newLayer)
}

func hashLeafs(elems map[uint64]crypto.Hashable, hash hash.Hash) (map[uint64]crypto.GenericDigest, error) {

	hashedLeafs := make(map[uint64]crypto.GenericDigest)
	for i, element := range elems {
		hashedLeafs[i] = crypto.GenereicHashObj(hash, element)
	}

	return hashedLeafs, nil
}

// Verify ensures that the positions in elems correspond to the respective hashes
// in a tree with the given root hash.  The proof is expected to be the proof
// returned by Prove().
func Verify(root crypto.GenericDigest, elems map[uint64]crypto.Hashable, proof *Proof) error {

	if proof == nil {
		return fmt.Errorf("proof should not be nil")
	}

	if len(elems) == 0 {
		if len(proof.Path) != 0 {
			return fmt.Errorf("non-empty proof for empty set of elements")
		}
		return nil
	}

	hashedLeafs, err := hashLeafs(elems, proof.HashFactory.NewHash())
	if err != nil {
		return err
	}

	pl := buildPartialLayer(hashedLeafs)
	return verifyPath(root, proof, pl)
}

func verifyPath(root crypto.GenericDigest, proof *Proof, pl partialLayer) error {
	hints := proof.Path

	s := &siblings{
		hints: hints,
	}

	hsh := proof.HashFactory.NewHash()
	var err error
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

func buildPartialLayer(elems map[uint64]crypto.GenericDigest) partialLayer {
	pl := make(partialLayer, 0, len(elems))
	for pos, elem := range elems {
		pl = append(pl, layerItem{
			pos:  pos,
			hash: elem.ToSlice(),
		})
	}

	sort.Slice(pl, func(i, j int) bool { return pl[i].pos < pl[j].pos })
	return pl
}

func inspectRoot(root crypto.GenericDigest, pl partialLayer) error {
	computedroot := pl[0]
	if computedroot.pos != 0 || !bytes.Equal(computedroot.hash, root) {
		return fmt.Errorf("root mismatch")
	}
	return nil
}
