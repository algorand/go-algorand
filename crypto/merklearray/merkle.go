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
	"bytes"
	"errors"
	"fmt"
	"hash"
	"sort"

	"github.com/algorand/go-algorand/crypto"
)

const (
	// MaxTreeDepth is the maximum tree depth (root only depth 0)
	MaxTreeDepth = 16

	// MaxNumLeaves is the maximum number of leaves allowed in the tree
	MaxNumLeaves = 65536 // 2^MaxTreeDepth
)

// Merkle tree errors
var (
	ErrRootMismatch                  = errors.New("root mismatch")
	ErrProvingZeroCommitment         = errors.New("proving in zero-length commitment")
	ErrProofIsNil                    = errors.New("proof should not be nil")
	ErrNonEmptyProofForEmptyElements = errors.New("non-empty proof for empty set of elements")
	ErrTreeTooDeep                   = errors.New("proven tree is too deep")
	ErrTooManyVerificationLevels     = errors.New("Verify exceeded 64 Levels, more than 2^64 leaves not supported")
	ErrUnexpectedTreeDepth           = errors.New("unexpected tree depth")
	ErrPosOutOfBound                 = "pos %d larger than leaf count %d"
)

// Tree is a Merkle tree, represented by layers of nodes (hashes) in the tree
// at each height.
type Tree struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Level 0 is the leaves.
	Levels           []Layer            `codec:"lvls,allocbound=MaxTreeDepth+1"`
	NumOfLeaves      uint64             `codec:"nl"`
	Hash             crypto.HashFactory `codec:"hsh"`
	VectorCommitment bool               `codec:"vc"`
}

// Proof contains the merkle path, along with the hash factory that should be used.
type Proof struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Path is bounded by MaxNumLeaves since there could be multiple reveals, and
	// given the distribution of the elt positions and the depth of the tree,
	// the path length can increase up to 2^MaxTreeDepth / 2
	Path        []crypto.GenericDigest `codec:"pth,allocbound=MaxNumLeaves/2"`
	HashFactory crypto.HashFactory     `codec:"hsh"`
	// TreeDepth represents the depth of the tree that is being proven.
	// the root level does not included
	TreeDepth uint8 `codec:"td"`
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
			leaves[i] = crypto.GenereicHashObj(hash, m)
		}

		batchSize++
	}
}

// BuildVectorCommitmentTree constructs a Merkle tree given an array.
// the tree returned from this function can function as a vector commitment (has position binding property)
// In addition, the tree will also extend the array to have a length of 2^X leaves.
// i.e we always create a full tree
func BuildVectorCommitmentTree(array Array, factory crypto.HashFactory) (*Tree, error) {
	t, err := Build(generateVectorCommitmentArray(array), factory)
	if err != nil {
		return nil, err
	}
	t.VectorCommitment = true
	t.NumOfLeaves = array.Length()
	return t, nil
}

// Build constructs a Merkle tree given an array. The tree can be used to generate
// proofs of membership on element. If a proof of position is require, a Vector Commitments
// is required
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
		Levels:           nil,
		NumOfLeaves:      array.Length(),
		Hash:             factory,
		VectorCommitment: false,
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

// TODO: change into something global and more configurable
const validateProof = false

// Prove constructs a proof for some set of positions in the array that was
// used to construct the tree.
func (tree *Tree) Prove(idxs []uint64) (*Proof, error) {
	if len(idxs) == 0 {
		treeDepth := uint8(0)
		if len(tree.Levels) != 0 {
			treeDepth = uint8(len(tree.Levels)) - 1
		}
		return &Proof{
			HashFactory: tree.Hash,
			TreeDepth:   treeDepth,
		}, nil
	}

	// Special case: commitment to zero-length array
	if len(tree.Levels) == 0 || tree.NumOfLeaves == 0 {
		return nil, ErrProvingZeroCommitment
	}

	// verify that all positions where part of the original array
	for i := 0; i < len(idxs); i++ {
		if idxs[i] >= tree.NumOfLeaves {
			return nil, fmt.Errorf(ErrPosOutOfBound, idxs[i], tree.NumOfLeaves)
		}
	}

	if tree.VectorCommitment {
		vcIdxs := make([]uint64, len(idxs))
		for i := 0; i < len(idxs); i++ {
			idx, err := msbToLsbIndex(idxs[i], uint8(len(tree.Levels)-1))
			if err != nil {
				return nil, err
			}
			vcIdxs[i] = idx

		}
		idxs = vcIdxs
	}

	sort.Slice(idxs, func(i, j int) bool { return idxs[i] < idxs[j] })

	pl := make(partialLayer, 0, len(idxs))
	for _, pos := range idxs {
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
		TreeDepth:   uint8(len(tree.Levels) - 1),
	}, nil
}

func (tree *Tree) buildNextLayer() {
	l := tree.topLayer()
	n := len(l)
	newLayer := make(Layer, (uint64(n)+1)/2)

	ws := newWorkerState(uint64(n))
	for ws.nextWorker() {
		go upWorker(ws, l, newLayer, tree.Hash.NewHash())
	}
	ws.wait()
	tree.Levels = append(tree.Levels, newLayer)
}

func hashLeaves(elems map[uint64]crypto.Hashable, treeDepth uint8, hash hash.Hash) (map[uint64]crypto.GenericDigest, error) {
	hashedLeaves := make(map[uint64]crypto.GenericDigest, len(elems))
	for i, element := range elems {
		if i >= (1 << treeDepth) {
			return nil, fmt.Errorf(ErrPosOutOfBound, i, 1<<treeDepth)
		}
		hashedLeaves[i] = crypto.GenereicHashObj(hash, element)
	}

	return hashedLeaves, nil
}

func convertIndexes(elems map[uint64]crypto.Hashable, proof *Proof) (map[uint64]crypto.Hashable, error) {
	msbIndexedElements := make(map[uint64]crypto.Hashable, len(elems))
	for i, e := range elems {
		idx, err := msbToLsbIndex(i, proof.TreeDepth)
		if err != nil {
			return nil, err
		}
		msbIndexedElements[idx] = e
	}
	return msbIndexedElements, nil
}

// VerifyVectorCommitment verifies a vector commitment proof against a given root.
func VerifyVectorCommitment(root crypto.GenericDigest, elems map[uint64]crypto.Hashable, proof *Proof) error {
	if err := checkInput(proof); err != nil {
		return err
	}

	msbIndexedElements, err := convertIndexes(elems, proof)
	if err != nil {
		return err
	}

	return Verify(root, msbIndexedElements, proof)
}

// Verify ensures that the positions in elems correspond to the respective hashes
// in a tree with the given root hash.  The proof is expected to be the proof
// returned by Prove().
func Verify(root crypto.GenericDigest, elems map[uint64]crypto.Hashable, proof *Proof) error {
	if err := checkInput(proof); err != nil {
		return err
	}

	if len(elems) == 0 {
		if len(proof.Path) != 0 {
			return ErrNonEmptyProofForEmptyElements
		}
		return nil
	}

	hashedLeaves, err := hashLeaves(elems, proof.TreeDepth, proof.HashFactory.NewHash())
	if err != nil {
		return err
	}

	pl := buildPartialLayer(hashedLeaves)
	return verifyPath(root, proof, pl)
}

func checkInput(proof *Proof) error {
	if proof == nil {
		return ErrProofIsNil
	}

	if proof.TreeDepth > 64 {
		return ErrTreeTooDeep
	}
	return nil
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
			return ErrTreeTooDeep
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
		return ErrRootMismatch
	}
	return nil
}
