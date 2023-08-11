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
	"bytes"
	"errors"
	"fmt"
	"hash"
	"sort"

	"github.com/algorand/go-algorand/crypto"
	"golang.org/x/exp/slices"
)

const (
	// MaxEncodedTreeDepth is the maximum tree depth (root only depth 0) for a tree which
	// is being encoded (either by msbpack or by the fixed length encoding)
	MaxEncodedTreeDepth = 16

	// MaxNumLeavesOnEncodedTree is the maximum number of leaves allowed for a tree which
	// is being encoded (either by msbpack or by the fixed length encoding)
	MaxNumLeavesOnEncodedTree = 1 << MaxEncodedTreeDepth
)

// Merkle tree errors
var (
	ErrRootMismatch                  = errors.New("root mismatch")
	ErrProvingZeroCommitment         = errors.New("proving in zero-length commitment")
	ErrProofIsNil                    = errors.New("proof should not be nil")
	ErrNonEmptyProofForEmptyElements = errors.New("non-empty proof for empty set of elements")
	ErrUnexpectedTreeDepth           = errors.New("unexpected tree depth")
	ErrPosOutOfBound                 = errors.New("pos out of bound")
	ErrProofLengthDigestSizeMismatch = errors.New("proof length and digest size mismatched")
)

// Tree is a Merkle tree, represented by layers of nodes (hashes) in the tree
// at each height.
type Tree struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Levels represents the tree in layers. layer[0] contains the leaves.
	Levels []Layer `codec:"lvls,allocbound=MaxEncodedTreeDepth+1"`

	// NumOfElements represents the number of the elements in the array which the tree is built on.
	// notice that the number of leaves might be larger in case of a vector commitment
	// In addition, the code will not generate proofs on indexes larger than NumOfElements.
	NumOfElements uint64 `codec:"nl"`

	// Hash represents the hash function which is being used on elements in this tree.
	Hash crypto.HashFactory `codec:"hsh"`

	// IsVectorCommitment determines whether the tree was built as a vector commitment
	IsVectorCommitment bool `codec:"vc"`
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
			leaves[i] = crypto.GenericHashObj(hash, m)
		}

		batchSize++
	}
}

// BuildVectorCommitmentTree constructs a Merkle tree given an array.
// the tree returned from this function can function as a vector commitment which has position binding property.
// (having a position binding means that an adversary can not create a commitment and open
// its entry i = 1 in two different ways, using proofs of different ‘depths.’)
//
// In addition, the tree will also extend the array to have a length of 2^X leaves.
// i.e we always create a full tree
func BuildVectorCommitmentTree(array Array, factory crypto.HashFactory) (*Tree, error) {
	t, err := Build(generateVectorCommitmentArray(array), factory)
	if err != nil {
		return nil, err
	}
	t.IsVectorCommitment = true
	t.NumOfElements = array.Length()
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
		Levels:             nil,
		NumOfElements:      array.Length(),
		Hash:               factory,
		IsVectorCommitment: false,
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
// In case the tree is empty, the return value is an empty GenericDigest.
func (tree *Tree) Root() crypto.GenericDigest {
	// Special case: commitment to zero-length array
	if len(tree.Levels) == 0 {
		return crypto.GenericDigest{}
	}

	return tree.topLayer()[0]
}

// TODO: change into something global and more configurable
const validateProof = false

// ProveSingleLeaf constructs a proof for a leaf in a specific position in the array that was
// used to construct the tree.
func (tree *Tree) ProveSingleLeaf(idx uint64) (*SingleLeafProof, error) {
	proof, err := tree.Prove([]uint64{idx})
	if err != nil {
		return nil, err
	}
	return &SingleLeafProof{Proof: *proof}, err
}

// Prove constructs a proof for some set of positions in the array that was
// used to construct the tree.
//
// this function defines the following behavior:
// Tree is empty AND idxs list is empty results with an empty proof
// Tree is not empty AND idxs list is empty results with an empty proof
// Tree is empty AND idxs list not is empty results with an error
// Tree is not empty AND idxs list is not empty results with a proof
func (tree *Tree) Prove(idxs []uint64) (*Proof, error) {
	// Special case: empty proof when trying to prove on 0 elements (nothing)
	if len(idxs) == 0 {
		return tree.createEmptyProof()
	}

	// Special case: error when trying to prove on elements when the tree is empty
	// (i.e no elements in the underlying array)
	if tree.NumOfElements == 0 {
		return nil, ErrProvingZeroCommitment
	}

	// verify that all positions where part of the original array
	for i := 0; i < len(idxs); i++ {
		if idxs[i] >= tree.NumOfElements {
			return nil, fmt.Errorf("idxs[i] %d >= tree.NumOfElements %d: %w", idxs[i], tree.NumOfElements, ErrPosOutOfBound)
		}
	}

	if tree.IsVectorCommitment {
		VcIdxs, err := tree.convertLeavesIndexes(idxs)
		if err != nil {
			return nil, err
		}
		idxs = VcIdxs
	}

	slices.Sort(idxs)

	return tree.createProof(idxs)
}

func (tree *Tree) createProof(idxs []uint64) (*Proof, error) {
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

func (tree *Tree) convertLeavesIndexes(idxs []uint64) ([]uint64, error) {
	vcIdxs := make([]uint64, len(idxs))
	for i := 0; i < len(idxs); i++ {
		idx, err := merkleTreeToVectorCommitmentIndex(idxs[i], uint8(len(tree.Levels)-1))
		if err != nil {
			return nil, err
		}
		vcIdxs[i] = idx
	}
	return vcIdxs, nil
}

func (tree *Tree) createEmptyProof() (*Proof, error) {
	treeDepth := uint8(0)
	if len(tree.Levels) != 0 {
		treeDepth = uint8(len(tree.Levels)) - 1
	}
	return &Proof{
		HashFactory: tree.Hash,
		TreeDepth:   treeDepth,
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

// VerifyVectorCommitment verifies a vector commitment proof against a given root.
func VerifyVectorCommitment(root crypto.GenericDigest, elems map[uint64]crypto.Hashable, proof *Proof) error {
	if proof == nil {
		return ErrProofIsNil
	}

	msbIndexedElements, err := convertIndexes(elems, proof.TreeDepth)
	if err != nil {
		return err
	}

	return Verify(root, msbIndexedElements, proof)
}

// Verify ensures that the positions in elems correspond to the respective hashes
// in a tree with the given root hash.  The proof is expected to be the proof
// returned by Prove().
func Verify(root crypto.GenericDigest, elems map[uint64]crypto.Hashable, proof *Proof) error {
	if proof == nil {
		return ErrProofIsNil
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

	pl := buildFirstPartialLayer(hashedLeaves)
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
	}

	return inspectRoot(root, pl)
}

func hashLeaves(elems map[uint64]crypto.Hashable, treeDepth uint8, hash hash.Hash) (map[uint64]crypto.GenericDigest, error) {
	hashedLeaves := make(map[uint64]crypto.GenericDigest, len(elems))
	for i, element := range elems {
		if i >= (1 << treeDepth) {
			return nil, fmt.Errorf("pos %d >= 1^treeDepth %d: %w", i, 1<<treeDepth, ErrPosOutOfBound)
		}
		hashedLeaves[i] = crypto.GenericHashObj(hash, element)
	}

	return hashedLeaves, nil
}

func convertIndexes(elems map[uint64]crypto.Hashable, treeDepth uint8) (map[uint64]crypto.Hashable, error) {
	msbIndexedElements := make(map[uint64]crypto.Hashable, len(elems))
	for i, e := range elems {
		idx, err := merkleTreeToVectorCommitmentIndex(i, treeDepth)
		if err != nil {
			return nil, err
		}
		msbIndexedElements[idx] = e
	}
	return msbIndexedElements, nil
}

func buildFirstPartialLayer(elems map[uint64]crypto.GenericDigest) partialLayer {
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
