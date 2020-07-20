package merklearray

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
)

type Tree struct {
	// Level 0 is the leaves.
	levels []layer
}

func (tree *Tree) topLayer() layer {
	return tree.levels[len(tree.levels)-1]
}

func Build(array Array) (*Tree, error) {
	tree := &Tree{}

	var leaves layer
	arraylen := array.Length()
	for i := uint64(0); i < arraylen; i++ {
		data, err := array.Get(i)
		if err != nil {
			return nil, err
		}

		leaves = append(leaves, crypto.HashObj(data))
	}

	if arraylen > 0 {
		tree.levels = []layer{leaves}

		for len(tree.topLayer()) > 1 {
			tree.levels = append(tree.levels, tree.topLayer().up())
		}
	}

	return tree, nil
}

func (tree *Tree) Root() crypto.Digest {
	// Special case: commitment to zero-length array
	if len(tree.levels) == 0 {
		var zero crypto.Digest
		return zero
	}

	return tree.topLayer()[0]
}

const validateProof = false

func (tree *Tree) Prove(idxs []uint64) ([]crypto.Digest, error) {
	if len(idxs) == 0 {
		return nil, nil
	}

	// Special case: commitment to zero-length array
	if len(tree.levels) == 0 {
		return nil, fmt.Errorf("proving in zero-length commitment")
	}

	pl := make(partialLayer)
	for _, pos := range idxs {
		if pos >= uint64(len(tree.levels[0])) {
			return nil, fmt.Errorf("pos %d larger than leaf count %d", pos, len(tree.levels[0]))
		}

		pl[pos] = tree.levels[0][pos]
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
		computedroot, ok := pl[0]
		if !ok || computedroot != tree.topLayer()[0] {
			return nil, fmt.Errorf("internal error: root mismatch during proof")
		}
	}

	return s.hints, nil
}

func Verify(root crypto.Digest, elems map[uint64]crypto.Hashable, proof []crypto.Digest) error {
	if len(elems) == 0 {
		if len(proof) != 0 {
			return fmt.Errorf("non-empty proof for empty set of elements")
		}

		return nil
	}

	pl := make(partialLayer)
	for pos, elem := range elems {
		pl[pos] = crypto.HashObj(elem)
	}

	s := &siblings{
		hints: proof,
	}

	for l := uint64(0); len(s.hints) > 0 || len(pl) > 1; l++ {
		var err error
		pl, err = pl.up(s, l, true)
		if err != nil {
			return err
		}
	}

	computedroot, ok := pl[0]
	if !ok || computedroot != root {
		return fmt.Errorf("root mismatch")
	}

	return nil
}
