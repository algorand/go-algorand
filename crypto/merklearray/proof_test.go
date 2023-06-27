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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestProofSerialization(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, 3)
	for i := uint64(0); i < 3; i++ {
		crypto.RandBytes(array[i][:])
	}

	tree, err := Build(array, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	// creates a proof with missing child
	p, err := tree.ProveSingleLeaf(2)
	a.NoError(err)

	data := p.GetFixedLengthHashableRepresentation()
	a.Equal(len(data), 1+(MaxEncodedTreeDepth*crypto.Sha512_256Size))

	// check the padded results
	zeroDigest := make([]byte, crypto.Sha512_256Size)
	i := 0
	proofData := data[1:]
	for ; i < (MaxEncodedTreeDepth - 2); i++ {
		a.Equal(zeroDigest, proofData[crypto.Sha512_256Size*i:crypto.Sha512_256Size*(i+1)])
	}

	// first proof digest is nil -> so the HashableRepresentation is zeros
	a.Equal(crypto.GenericDigest(nil), p.Path[0])
	a.Equal(zeroDigest, proofData[crypto.Sha512_256Size*i:crypto.Sha512_256Size*(i+1)])
	i++

	a.Equal([]byte(p.Path[1]), proofData[crypto.Sha512_256Size*i:crypto.Sha512_256Size*(i+1)])

	//VC
	tree, err = BuildVectorCommitmentTree(array, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	// creates a proof with missing child
	p, err = tree.ProveSingleLeaf(2)
	a.NoError(err)

	data = p.GetFixedLengthHashableRepresentation()
	a.Equal(len(data), 1+(MaxEncodedTreeDepth*crypto.Sha512_256Size))

	// check the padded results
	zeroDigest = make([]byte, crypto.Sha512_256Size)
	i = 0
	proofData = data[1:]
	for ; i < (MaxEncodedTreeDepth - 2); i++ {
		a.Equal(zeroDigest, proofData[crypto.Sha512_256Size*i:crypto.Sha512_256Size*(i+1)])
	}

	a.Equal([]byte(p.Path[0]), proofData[crypto.Sha512_256Size*i:crypto.Sha512_256Size*(i+1)])
	i++
	a.Equal([]byte(p.Path[1]), proofData[crypto.Sha512_256Size*i:crypto.Sha512_256Size*(i+1)])

}

func TestProofSerializationMaxTree(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, MaxNumLeavesOnEncodedTree)
	for i := uint64(0); i < MaxNumLeavesOnEncodedTree; i++ {
		crypto.RandBytes(array[i][:])
	}

	tree, err := BuildVectorCommitmentTree(array, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	p, err := tree.ProveSingleLeaf(2)
	a.NoError(err)

	data := p.GetFixedLengthHashableRepresentation()
	a.Equal(len(data), 1+(MaxEncodedTreeDepth*crypto.Sha512_256Size))

	proofData := data[1:]
	for i := 0; i < MaxEncodedTreeDepth; i++ {
		a.Equal([]byte(p.Path[i]), proofData[crypto.Sha512_256Size*i:crypto.Sha512_256Size*(i+1)])
	}
}

func TestProofSerializationOneLeafTree(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, 1)
	crypto.RandBytes(array[0][:])

	tree, err := BuildVectorCommitmentTree(array, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	p, err := tree.ProveSingleLeaf(0)
	a.NoError(err)

	data := p.GetFixedLengthHashableRepresentation()
	a.Equal(len(data), 1+(MaxEncodedTreeDepth*crypto.Sha512_256Size))

	zeroDigest := make([]byte, crypto.Sha512_256Size)

	proofData := data[1:]
	for i := 0; i < MaxEncodedTreeDepth; i++ {
		a.Equal(zeroDigest, proofData[crypto.Sha512_256Size*i:crypto.Sha512_256Size*(i+1)])
	}

}

func TestConcatenatedProofsMissingChild(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, 7)
	for i := 0; i < 7; i++ {
		crypto.RandBytes(array[i][:])
	}

	tree, err := Build(array, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	p, err := tree.ProveSingleLeaf(6)
	a.NoError(err)

	concatenatedProof := p.GetConcatenatedProof()
	computedPath := recomputePath(concatenatedProof)

	// verify that the concatenated proof can be verified correctly
	newP := SingleLeafProof{Proof: Proof{TreeDepth: p.TreeDepth, Path: []crypto.GenericDigest{}, HashFactory: p.HashFactory}}
	newP.Path = computedPath
	err = Verify(tree.Root(), map[uint64]crypto.Hashable{6: array[6]}, newP.ToProof())
	a.NoError(err)

	recomputedProof, err := ProofDataToSingleLeafProof(p.HashFactory.HashType.String(), uint64(p.TreeDepth), concatenatedProof)
	a.NoError(err)

	// verify that we can reconstruct the original singleLeafProof from the concatenated proof
	err = Verify(tree.Root(), map[uint64]crypto.Hashable{6: array[6]}, recomputedProof.ToProof())
	a.NoError(err)

}

func TestConcatenatedProofsFullTree(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, 8)
	for i := 0; i < 8; i++ {
		crypto.RandBytes(array[i][:])
	}

	tree, err := Build(array, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	p, err := tree.ProveSingleLeaf(6)
	a.NoError(err)

	concatenatedProof := p.GetConcatenatedProof()
	computedPath := recomputePath(concatenatedProof)

	// verify that the concatenated proof can be verified correctly
	newP := SingleLeafProof{Proof: Proof{TreeDepth: p.TreeDepth, Path: computedPath, HashFactory: p.HashFactory}}
	err = Verify(tree.Root(), map[uint64]crypto.Hashable{6: array[6]}, newP.ToProof())
	a.NoError(err)

	recomputedProof, err := ProofDataToSingleLeafProof(p.HashFactory.HashType.String(), uint64(p.TreeDepth), concatenatedProof)
	a.NoError(err)

	// verify that we can reconstruct the original singleLeafProof from the concatenated proof
	err = Verify(tree.Root(), map[uint64]crypto.Hashable{6: array[6]}, recomputedProof.ToProof())
	a.NoError(err)
}

func TestConcatenatedProofsOneLeaf(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, 1)
	crypto.RandBytes(array[0][:])

	tree, err := Build(array, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	p, err := tree.ProveSingleLeaf(0)
	a.NoError(err)

	concatenatedProof := p.GetConcatenatedProof()
	computedPath := recomputePath(concatenatedProof)

	// verify that the concatenated proof can be verified correctly
	newP := SingleLeafProof{Proof: Proof{TreeDepth: p.TreeDepth, Path: computedPath, HashFactory: p.HashFactory}}
	err = Verify(tree.Root(), map[uint64]crypto.Hashable{0: array[0]}, newP.ToProof())
	a.NoError(err)

	recomputedProof, err := ProofDataToSingleLeafProof(p.HashFactory.HashType.String(), uint64(p.TreeDepth), concatenatedProof)
	a.NoError(err)

	// verify that we can reconstruct the original singleLeafProof from the concatenated proof
	err = Verify(tree.Root(), map[uint64]crypto.Hashable{0: array[0]}, recomputedProof.ToProof())
	a.NoError(err)
}

func TestProofDeserializationError(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	_, err := ProofDataToSingleLeafProof(crypto.Sha256.String(), 1, []byte{1})
	a.ErrorIs(err, ErrProofLengthDigestSizeMismatch)
}

func recomputePath(p []byte) []crypto.GenericDigest {
	var computedPath []crypto.GenericDigest
	for len(p) > 0 {
		var d crypto.Digest
		copy(d[:], p)
		computedPath = append(computedPath, d[:])
		p = p[len(d):]
	}
	return computedPath
}

func TestMaxSizeCalculation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Ensure that the manually generated ProofMaxSizeByElements matches the autogenerated ProofMaxSize() function
	// If this breaks either the allocbound has changed or the Proof struct definition has changed
	require.Equal(t, ProofMaxSizeByElements(MaxNumLeavesOnEncodedTree/2), ProofMaxSize())
}
