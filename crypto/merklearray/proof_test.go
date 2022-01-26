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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestProofSerialization(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := make(TestArray, 3)
	for i := uint64(0); i < 3; i++ {
		crypto.RandBytes(a[i][:])
	}

	tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	// creates a proof with missing child
	p, err := tree.ProveSingleLeaf(2)
	require.NoError(t, err)

	data := p.GetFixedLengthHashableRepresentation()
	require.Equal(t, len(data), 1+(MaxEncodedTreeDepth*crypto.Sha512_256Size))

	// check the padded results
	zeroDigest := make([]byte, crypto.Sha512_256Size)
	i := 0
	for ; i < (MaxEncodedTreeDepth - 2); i++ {
		require.Equal(t, zeroDigest, data[1+crypto.Sha512_256Size*i:1+crypto.Sha512_256Size*(i+1)])
	}

	// first proof digest is nil -> so the HashableRepresentation is zeros
	require.Equal(t, crypto.GenericDigest(nil), p.Path[0])
	require.Equal(t, zeroDigest, data[1+crypto.Sha512_256Size*i:1+crypto.Sha512_256Size*(i+1)])
	i++

	require.Equal(t, []byte(p.Path[1]), data[1+crypto.Sha512_256Size*i:1+crypto.Sha512_256Size*(i+1)])

	//VC
	tree, err = BuildVectorCommitmentTree(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	// creates a proof with missing child
	p, err = tree.ProveSingleLeaf(2)
	require.NoError(t, err)

	data = p.GetFixedLengthHashableRepresentation()
	require.Equal(t, len(data), 1+(MaxEncodedTreeDepth*crypto.Sha512_256Size))

	// check the padded results
	zeroDigest = make([]byte, crypto.Sha512_256Size)
	i = 0
	for ; i < (MaxEncodedTreeDepth - 2); i++ {
		require.Equal(t, zeroDigest, data[1+crypto.Sha512_256Size*i:1+crypto.Sha512_256Size*(i+1)])
	}

	require.Equal(t, []byte(p.Path[0]), data[1+crypto.Sha512_256Size*i:1+crypto.Sha512_256Size*(i+1)])
	i++
	require.Equal(t, []byte(p.Path[1]), data[1+crypto.Sha512_256Size*i:1+crypto.Sha512_256Size*(i+1)])

}

func TestProofSerializationMaxTree(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := make(TestArray, MaxNumLeavesOnEncodedTree)
	for i := uint64(0); i < MaxNumLeavesOnEncodedTree; i++ {
		crypto.RandBytes(a[i][:])
	}

	tree, err := BuildVectorCommitmentTree(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	p, err := tree.ProveSingleLeaf(2)
	require.NoError(t, err)

	data := p.GetFixedLengthHashableRepresentation()
	require.Equal(t, len(data), 1+(MaxEncodedTreeDepth*crypto.Sha512_256Size))

	i := 0
	for ; i < MaxEncodedTreeDepth; i++ {
		require.Equal(t, []byte(p.Path[i]), data[1+crypto.Sha512_256Size*i:1+crypto.Sha512_256Size*(i+1)])
	}
}

func TestProofSerializationOneLeafTree(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := make(TestArray, 1)
	crypto.RandBytes(a[0][:])

	tree, err := BuildVectorCommitmentTree(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	p, err := tree.ProveSingleLeaf(0)
	require.NoError(t, err)

	data := p.GetFixedLengthHashableRepresentation()
	require.Equal(t, len(data), 1+(MaxEncodedTreeDepth*crypto.Sha512_256Size))

	zeroDigest := make([]byte, crypto.Sha512_256Size)
	i := 0
	for ; i < MaxEncodedTreeDepth; i++ {
		require.Equal(t, zeroDigest, data[1+crypto.Sha512_256Size*i:1+crypto.Sha512_256Size*(i+1)])
	}

}
