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

	var junk TestData
	crypto.RandBytes(junk[:])

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
	require.Equal(t, data[1+((MaxEncodedTreeDepth-1)*crypto.Sha512_256Size):], zeroDigest)

	var newPath []crypto.GenericDigest
	for i := 0; i < MaxEncodedTreeDepth+1; i++ {
		var junkDigest [crypto.Sha512_256Size]byte
		crypto.RandBytes(junkDigest[:])
		newPath = append(newPath, junkDigest[:])
	}

	p.Path = newPath
	p.TreeDepth = uint8(len(newPath))
	data = p.GetFixedLengthHashableRepresentation()
	require.Equal(t, len(data), 1+(MaxEncodedTreeDepth*crypto.Sha512_256Size))
	require.Equal(t, data[1+((MaxEncodedTreeDepth-1)*crypto.Sha512_256Size):], []byte(p.Path[MaxEncodedTreeDepth-1]))
}
