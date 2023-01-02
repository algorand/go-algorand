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
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func indexTranslate(t *testing.T, from, to uint64, pathLen uint8) {
	lsbIndex, err := merkleTreeToVectorCommitmentIndex(from, pathLen)
	require.NoError(t, err)
	require.Equal(t, to, lsbIndex)
}

func TestIndexing(t *testing.T) {
	partitiontest.PartitionTest(t)

	var pathLen uint8

	pathLen = 1
	indexTranslate(t, 0, 0, pathLen)
	indexTranslate(t, 1, 1, pathLen)

	pathLen = 2
	indexTranslate(t, 0, 0, pathLen)
	indexTranslate(t, 1, 2, pathLen)
	indexTranslate(t, 2, 1, pathLen)
	indexTranslate(t, 3, 3, pathLen)

	pathLen = 3
	indexTranslate(t, 0, 0, pathLen)
	indexTranslate(t, 1, 4, pathLen)
	indexTranslate(t, 2, 2, pathLen)
	indexTranslate(t, 3, 6, pathLen)
	indexTranslate(t, 4, 1, pathLen)
	indexTranslate(t, 5, 5, pathLen)
	indexTranslate(t, 6, 3, pathLen)
	indexTranslate(t, 7, 7, pathLen)

	pathLen = 4
	indexTranslate(t, 0, 0, pathLen)
	indexTranslate(t, 1, 8, pathLen)
	indexTranslate(t, 2, 4, pathLen)
	indexTranslate(t, 3, 12, pathLen)
	indexTranslate(t, 4, 2, pathLen)
	indexTranslate(t, 5, 10, pathLen)
	indexTranslate(t, 6, 6, pathLen)
	indexTranslate(t, 7, 14, pathLen)
	indexTranslate(t, 8, 1, pathLen)
	indexTranslate(t, 9, 9, pathLen)
	indexTranslate(t, 10, 5, pathLen)
	indexTranslate(t, 11, 13, pathLen)
	indexTranslate(t, 12, 3, pathLen)
	indexTranslate(t, 13, 11, pathLen)
	indexTranslate(t, 14, 7, pathLen)
	indexTranslate(t, 15, 15, pathLen)

	pathLen = 63
	indexTranslate(t, 0, 0, pathLen)
	indexTranslate(t, (1<<63)/2, 1, pathLen)
	indexTranslate(t, 1, (1<<63)/2, pathLen)
	indexTranslate(t, 1<<63-1, 1<<63-1, pathLen)

}

func vcSizeInnerTest(size uint64) *vectorCommitmentArray {
	testArray := make(TestArray, size)
	for i := uint64(0); i < size; i++ {
		crypto.RandBytes(testArray[i][:])
	}
	return generateVectorCommitmentArray(testArray)
}

func TestIndexOutOfBounds(t *testing.T) {
	partitiontest.PartitionTest(t)

	var pathLen uint8

	pathLen = 1
	lsbIndex, err := merkleTreeToVectorCommitmentIndex(0, pathLen)
	require.NoError(t, err)
	require.Equal(t, uint64(0), lsbIndex)

	lsbIndex, err = merkleTreeToVectorCommitmentIndex(1, pathLen)
	require.NoError(t, err)
	require.Equal(t, uint64(1), lsbIndex)

	lsbIndex, err = merkleTreeToVectorCommitmentIndex(2, pathLen)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPosOutOfBound)

	pathLen = 4
	lsbIndex, err = merkleTreeToVectorCommitmentIndex(15, pathLen)
	require.NoError(t, err)
	require.Equal(t, uint64(15), lsbIndex)

	lsbIndex, err = merkleTreeToVectorCommitmentIndex(16, pathLen)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPosOutOfBound)

}

func TestVcSizes(t *testing.T) {
	partitiontest.PartitionTest(t)

	var vc *vectorCommitmentArray
	vc = vcSizeInnerTest(0)
	require.Equal(t, uint8(1), vc.pathLen)
	require.Equal(t, uint64(1), vc.paddedLen)
	require.Equal(t, uint64(1), vc.Length())

	vc = vcSizeInnerTest(1)
	require.Equal(t, uint8(1), vc.pathLen)
	require.Equal(t, uint64(1), vc.paddedLen)
	require.Equal(t, uint64(1), vc.Length())

	vc = vcSizeInnerTest(2)
	require.Equal(t, uint8(1), vc.pathLen)
	require.Equal(t, uint64(2), vc.paddedLen)
	require.Equal(t, uint64(2), vc.Length())

	vc = vcSizeInnerTest(3)
	require.Equal(t, uint8(2), vc.pathLen)
	require.Equal(t, uint64(4), vc.paddedLen)
	require.Equal(t, uint64(4), vc.Length())

	vc = vcSizeInnerTest(4)
	require.Equal(t, uint8(2), vc.pathLen)
	require.Equal(t, uint64(4), vc.paddedLen)
	require.Equal(t, uint64(4), vc.Length())

	vc = vcSizeInnerTest(5)
	require.Equal(t, uint8(3), vc.pathLen)
	require.Equal(t, uint64(8), vc.paddedLen)
	require.Equal(t, uint64(8), vc.Length())

	vc = vcSizeInnerTest(9)
	require.Equal(t, uint8(4), vc.pathLen)
	require.Equal(t, uint64(16), vc.paddedLen)
	require.Equal(t, uint64(16), vc.Length())

	vc = vcSizeInnerTest(15)
	require.Equal(t, uint8(4), vc.pathLen)
	require.Equal(t, uint64(16), vc.paddedLen)
	require.Equal(t, uint64(16), vc.Length())

	vc = vcSizeInnerTest(16)
	require.Equal(t, uint8(4), vc.pathLen)
	require.Equal(t, uint64(16), vc.paddedLen)
	require.Equal(t, uint64(16), vc.Length())

	vc = vcSizeInnerTest(17)
	require.Equal(t, uint8(5), vc.pathLen)
	require.Equal(t, uint64(32), vc.paddedLen)
	require.Equal(t, uint64(32), vc.Length())
}

func TestVcArrayPadding(t *testing.T) {
	partitiontest.PartitionTest(t)

	testArray := make(TestArray, 11)
	for i := uint64(0); i < 11; i++ {
		crypto.RandBytes(testArray[i][:])
	}
	vc := generateVectorCommitmentArray(testArray)

	h := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()
	leafBytes := make([]byte, len(protocol.Message)+h.Size())
	copy(leafBytes, protocol.Message)
	copy(leafBytes[len(protocol.Message):], testArray[1][:])
	h.Reset()
	h.Write(leafBytes)
	leafHash := h.Sum(nil)

	idx, err := merkleTreeToVectorCommitmentIndex(1, 4)
	require.NoError(t, err)
	leafVc, err := vc.Marshal(idx)
	hashID, leafData := leafVc.ToBeHashed()
	h.Reset()
	h.Write([]byte(hashID))
	h.Write(leafData)
	leafVcHash := h.Sum(nil)

	require.NoError(t, err)
	require.Equal(t, leafHash, leafVcHash)
}
