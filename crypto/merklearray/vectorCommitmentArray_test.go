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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIndexing(t *testing.T) {
	partitiontest.PartitionTest(t)

	var pathLen uint8

	pathLen = 1
	require.Equal(t, uint64(0), msbToLsbIndex(0, pathLen))
	require.Equal(t, uint64(1), msbToLsbIndex(1, pathLen))

	pathLen = 2
	require.Equal(t, uint64(0), msbToLsbIndex(0, pathLen))
	require.Equal(t, uint64(2), msbToLsbIndex(1, pathLen))
	require.Equal(t, uint64(1), msbToLsbIndex(2, pathLen))
	require.Equal(t, uint64(3), msbToLsbIndex(3, pathLen))

	pathLen = 3
	require.Equal(t, uint64(0), msbToLsbIndex(0, pathLen))
	require.Equal(t, uint64(4), msbToLsbIndex(1, pathLen))
	require.Equal(t, uint64(2), msbToLsbIndex(2, pathLen))
	require.Equal(t, uint64(6), msbToLsbIndex(3, pathLen))
	require.Equal(t, uint64(1), msbToLsbIndex(4, pathLen))
	require.Equal(t, uint64(5), msbToLsbIndex(5, pathLen))
	require.Equal(t, uint64(3), msbToLsbIndex(6, pathLen))
	require.Equal(t, uint64(7), msbToLsbIndex(7, pathLen))

	pathLen = 4
	require.Equal(t, uint64(0), msbToLsbIndex(0, pathLen))
	require.Equal(t, uint64(8), msbToLsbIndex(1, pathLen))
	require.Equal(t, uint64(4), msbToLsbIndex(2, pathLen))
	require.Equal(t, uint64(12), msbToLsbIndex(3, pathLen))
	require.Equal(t, uint64(2), msbToLsbIndex(4, pathLen))
	require.Equal(t, uint64(10), msbToLsbIndex(5, pathLen))
	require.Equal(t, uint64(6), msbToLsbIndex(6, pathLen))
	require.Equal(t, uint64(14), msbToLsbIndex(7, pathLen))
	require.Equal(t, uint64(1), msbToLsbIndex(8, pathLen))
	require.Equal(t, uint64(9), msbToLsbIndex(9, pathLen))
	require.Equal(t, uint64(5), msbToLsbIndex(10, pathLen))
	require.Equal(t, uint64(13), msbToLsbIndex(11, pathLen))
	require.Equal(t, uint64(3), msbToLsbIndex(12, pathLen))
	require.Equal(t, uint64(11), msbToLsbIndex(13, pathLen))
	require.Equal(t, uint64(7), msbToLsbIndex(14, pathLen))
	require.Equal(t, uint64(15), msbToLsbIndex(15, pathLen))

	pathLen = 64
	require.Equal(t, uint64(0), msbToLsbIndex(0, pathLen))
	require.Equal(t, uint64(1), msbToLsbIndex((1<<64)/2, pathLen))
	require.Equal(t, uint64((1<<64)/2), msbToLsbIndex(1, pathLen))
	require.Equal(t, uint64(1<<64-1), msbToLsbIndex(1<<64-1, pathLen))
}

func vcSizeInnerTest(size uint64) *vectorCommitmentArray {
	testArray := make(TestArray, size)
	for i := uint64(0); i < size; i++ {
		crypto.RandBytes(testArray[i][:])
	}
	return generateVectorCommitmentArray(testArray)
}

func TestVcSizes(t *testing.T) {
	var vc *vectorCommitmentArray

	vc = vcSizeInnerTest(0)
	require.Equal(t, uint8(1), vc.pathLen)
	require.Equal(t, uint64(1), vc.paddedSize)
	require.Equal(t, uint64(1), vc.Length())

	vc = vcSizeInnerTest(1)
	require.Equal(t, uint8(1), vc.pathLen)
	require.Equal(t, uint64(2), vc.paddedSize)
	require.Equal(t, uint64(2), vc.Length())

	vc = vcSizeInnerTest(2)
	require.Equal(t, uint8(1), vc.pathLen)
	require.Equal(t, uint64(2), vc.paddedSize)
	require.Equal(t, uint64(2), vc.Length())

	vc = vcSizeInnerTest(3)
	require.Equal(t, uint8(2), vc.pathLen)
	require.Equal(t, uint64(4), vc.paddedSize)
	require.Equal(t, uint64(4), vc.Length())

	vc = vcSizeInnerTest(4)
	require.Equal(t, uint8(2), vc.pathLen)
	require.Equal(t, uint64(4), vc.paddedSize)
	require.Equal(t, uint64(4), vc.Length())

	vc = vcSizeInnerTest(5)
	require.Equal(t, uint8(3), vc.pathLen)
	require.Equal(t, uint64(8), vc.paddedSize)
	require.Equal(t, uint64(8), vc.Length())

	vc = vcSizeInnerTest(9)
	require.Equal(t, uint8(4), vc.pathLen)
	require.Equal(t, uint64(16), vc.paddedSize)
	require.Equal(t, uint64(16), vc.Length())

	vc = vcSizeInnerTest(15)
	require.Equal(t, uint8(4), vc.pathLen)
	require.Equal(t, uint64(16), vc.paddedSize)
	require.Equal(t, uint64(16), vc.Length())

	vc = vcSizeInnerTest(16)
	require.Equal(t, uint8(4), vc.pathLen)
	require.Equal(t, uint64(16), vc.paddedSize)
	require.Equal(t, uint64(16), vc.Length())

	vc = vcSizeInnerTest(17)
	require.Equal(t, uint8(5), vc.pathLen)
	require.Equal(t, uint64(32), vc.paddedSize)
	require.Equal(t, uint64(32), vc.Length())
}

func TestVcArrayPadding(t *testing.T) {
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

	leafVc, err := vc.Marshal(msbToLsbIndex(1, 4))
	h.Reset()
	h.Write(leafVc)
	leafVcHash := h.Sum(nil)

	require.NoError(t, err)
	require.Equal(t, leafHash, leafVcHash)
}
