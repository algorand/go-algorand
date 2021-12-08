package merklearray

import (
	"github.com/algorand/go-algorand/crypto"
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
	require.Equal(t, uint8(0), vc.pathLen)
	require.Equal(t, uint64(0), vc.paddedSize)
	require.Equal(t, uint64(0), vc.Length())

	vc = vcSizeInnerTest(1)
	require.Equal(t, uint8(1), vc.pathLen)
	require.Equal(t, uint64(1), vc.paddedSize)
	require.Equal(t, uint64(1), vc.Length())

	vc = vcSizeInnerTest(2)
	require.Equal(t, uint8(2), vc.pathLen)
	require.Equal(t, uint64(2), vc.paddedSize)
	require.Equal(t, uint64(2), vc.Length())

	vc = vcSizeInnerTest(3)
	require.Equal(t, uint8(2), vc.pathLen)
	require.Equal(t, uint64(4), vc.paddedSize)
	require.Equal(t, uint64(4), vc.Length())

	vc = vcSizeInnerTest(4)
	require.Equal(t, uint8(3), vc.pathLen)
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
	
}
