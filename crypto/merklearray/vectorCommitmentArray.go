package merklearray

import (
	"fmt"
	"math/bits"
)

type vectorCommitmentArray struct {
	array      Array
	pathLen    uint8
	paddedSize uint64
}

func getBottomElement() []byte {
	// TODO what is the bottom element?
	return []byte{0x00}
}

func generateVectorCommitmentArray(innerArray Array) *vectorCommitmentArray {
	arrayLen := innerArray.Length()
	if arrayLen == 0 {
		// in this case the tree has only one bottom element
		return &vectorCommitmentArray{array: innerArray, pathLen: 1, paddedSize: 1}
	}
	if arrayLen == 1 {
		return &vectorCommitmentArray{array: innerArray, pathLen: 1, paddedSize: 2}
	}

	numOfBits := uint8(bits.Len64(arrayLen - 1))

	var fullSize uint64
	var path uint8
	// if only one bit is set then this is a power of 2 number
	// if not, we round up the number to the closest power of 2
	if bits.OnesCount64(arrayLen) == 1 {
		fullSize = arrayLen
		path = numOfBits
	} else {
		path = numOfBits
		fullSize = 1 << path
	}

	return &vectorCommitmentArray{array: innerArray, pathLen: path, paddedSize: fullSize}
}

func (vc *vectorCommitmentArray) Length() uint64 {
	return vc.paddedSize
}

func (vc *vectorCommitmentArray) Marshal(pos uint64) ([]byte, error) {
	msbIndex := msbToLsbIndex(pos, vc.pathLen)
	if msbIndex >= vc.paddedSize {
		return nil, fmt.Errorf("vectorCommitmentArray.Get(%d): out of bounds, full size %d", pos, vc.paddedSize)
	}

	if msbIndex < vc.array.Length() {
		return vc.array.Marshal(msbIndex)
	}
	return getBottomElement(), nil
}

func msbToLsbIndex(msbIndex uint64, pathLen uint8) uint64 {
	return bits.Reverse64(msbIndex) >> (64 - pathLen)
}
