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
	"fmt"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"math/bits"
)

// ErrGetOutOfBound returned when trying to retrieve an element which is out of
// the padded array bound.
var (
	ErrGetOutOfBound = "vectorCommitmentArray.Get(%d): out of bounds, full size %d"
)

type vectorCommitmentArray struct {
	array     Array
	pathLen   uint8
	paddedLen uint64
}

type bottomElement struct{}

func (b *bottomElement) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.MerkleVectorCommitmentBottomLeaf, []byte{}
}

func generateVectorCommitmentArray(innerArray Array) *vectorCommitmentArray {
	arrayLen := innerArray.Length()
	if arrayLen == 0 || arrayLen == 1 {
		return &vectorCommitmentArray{array: innerArray, pathLen: 1, paddedLen: 1}
	}

	path := uint8(bits.Len64(arrayLen - 1))
	fullSize := uint64(1 << path)
	return &vectorCommitmentArray{array: innerArray, pathLen: path, paddedLen: fullSize}
}

func (vc *vectorCommitmentArray) Length() uint64 {
	return vc.paddedLen
}

func (vc *vectorCommitmentArray) Marshal(pos uint64) (crypto.Hashable, error) {
	lsbIndex, err := merkleTreeToVectorCommitmentIndex(pos, vc.pathLen)
	if err != nil {
		return nil, err
	}
	if lsbIndex >= vc.paddedLen {
		return nil, fmt.Errorf(ErrGetOutOfBound, pos, vc.paddedLen)
	}

	if lsbIndex < vc.array.Length() {
		return vc.array.Marshal(lsbIndex)
	}

	return &bottomElement{}, nil
}

// merkleTreeToVectorCommitmentIndex Translate an index of an element on a merkle tree to an index on the vector commitment.
// The given index must be within the range of the elements in the tree (assume this number is 1^pathLen)
func merkleTreeToVectorCommitmentIndex(msbIndex uint64, pathLen uint8) (uint64, error) {
	if msbIndex >= (1 << pathLen) {
		return 0, fmt.Errorf(ErrPosOutOfBound, msbIndex, 1<<pathLen)
	}
	return bits.Reverse64(msbIndex) >> (64 - pathLen), nil
}
