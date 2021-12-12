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
	"hash"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type TestMessage string

func (m TestMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, []byte(m)
}

type TestData crypto.Digest

func (d TestData) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, d[:]
}

type TestBuf []byte

func (b TestBuf) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, b
}

type TestArray []TestData

func (a TestArray) Length() uint64 {
	return uint64(len(a))
}
func hashRep(h crypto.Hashable) []byte {
	hashid, data := h.ToBeHashed()
	return append([]byte(hashid), data...)
}

func (a TestArray) Marshal(pos uint64) ([]byte, error) {
	if pos >= uint64(len(a)) {
		return nil, fmt.Errorf("pos %d larger than length %d", pos, len(a))
	}

	return hashRep(a[pos]), nil
}

type TestRepeatingArray struct {
	item  crypto.Hashable
	count uint64
}

func (a TestRepeatingArray) Length() uint64 {
	return a.count
}

func (a TestRepeatingArray) Marshal(pos uint64) ([]byte, error) {
	if pos >= a.count {
		return nil, fmt.Errorf("pos %d larger than length %d", pos, a.count)
	}

	return hashRep(a.item), nil
}

func TestMerkle(t *testing.T) {
	partitiontest.PartitionTest(t)

	increment := uint64(1)
	// with -race this will take a very long time
	// run a shorter version for Short testing
	if testing.Short() {
		increment = uint64(16)
	}

	for i := uint64(0); i < 1024; i = i + increment {
		testMerkle(t, crypto.Sha512_256, i)
	}

	if !testing.Short() {
		for i := uint64(0); i < 10; i++ {
			testMerkle(t, crypto.Sumhash, i)
		}
	} else {
		testMerkle(t, crypto.Sumhash, 10)
	}
}

func testMerkle(t *testing.T, hashtype crypto.HashType, size uint64) {
	var junk TestData
	crypto.RandBytes(junk[:])

	a := make(TestArray, size)
	for i := uint64(0); i < size; i++ {
		crypto.RandBytes(a[i][:])
	}

	tree, err := Build(a, crypto.HashFactory{HashType: hashtype})
	require.NoError(t, err)

	root := tree.Root()

	var allpos []uint64
	allmap := make(map[uint64]crypto.Hashable)

	for i := uint64(0); i < size; i++ {
		proof, err := tree.Prove([]uint64{i})
		require.NoError(t, err)

		err = Verify(root, map[uint64]crypto.Hashable{i: a[i]}, proof)
		require.NoError(t, err)

		err = Verify(root, map[uint64]crypto.Hashable{i: junk}, proof)
		require.Error(t, err, "no error when verifying junk")

		allpos = append(allpos, i)
		allmap[i] = a[i]
	}

	proof, err := tree.Prove(allpos)
	require.NoError(t, err)

	err = Verify(root, allmap, proof)
	require.NoError(t, err)

	err = Verify(root, map[uint64]crypto.Hashable{0: junk}, proof)
	require.Error(t, err, "no error when verifying junk batch")

	err = Verify(root, map[uint64]crypto.Hashable{0: junk}, nil)
	require.Error(t, err, "no error when verifying junk batch")

	_, err = tree.Prove([]uint64{size})
	require.Error(t, err, "no error when proving past the end")

	err = Verify(root, map[uint64]crypto.Hashable{size: junk}, nil)
	require.Error(t, err, "no error when verifying past the end")

	if size > 0 {
		var somepos []uint64
		somemap := make(map[uint64]crypto.Hashable)
		for i := 0; i < 10; i++ {
			pos := crypto.RandUint64() % size
			somepos = append(somepos, pos)
			somemap[pos] = a[pos]
		}

		proof, err = tree.Prove(somepos)
		require.NoError(t, err)

		err = Verify(root, somemap, proof)
		require.NoError(t, err)
	}
}

func TestEmptyProveStructure(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	size := uint64(10)
	arr := make(TestArray, size)
	for i := uint64(0); i < size; i++ {
		crypto.RandBytes(arr[i][:])
	}

	tree, err := Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	prf, err := tree.Prove(nil)
	a.NoError(err)
	a.NotNil(prf)
	a.Nil(prf.Path)
	a.Equal(prf.HashFactory, crypto.HashFactory{HashType: crypto.Sha512_256})
}

type nonmarshalable []int

func (n nonmarshalable) Length() uint64 {
	return uint64(len(n))
}

func (n nonmarshalable) Marshal(pos uint64) ([]byte, error) {
	return nil, fmt.Errorf("can't be marshaled")
}

func TestErrorInMarshal(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := nonmarshalable{1}
	_, err := Build(&a, crypto.HashFactory{})
	require.Error(t, err)
}

func TestVerifyWithNoElements(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)
	size := uint64(10)
	arr := make(TestArray, size)
	for i := uint64(0); i < size; i++ {
		crypto.RandBytes(arr[i][:])
	}
	tree, err := Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	p, err := tree.Prove([]uint64{1})
	a.NoError(err)
	err = Verify(tree.Root(), map[uint64]crypto.Hashable{}, p)
	require.Error(t, err)

	err = Verify(tree.Root(), map[uint64]crypto.Hashable{}, nil)
	require.Error(t, err)

	err = Verify(tree.Root(), map[uint64]crypto.Hashable{}, &Proof{HashFactory: crypto.HashFactory{HashType: crypto.Sha512_256}})
	require.NoError(t, err)
}

func TestEmptyTree(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	arr := make(TestArray, 0)
	tree, err := Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	a.Len(tree.Levels, 0)

	arr = make(TestArray, 1)
	tree, err = Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	a.Len(tree.Levels, 1)
	a.Equal(tree.Root().ToSlice(), tree.Levels[0][0].ToSlice())
}

// TestGenericDigest makes sure GenericDigest will not decoded sizes
// greater than the max allowd.
func TestGenericDigest(t *testing.T) {
	partitiontest.PartitionTest(t)

	err := testWithSize(t, crypto.MaxHashDigestSize)
	require.NoError(t, err)

	err = testWithSize(t, crypto.MaxHashDigestSize+1)
	require.Error(t, err)
}

func testWithSize(t *testing.T, size int) error {
	gd := make(crypto.GenericDigest, size)
	gd[8] = 88

	var wgd Proof
	wgd.Path = make([]crypto.GenericDigest, 1000)
	wgd.Path[0] = gd

	bytes := protocol.Encode(&wgd)

	var out Proof
	err := protocol.Decode(bytes, &out)

	if err == nil {
		require.Equal(t, wgd, out)
	}
	return err
}

func TestSizeLimitsMerkle(t *testing.T) {
	partitiontest.PartitionTest(t)

	increment := uint64(1)
	// with -race this will take a very long time
	// run a shorter version for Short testing
	if testing.Short() {
		increment = 8
	}
	for depth := uint64(0); depth < uint64(18); depth = depth + increment {
		size := uint64(1) << depth

		// eltCoefficient is the coefficent to determine how many elements are in the proof.
		// There will be 1/eltCoefficient elements of all possible element (2^treeDepth)
		// numElts = 2^(depth-eltCoefficient)

		// When the positions are regularly positioned then, the number of paths will be maximum, bounded by:
		// 2^(depth-eltCoefficient)*eltCoefficient

		// regular spaced elets
		for eltCoefficient := uint64(0); eltCoefficient <= depth; {
			numElts := uint64(1) << (depth - eltCoefficient)
			positions := getRegularPositions(numElts, uint64(1)<<depth)

			tree, proof := testMerkelSizeLimits(t, crypto.Sha512_256, size, positions)
			require.Equal(t, (uint64(1)<<(depth-eltCoefficient))*eltCoefficient, uint64(len(proof.Path)))

			// encode/decode
			bytes := protocol.Encode(proof)
			var outProof Proof
			err := protocol.Decode(bytes, &outProof)
			if depth > MaxTreeDepth && (eltCoefficient == 1 || eltCoefficient == 2) {
				errmsg := fmt.Sprintf("%d > %d at Path", len(proof.Path), MaxNumLeaves/2)
				require.Contains(t, err.Error(), errmsg)
			} else {
				require.NoError(t, err)
				require.Equal(t, *proof, outProof)
			}

			bytes = protocol.Encode(tree)
			var outTree Tree
			err = protocol.Decode(bytes, &outTree)
			if depth > MaxTreeDepth {
				require.Contains(t, err.Error(), "> 17 at Levels")
			} else {
				require.NoError(t, err)
				require.Equal(t, *tree, outTree)
			}

			if eltCoefficient == 0 {
				eltCoefficient = 1
			} else {
				eltCoefficient = eltCoefficient << increment
			}
		}

		// randomly positioned elts
		for eltCoefficient := uint64(1); eltCoefficient <= depth; eltCoefficient = eltCoefficient << increment {
			numElts := uint64(1) << (depth - eltCoefficient)
			positions := getRandomPositions(numElts, numElts)

			_, proof := testMerkelSizeLimits(t, crypto.Sha512_256, size, positions)
			require.GreaterOrEqual(t, (uint64(1)<<(depth-eltCoefficient))*eltCoefficient, uint64(len(proof.Path)))

			if len(proof.Path) > MaxNumLeaves {
				// encode/decode
				bytes := protocol.Encode(proof)
				var outProof Proof
				err := protocol.Decode(bytes, &outProof)
				errmsg := fmt.Sprintf("%d > %d at Path", len(proof.Path), MaxNumLeaves)
				require.Contains(t, err.Error(), errmsg)
			}
		}
	}

	// case of a tree with leaves 2^16 + 1
	size := (uint64(1) << MaxTreeDepth) + 1
	tree, _ := testMerkelSizeLimits(t, crypto.Sha512_256, size, []uint64{})
	bytes := protocol.Encode(tree)
	var outTree Tree
	err := protocol.Decode(bytes, &outTree)
	require.Contains(t, err.Error(), "> 17 at Levels")
}

func validateVector(t *testing.T, array TestArray, root []byte) {
	tree, err := Build(array, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)
	root2 := tree.Root()
	require.Equal(t, root, []byte(root2))
}

func TestMerkleTreeVectors(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := make(TestArray, 1)
	copy(a[0][:], []byte{212, 60, 103, 72, 82, 10, 118, 248, 31, 184, 37, 10, 169, 225, 166, 86, 240, 115, 255, 241, 229, 81, 86, 47, 173, 67, 233, 255, 251, 26, 184, 139})
	root := []byte{223, 165, 76, 43, 118, 131, 205, 83, 151, 176, 50, 187, 236, 17, 236, 27, 119, 185, 251, 236, 90, 86, 201, 233, 66, 15, 107, 153, 128, 120, 64, 52}
	validateVector(t, a, root)

	a = make(TestArray, 2)
	copy(a[0][:], []byte{39, 169, 1, 19, 53, 252, 150, 220, 9, 95, 52, 138, 108, 147, 71, 211, 199, 205, 213, 108, 87, 198, 80, 41, 125, 135, 223, 149, 209, 63, 119, 11})
	copy(a[1][:], []byte{88, 120, 69, 62, 77, 91, 206, 2, 75, 78, 224, 127, 108, 87, 24, 104, 104, 243, 65, 3, 72, 245, 167, 214, 1, 192, 217, 206, 30, 254, 210, 57})
	root = []byte{117, 207, 58, 54, 89, 80, 47, 147, 38, 223, 250, 114, 218, 81, 102, 235, 222, 29, 19, 246, 82, 156, 146, 35, 36, 135, 70, 68, 244, 183, 97, 110}
	validateVector(t, a, root)

	a = make(TestArray, 3)
	copy(a[0][:], []byte{68, 181, 96, 106, 228, 157, 129, 188, 127, 52, 81, 196, 255, 128, 57, 152, 168, 254, 0, 87, 226, 45, 99, 103, 8, 14, 90, 21, 91, 102, 16, 8})
	copy(a[1][:], []byte{112, 206, 125, 248, 189, 164, 41, 32, 245, 231, 90, 231, 136, 238, 123, 152, 9, 130, 106, 146, 112, 26, 78, 14, 73, 1, 56, 56, 14, 166, 15, 68})
	copy(a[2][:], []byte{119, 180, 57, 233, 159, 118, 74, 31, 103, 73, 230, 105, 177, 54, 31, 227, 187, 92, 228, 27, 234, 196, 181, 205, 85, 254, 81, 170, 158, 254, 60, 103})
	root = []byte{7, 177, 51, 83, 39, 122, 156, 203, 107, 66, 79, 87, 58, 180, 252, 158, 38, 138, 1, 39, 206, 188, 73, 150, 82, 146, 64, 181, 226, 155, 109, 233}
	validateVector(t, a, root)

	a = make(TestArray, 4)
	copy(a[0][:], []byte{250, 174, 33, 61, 215, 33, 81, 114, 138, 36, 195, 111, 154, 163, 224, 126, 251, 227, 38, 192, 88, 248, 95, 104, 34, 193, 220, 33, 117, 224, 157, 153})
	copy(a[1][:], []byte{41, 233, 15, 204, 75, 28, 149, 19, 188, 21, 92, 1, 141, 183, 150, 208, 126, 151, 199, 165, 0, 155, 215, 165, 238, 212, 40, 30, 147, 222, 148, 19})
	copy(a[2][:], []byte{249, 60, 52, 8, 71, 52, 73, 153, 101, 28, 27, 215, 25, 73, 203, 151, 76, 124, 173, 123, 212, 33, 204, 198, 119, 103, 15, 104, 106, 229, 32, 204})
	copy(a[3][:], []byte{118, 168, 235, 254, 38, 163, 53, 60, 39, 2, 147, 113, 145, 221, 118, 98, 21, 104, 158, 90, 7, 189, 166, 15, 255, 212, 142, 207, 194, 32, 132, 212})
	root = []byte{50, 251, 85, 206, 75, 56, 190, 244, 154, 96, 138, 178, 226, 117, 12, 255, 22, 50, 26, 246, 34, 43, 225, 20, 151, 233, 26, 249, 252, 146, 165, 63}
	validateVector(t, a, root)

	a = make(TestArray, 5)
	copy(a[0][:], []byte{252, 45, 96, 11, 46, 67, 69, 114, 33, 227, 95, 207, 66, 117, 34, 31, 102, 214, 206, 37, 11, 134, 150, 135, 157, 124, 231, 164, 151, 79, 151, 93})
	copy(a[1][:], []byte{163, 250, 12, 46, 19, 21, 31, 211, 195, 208, 2, 165, 69, 8, 25, 174, 113, 80, 161, 23, 45, 236, 173, 69, 226, 170, 147, 5, 106, 178, 69, 182})
	copy(a[2][:], []byte{235, 14, 67, 121, 148, 161, 107, 28, 59, 141, 254, 233, 155, 110, 134, 48, 199, 187, 177, 47, 136, 117, 158, 183, 116, 180, 227, 147, 92, 85, 17, 6})
	copy(a[3][:], []byte{58, 68, 220, 226, 251, 163, 242, 111, 14, 10, 226, 196, 116, 131, 232, 203, 29, 129, 95, 157, 153, 129, 240, 48, 237, 195, 128, 212, 239, 172, 79, 87})
	copy(a[4][:], []byte{82, 196, 7, 144, 85, 233, 108, 62, 243, 17, 76, 169, 49, 136, 65, 14, 138, 138, 8, 170, 126, 83, 223, 178, 187, 24, 195, 1, 117, 111, 175, 158})
	root = []byte{23, 88, 226, 198, 37, 223, 43, 60, 98, 133, 183, 139, 102, 123, 221, 123, 0, 86, 205, 53, 28, 245, 228, 182, 120, 52, 206, 148, 27, 1, 84, 194}
	validateVector(t, a, root)

}

func TestMerkleTreeInternalNodeWithOneChild(t *testing.T) {
	partitiontest.PartitionTest(t)

	var internalNodeDS = "MA"
	a := make(TestArray, 5)
	for i := uint64(0); i < 5; i++ {
		crypto.RandBytes(a[i][:])
	}
	h := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()
	leaf0Hash := crypto.GenereicHashObj(h, a[0])
	leaf1Hash := crypto.GenereicHashObj(h, a[1])
	leaf2Hash := crypto.GenereicHashObj(h, a[2])
	leaf3Hash := crypto.GenereicHashObj(h, a[3])
	leaf4Hash := crypto.GenereicHashObj(h, a[4])

	internalNode0Hash := hashInternalNode(h, internalNodeDS, leaf0Hash, leaf1Hash)
	internalNode1Hash := hashInternalNode(h, internalNodeDS, leaf2Hash, leaf3Hash)
	internalNode2Hash := hashInternalNode(h, internalNodeDS, leaf4Hash, nil)
	internalNode00Hash := hashInternalNode(h, internalNodeDS, internalNode0Hash, internalNode1Hash)
	internalNode01Hash := hashInternalNode(h, internalNodeDS, internalNode2Hash, nil)
	rootHash := hashInternalNode(h, internalNodeDS, internalNode00Hash, internalNode01Hash)

	tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	root2 := tree.Root()
	require.Equal(t, rootHash, []byte(root2))

}

func TestMerkleTreeInternalNodeFullTree(t *testing.T) {
	partitiontest.PartitionTest(t)

	var internalNodeDS = "MA"
	a := make(TestArray, 4)
	for i := uint64(0); i < 4; i++ {
		crypto.RandBytes(a[i][:])
	}
	h := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()
	leaf0Hash := crypto.GenereicHashObj(h, a[0])
	leaf1Hash := crypto.GenereicHashObj(h, a[1])
	leaf2Hash := crypto.GenereicHashObj(h, a[2])
	leaf3Hash := crypto.GenereicHashObj(h, a[3])

	internalNode0Hash := hashInternalNode(h, internalNodeDS, leaf0Hash, leaf1Hash)
	internalNode1Hash := hashInternalNode(h, internalNodeDS, leaf2Hash, leaf3Hash)
	rootHash := hashInternalNode(h, internalNodeDS, internalNode0Hash, internalNode1Hash)

	tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	root2 := tree.Root()
	require.Equal(t, rootHash, []byte(root2))

}

func hashInternalNode(h hash.Hash, internalNodeDS string, firstLeafHash []byte, secondLeafHash []byte) []byte {
	internalNode := make([]byte, 2*h.Size()+len(internalNodeDS))
	copy(internalNode, internalNodeDS)
	copy(internalNode[len(internalNodeDS):], firstLeafHash)
	copy(internalNode[len(internalNodeDS)+h.Size():], secondLeafHash)
	h.Reset()
	h.Write(internalNode)
	internalNodeHash := h.Sum(nil)
	return internalNodeHash
}

func getRegularPositions(numElets, max uint64) (res []uint64) {
	skip := max / numElets
	pos := uint64(0)
	for i := uint64(0); i < numElets; i++ {
		res = append(res, pos)
		pos += skip
	}
	return
}

func getRandomPositions(numElets, max uint64) (res []uint64) {
	used := make([]bool, max)
	for i := uint64(0); i < numElets; i++ {

		pos := crypto.RandUint64() % max
		for used[pos] {
			pos = (pos + 1) % max
		}
		used[pos] = true
		res = append(res, pos)
	}
	return
}

func testMerkelSizeLimits(t *testing.T, hashtype crypto.HashType, size uint64, positions []uint64) (*Tree, *Proof) {

	a := make(TestArray, size)
	for i := uint64(0); i < size; i++ {
		crypto.RandBytes(a[i][:])
	}

	tree, err := Build(a, crypto.HashFactory{HashType: hashtype})
	require.NoError(t, err)

	root := tree.Root()

	posMap := make(map[uint64]crypto.Hashable)
	for _, j := range positions {
		posMap[j] = a[j]
	}

	proof, err := tree.Prove(positions)
	require.NoError(t, err)

	err = Verify(root, posMap, proof)
	require.NoError(t, err)

	return tree, proof
}

func TestMerkleVC(t *testing.T) {
	partitiontest.PartitionTest(t)

	for i := uint64(0); i < 32; i++ {
		testMerkleVC(t, crypto.Sha512_256, i)
	}

	for i := uint64(0); i < 8; i++ {
		testMerkleVC(t, crypto.Sumhash, i)
	}

}

func testMerkleVC(t *testing.T, hashtype crypto.HashType, size uint64) {
	var junk TestData
	crypto.RandBytes(junk[:])

	a := make(TestArray, size)
	for i := uint64(0); i < size; i++ {
		crypto.RandBytes(a[i][:])
	}

	tree, err := BuildVectorCommitmentTree(a, crypto.HashFactory{HashType: hashtype})
	require.NoError(t, err)

	root := tree.Root()

	var allpos []uint64
	allmap := make(map[uint64]crypto.Hashable)

	for i := uint64(0); i < size; i++ {
		proof, err := tree.Prove([]uint64{i})
		require.NoError(t, err)

		err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{i: a[i]}, proof)
		require.NoError(t, err)

		err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{i: junk}, proof)
		require.Error(t, err, "no error when verifying junk")

		allpos = append(allpos, i)
		allmap[i] = a[i]
	}

	proof, err := tree.Prove(allpos)
	require.NoError(t, err)

	err = VerifyVectorCommitment(root, allmap, proof)
	require.NoError(t, err)

	err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{0: junk}, proof)
	require.Error(t, err, "no error when verifying junk batch")

	err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{0: junk}, nil)
	require.Error(t, err, "no error when verifying junk batch")

	_, err = tree.Prove([]uint64{size})
	require.Error(t, err, "no error when proving past the end")

	err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{size: junk}, nil)
	require.Error(t, err, "no error when verifying past the end")

	if size > 0 {
		var somepos []uint64
		somemap := make(map[uint64]crypto.Hashable)
		for i := 0; i < 10; i++ {
			pos := crypto.RandUint64() % size
			somepos = append(somepos, pos)
			somemap[pos] = a[pos]
		}

		proof, err = tree.Prove(somepos)
		require.NoError(t, err)

		err = VerifyVectorCommitment(root, somemap, proof)
		require.NoError(t, err)
	}
}

func TestVCOnlyOneNode(t *testing.T) {
	partitiontest.PartitionTest(t)

	var internalNodeDS = "MA"
	a := make(TestArray, 1)
	crypto.RandBytes(a[0][:])
	var bottemLeafData TestData
	copy(bottemLeafData[:], []byte{0x0})

	h := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()
	leaf0Hash := crypto.GenereicHashObj(h, a[0])
	h.Reset()
	h.Write([]byte{0x0})
	leaf1Hash := h.Sum(nil)

	rootHash := hashInternalNode(h, internalNodeDS, leaf0Hash, leaf1Hash)

	tree, err := BuildVectorCommitmentTree(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	root2 := tree.Root()
	require.Equal(t, rootHash, []byte(root2))
}

func TestVCEmptyTree(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := make(TestArray, 0)

	h := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()
	h.Reset()
	h.Write([]byte{0x0})
	root2 := h.Sum(nil)

	tree, err := BuildVectorCommitmentTree(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	rootHash := tree.Root()
	require.Equal(t, []byte(rootHash), root2)
}

func BenchmarkMerkleCommit(b *testing.B) {
	b.Run("sha512_256", func(b *testing.B) { merkleCommitBench(b, crypto.Sha512_256) })
	b.Run("sumhash", func(b *testing.B) { merkleCommitBench(b, crypto.Sumhash) })
}

func merkleCommitBench(b *testing.B, hashType crypto.HashType) {
	for sz := 10; sz <= 100000; sz *= 100 {
		msg := make(TestBuf, sz)
		crypto.RandBytes(msg[:])

		for cnt := 10; cnt <= 10000000; cnt *= 10 {
			var a TestRepeatingArray
			a.item = msg
			a.count = uint64(cnt)

			b.Run(fmt.Sprintf("Item%d/Count%d", sz, cnt), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					tree, err := Build(a, crypto.HashFactory{HashType: hashType})
					if err != nil {
						b.Error(err)
					}
					tree.Root()
				}
			})
		}
	}
}

func BenchmarkMerkleProve1M(b *testing.B) {
	b.Run("sha512_256", func(b *testing.B) { benchmarkMerkleProve1M(b, crypto.Sha512_256) })
	b.Run("sumhash", func(b *testing.B) { benchmarkMerkleProve1M(b, crypto.Sumhash) })
}

func benchmarkMerkleProve1M(b *testing.B, hashType crypto.HashType) {
	msg := TestMessage("Hello world")

	var a TestRepeatingArray
	a.item = msg
	a.count = 1024 * 1024

	tree, err := Build(a, crypto.HashFactory{HashType: hashType})
	if err != nil {
		b.Error(err)
	}

	b.ResetTimer()

	for i := uint64(0); i < uint64(b.N); i++ {
		_, err := tree.Prove([]uint64{i % a.count})
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkMerkleVerify1M(b *testing.B) {
	b.Run("sha512_256", func(b *testing.B) { benchmarkMerkleVerify1M(b, crypto.Sha512_256) })
	b.Run("sumhash", func(b *testing.B) { benchmarkMerkleVerify1M(b, crypto.Sumhash) })
}

func benchmarkMerkleVerify1M(b *testing.B, hashType crypto.HashType) {
	msg := TestMessage("Hello world")

	var a TestRepeatingArray
	a.item = msg
	a.count = 1024 * 1024

	tree, err := Build(a, crypto.HashFactory{HashType: hashType})
	if err != nil {
		b.Error(err)
	}
	root := tree.Root()

	proofs := make([]*Proof, a.count)
	for i := uint64(0); i < a.count; i++ {
		proofs[i], err = tree.Prove([]uint64{i})
		if err != nil {
			b.Error(err)
		}
	}

	b.ResetTimer()

	for i := uint64(0); i < uint64(b.N); i++ {
		err := Verify(root, map[uint64]crypto.Hashable{i % a.count: msg}, proofs[i])
		if err != nil {
			b.Error(err)
		}
	}
}
