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
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type KATElement struct {
	expectedRoot []byte
	elements     [][]byte
}

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

func (a TestArray) Marshal(pos uint64) (crypto.Hashable, error) {
	if pos >= uint64(len(a)) {
		return nil, fmt.Errorf("pos %d larger than length %d", pos, len(a))
	}

	return a[pos], nil
}

type TestRepeatingArray struct {
	item  crypto.Hashable
	count uint64
}

func (a TestRepeatingArray) Length() uint64 {
	return a.count
}

func (a TestRepeatingArray) Marshal(pos uint64) (crypto.Hashable, error) {
	if pos >= a.count {
		return nil, fmt.Errorf("pos %d larger than length %d", pos, a.count)
	}

	return a.item, nil
}

const OutOfBoundErrorString = "larger than leaf count"

func TestMerkle(t *testing.T) {
	partitiontest.PartitionTest(t)

	increment := uint64(1)
	// with -race this will take a very long time
	// run a shorter version for Short testing
	if testing.Short() {
		increment = uint64(16)
	}

	for i := uint64(1); i < 1024; i = i + increment {
		t.Run(fmt.Sprintf("hash#%s/Size#%d", crypto.Sha512_256.String(), i), func(t *testing.T) {
			testMerkle(t, crypto.Sha512_256, i)
		})
	}

	if !testing.Short() {
		for i := uint64(1); i < 10; i++ {
			t.Run(fmt.Sprintf("hash#%s/Size#%d", crypto.Sumhash.String(), i), func(t *testing.T) {
				testMerkle(t, crypto.Sumhash, i)
			})
		}
	} else {
		t.Run(fmt.Sprintf("hash#%s/Size#%d", crypto.Sha512_256.String(), 10), func(t *testing.T) {
			testMerkle(t, crypto.Sumhash, 10)
		})

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
		require.ErrorIs(t, err, ErrRootMismatch)

		allpos = append(allpos, i)
		allmap[i] = a[i]
	}

	proof, err := tree.Prove(allpos)
	require.NoError(t, err)

	err = Verify(root, allmap, proof)
	require.NoError(t, err)

	err = Verify(root, map[uint64]crypto.Hashable{0: junk}, proof)
	require.ErrorIs(t, err, ErrRootMismatch)

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

type nonmarshalable []int

func (n nonmarshalable) Length() uint64 {
	return uint64(len(n))
}

func (n nonmarshalable) Marshal(pos uint64) (crypto.Hashable, error) {
	return nil, fmt.Errorf("can't be marshaled")
}

func TestErrorInMarshal(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := nonmarshalable{1}
	_, err := Build(&a, crypto.HashFactory{})
	require.Error(t, err)
}

func TestMerkleBuildEdgeCases(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	arr := make(TestArray, 0)
	tree, err := Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	a.Len(tree.Levels, 0)
	a.Equal(tree.NumOfElements, uint64(0))

	root := tree.Root()

	a.Equal(root, crypto.GenericDigest([]byte{}))
}

func TestMerkleVCBuildEdgeCases(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	h := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()
	h.Reset()
	h.Write([]byte(protocol.MerkleVectorCommitmentBottomLeaf))
	root2 := h.Sum(nil)

	arr := make(TestArray, 0)
	tree, err := BuildVectorCommitmentTree(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	a.Len(tree.Levels, 1)
	a.Equal(tree.NumOfElements, uint64(0))

	rootHash := tree.Root()
	require.Equal(t, []byte(rootHash), root2)
}

func TestMerkleProveEdgeCases(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	arr := make(TestArray, 4)
	for i := uint64(0); i < 4; i++ {
		crypto.RandBytes(arr[i][:])
	}

	tree, err := Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	_, err = tree.Prove([]uint64{4})
	a.Error(err)
	require.Contains(t, err.Error(), OutOfBoundErrorString)

	// prove on nothing
	proof, err := tree.Prove(nil)
	a.NoError(err)
	a.Equal(proof.Path, []crypto.GenericDigest(nil))
	a.Equal(proof.TreeDepth, uint8(2))

	arr = make(TestArray, 0)
	tree, err = Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	_, err = tree.Prove([]uint64{0})
	a.Error(err)
	require.ErrorIs(t, err, ErrProvingZeroCommitment)

	// prove on nothing - now the tree is empty as well
	proof, err = tree.Prove(nil)
	a.NoError(err)
	a.Equal(proof.Path, []crypto.GenericDigest(nil))
	a.Equal(proof.TreeDepth, uint8(0))
}

func TestMerkleVCProveEdgeCases(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	arr := make(TestArray, 5)
	for i := uint64(0); i < 5; i++ {
		crypto.RandBytes(arr[i][:])
	}
	tree, err := BuildVectorCommitmentTree(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	// element in the out of the inner array
	_, err = tree.Prove([]uint64{5})
	a.Error(err)
	require.Contains(t, err.Error(), OutOfBoundErrorString)

	// element in the padded array - bottom leaf
	_, err = tree.Prove([]uint64{8})
	a.Error(err)
	require.Contains(t, err.Error(), OutOfBoundErrorString)

	// prove on nothing
	proof, err := tree.Prove(nil)
	a.NoError(err)
	a.Equal(proof.Path, []crypto.GenericDigest(nil))
	a.Equal(proof.TreeDepth, uint8(3))

	arr = make(TestArray, 0)
	tree, err = BuildVectorCommitmentTree(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	_, err = tree.Prove([]uint64{0})
	a.Error(err)
	require.ErrorIs(t, err, ErrProvingZeroCommitment)

	// prove on nothing - now the tree is empty as well
	proof, err = tree.Prove(nil)
	a.NoError(err)
	a.Equal(proof.Path, []crypto.GenericDigest(nil))
	a.Equal(proof.TreeDepth, uint8(0))
}

func TestMerkleVerifyEdgeCases(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	arr := make(TestArray, 4)
	for i := uint64(0); i < 4; i++ {
		crypto.RandBytes(arr[i][:])
	}
	tree, err := Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	proof, err := tree.Prove([]uint64{3})
	a.NoError(err)

	root := tree.Root()

	err = Verify(root, map[uint64]crypto.Hashable{4: arr[3]}, proof)
	a.Error(err)
	require.Contains(t, err.Error(), OutOfBoundErrorString)

	err = Verify(root, map[uint64]crypto.Hashable{3: arr[3], 4: arr[3]}, proof)
	a.Error(err)
	require.Contains(t, err.Error(), OutOfBoundErrorString)

	err = Verify(root, nil, nil)
	a.Error(err)
	a.ErrorIs(ErrProofIsNil, err)

	trivialProof := Proof{TreeDepth: 2, HashFactory: crypto.HashFactory{HashType: crypto.Sha512_256}}
	err = Verify(root, nil, &trivialProof)
	a.NoError(err)

	err = Verify(root, nil, proof)
	a.Error(err)
	a.ErrorIs(ErrNonEmptyProofForEmptyElements, err)

	err = Verify(root, nil, &trivialProof)
	a.NoError(err)

	arr = make(TestArray, 1)
	for i := uint64(0); i < 1; i++ {
		crypto.RandBytes(arr[i][:])
	}

	tree, err = Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	proof, err = tree.Prove([]uint64{0})
	a.NoError(err)
	a.Equal(trivialProof.Path, []crypto.GenericDigest(nil))
	err = Verify(tree.Root(), map[uint64]crypto.Hashable{0: arr[0]}, proof)
	a.NoError(err)
}

func TestProveDuplicateLeaves(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	arr := make(TestArray, 4)
	for i := uint64(0); i < 4; i++ {
		crypto.RandBytes(arr[i][:])
	}
	tree, err := Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	proof, err := tree.Prove([]uint64{3, 3})
	a.NoError(err)

	root := tree.Root()

	err = Verify(root, map[uint64]crypto.Hashable{3: arr[3]}, proof)
	a.NoError(err)

	tree, err = BuildVectorCommitmentTree(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	proof, err = tree.Prove([]uint64{3, 3})
	a.NoError(err)

	root = tree.Root()

	err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{3: arr[3]}, proof)
	a.NoError(err)
}

func TestMerkleVCVerifyEdgeCases(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	arr := make(TestArray, 4)
	for i := uint64(0); i < 4; i++ {
		crypto.RandBytes(arr[i][:])
	}
	tree, err := BuildVectorCommitmentTree(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)

	proof, err := tree.Prove([]uint64{3})
	a.NoError(err)

	root := tree.Root()

	err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{4: arr[3]}, proof)
	a.Error(err)
	require.Contains(t, err.Error(), OutOfBoundErrorString)

	err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{3: arr[3], 4: arr[3]}, proof)
	a.Error(err)
	require.Contains(t, err.Error(), OutOfBoundErrorString)

	err = VerifyVectorCommitment(root, nil, nil)
	a.Error(err)
	a.ErrorIs(ErrProofIsNil, err)

	trivialProof := Proof{TreeDepth: 2, HashFactory: crypto.HashFactory{HashType: crypto.Sha512_256}}
	err = VerifyVectorCommitment(root, nil, &trivialProof)
	a.NoError(err)

	err = VerifyVectorCommitment(root, nil, proof)
	a.Error(err)
	a.ErrorIs(ErrNonEmptyProofForEmptyElements, err)

	err = VerifyVectorCommitment(root, nil, &trivialProof)
	a.NoError(err)

	arr = make(TestArray, 1)
	for i := uint64(0); i < 1; i++ {
		crypto.RandBytes(arr[i][:])
	}

	tree, err = Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	proof, err = tree.Prove([]uint64{0})
	a.NoError(err)
	a.Equal(trivialProof.Path, []crypto.GenericDigest(nil))
	err = VerifyVectorCommitment(tree.Root(), map[uint64]crypto.Hashable{0: arr[0]}, proof)
	a.NoError(err)
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

	// The next operations are heavy on the memory.
	// Garbage collection helps prevent trashing
	runtime.GC()

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
			t.Run(fmt.Sprintf("regular-elemetns/Depth#%d/Coefficient#%d", depth, eltCoefficient), func(t *testing.T) {
				numElts := uint64(1) << (depth - eltCoefficient)
				positions := getRegularPositions(numElts, uint64(1)<<depth)

				tree, proof := testMerkelSizeLimits(t, crypto.Sha512_256, size, positions)
				require.Equal(t, (uint64(1)<<(depth-eltCoefficient))*eltCoefficient, uint64(len(proof.Path)))

				// encode/decode
				bytes := protocol.Encode(proof)
				var outProof Proof
				err := protocol.Decode(bytes, &outProof)
				if depth > MaxEncodedTreeDepth && (eltCoefficient == 1 || eltCoefficient == 2) {
					errmsg := fmt.Sprintf("%d > %d at Path", len(proof.Path), MaxNumLeavesOnEncodedTree/2)
					require.Contains(t, err.Error(), errmsg)
				} else {
					require.NoError(t, err)
					require.Equal(t, *proof, outProof)
				}

				bytes = protocol.Encode(tree)
				var outTree Tree
				err = protocol.Decode(bytes, &outTree)
				if depth > MaxEncodedTreeDepth {
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
			})
		}

		// randomly positioned elts
		for eltCoefficient := uint64(1); eltCoefficient <= depth; eltCoefficient = eltCoefficient << increment {
			t.Run(fmt.Sprintf("random-elemetns/Depth#%d/Coefficient#%d", depth, eltCoefficient), func(t *testing.T) {
				numElts := uint64(1) << (depth - eltCoefficient)
				positions := getRandomPositions(numElts, numElts)

				_, proof := testMerkelSizeLimits(t, crypto.Sha512_256, size, positions)
				require.GreaterOrEqual(t, (uint64(1)<<(depth-eltCoefficient))*eltCoefficient, uint64(len(proof.Path)))

				if len(proof.Path) > MaxNumLeavesOnEncodedTree {
					// encode/decode
					bytes := protocol.Encode(proof)
					var outProof Proof
					err := protocol.Decode(bytes, &outProof)
					errmsg := fmt.Sprintf("%d > %d at Path", len(proof.Path), MaxNumLeavesOnEncodedTree)
					require.Contains(t, err.Error(), errmsg)
				}

			})
		}
	}

	// case of a tree with leaves 2^16 + 1
	size := (uint64(1) << MaxEncodedTreeDepth) + 1
	tree, _ := testMerkelSizeLimits(t, crypto.Sha512_256, size, []uint64{})
	bytes := protocol.Encode(tree)
	var outTree Tree
	err := protocol.Decode(bytes, &outTree)
	require.Contains(t, err.Error(), "> 17 at Levels")

	// Garbage collection helps prevent trashing
	// for next tests
	runtime.GC()
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

var KATs = []KATElement{
	{
		[]byte{223, 165, 76, 43, 118, 131, 205, 83, 151, 176, 50, 187, 236, 17, 236, 27, 119, 185, 251, 236, 90, 86, 201, 233, 66, 15, 107, 153, 128, 120, 64, 52},
		[][]byte{{212, 60, 103, 72, 82, 10, 118, 248, 31, 184, 37, 10, 169, 225, 166, 86, 240, 115, 255, 241, 229, 81, 86, 47, 173, 67, 233, 255, 251, 26, 184, 139}},
	},
	{
		[]byte{117, 207, 58, 54, 89, 80, 47, 147, 38, 223, 250, 114, 218, 81, 102, 235, 222, 29, 19, 246, 82, 156, 146, 35, 36, 135, 70, 68, 244, 183, 97, 110},
		[][]byte{
			{39, 169, 1, 19, 53, 252, 150, 220, 9, 95, 52, 138, 108, 147, 71, 211, 199, 205, 213, 108, 87, 198, 80, 41, 125, 135, 223, 149, 209, 63, 119, 11},
			{88, 120, 69, 62, 77, 91, 206, 2, 75, 78, 224, 127, 108, 87, 24, 104, 104, 243, 65, 3, 72, 245, 167, 214, 1, 192, 217, 206, 30, 254, 210, 57},
		},
	},
	{
		[]byte{7, 177, 51, 83, 39, 122, 156, 203, 107, 66, 79, 87, 58, 180, 252, 158, 38, 138, 1, 39, 206, 188, 73, 150, 82, 146, 64, 181, 226, 155, 109, 233},
		[][]byte{
			{68, 181, 96, 106, 228, 157, 129, 188, 127, 52, 81, 196, 255, 128, 57, 152, 168, 254, 0, 87, 226, 45, 99, 103, 8, 14, 90, 21, 91, 102, 16, 8},
			{112, 206, 125, 248, 189, 164, 41, 32, 245, 231, 90, 231, 136, 238, 123, 152, 9, 130, 106, 146, 112, 26, 78, 14, 73, 1, 56, 56, 14, 166, 15, 68},
			{119, 180, 57, 233, 159, 118, 74, 31, 103, 73, 230, 105, 177, 54, 31, 227, 187, 92, 228, 27, 234, 196, 181, 205, 85, 254, 81, 170, 158, 254, 60, 103},
		},
	},
	{
		[]byte{50, 251, 85, 206, 75, 56, 190, 244, 154, 96, 138, 178, 226, 117, 12, 255, 22, 50, 26, 246, 34, 43, 225, 20, 151, 233, 26, 249, 252, 146, 165, 63},
		[][]byte{
			{250, 174, 33, 61, 215, 33, 81, 114, 138, 36, 195, 111, 154, 163, 224, 126, 251, 227, 38, 192, 88, 248, 95, 104, 34, 193, 220, 33, 117, 224, 157, 153},
			{41, 233, 15, 204, 75, 28, 149, 19, 188, 21, 92, 1, 141, 183, 150, 208, 126, 151, 199, 165, 0, 155, 215, 165, 238, 212, 40, 30, 147, 222, 148, 19},
			{249, 60, 52, 8, 71, 52, 73, 153, 101, 28, 27, 215, 25, 73, 203, 151, 76, 124, 173, 123, 212, 33, 204, 198, 119, 103, 15, 104, 106, 229, 32, 204},
			{118, 168, 235, 254, 38, 163, 53, 60, 39, 2, 147, 113, 145, 221, 118, 98, 21, 104, 158, 90, 7, 189, 166, 15, 255, 212, 142, 207, 194, 32, 132, 212},
		},
	},
	{
		[]byte{23, 88, 226, 198, 37, 223, 43, 60, 98, 133, 183, 139, 102, 123, 221, 123, 0, 86, 205, 53, 28, 245, 228, 182, 120, 52, 206, 148, 27, 1, 84, 194},
		[][]byte{
			{252, 45, 96, 11, 46, 67, 69, 114, 33, 227, 95, 207, 66, 117, 34, 31, 102, 214, 206, 37, 11, 134, 150, 135, 157, 124, 231, 164, 151, 79, 151, 93},
			{163, 250, 12, 46, 19, 21, 31, 211, 195, 208, 2, 165, 69, 8, 25, 174, 113, 80, 161, 23, 45, 236, 173, 69, 226, 170, 147, 5, 106, 178, 69, 182},
			{235, 14, 67, 121, 148, 161, 107, 28, 59, 141, 254, 233, 155, 110, 134, 48, 199, 187, 177, 47, 136, 117, 158, 183, 116, 180, 227, 147, 92, 85, 17, 6},
			{58, 68, 220, 226, 251, 163, 242, 111, 14, 10, 226, 196, 116, 131, 232, 203, 29, 129, 95, 157, 153, 129, 240, 48, 237, 195, 128, 212, 239, 172, 79, 87},
			{82, 196, 7, 144, 85, 233, 108, 62, 243, 17, 76, 169, 49, 136, 65, 14, 138, 138, 8, 170, 126, 83, 223, 178, 187, 24, 195, 1, 117, 111, 175, 158},
		},
	},
}

var VCKATs = []KATElement{
	{
		[]byte{223, 165, 76, 43, 118, 131, 205, 83, 151, 176, 50, 187, 236, 17, 236, 27, 119, 185, 251, 236, 90, 86, 201, 233, 66, 15, 107, 153, 128, 120, 64, 52},
		[][]byte{{212, 60, 103, 72, 82, 10, 118, 248, 31, 184, 37, 10, 169, 225, 166, 86, 240, 115, 255, 241, 229, 81, 86, 47, 173, 67, 233, 255, 251, 26, 184, 139}},
	},
	{
		[]byte{117, 207, 58, 54, 89, 80, 47, 147, 38, 223, 250, 114, 218, 81, 102, 235, 222, 29, 19, 246, 82, 156, 146, 35, 36, 135, 70, 68, 244, 183, 97, 110},
		[][]byte{
			{39, 169, 1, 19, 53, 252, 150, 220, 9, 95, 52, 138, 108, 147, 71, 211, 199, 205, 213, 108, 87, 198, 80, 41, 125, 135, 223, 149, 209, 63, 119, 11},
			{88, 120, 69, 62, 77, 91, 206, 2, 75, 78, 224, 127, 108, 87, 24, 104, 104, 243, 65, 3, 72, 245, 167, 214, 1, 192, 217, 206, 30, 254, 210, 57},
		},
	},
	{
		[]byte{56, 245, 10, 65, 222, 10, 236, 127, 224, 228, 244, 247, 143, 31, 84, 13, 93, 198, 17, 209, 144, 160, 206, 206, 111, 1, 40, 234, 42, 2, 127, 94},
		[][]byte{
			{68, 181, 96, 106, 228, 157, 129, 188, 127, 52, 81, 196, 255, 128, 57, 152, 168, 254, 0, 87, 226, 45, 99, 103, 8, 14, 90, 21, 91, 102, 16, 8},
			{112, 206, 125, 248, 189, 164, 41, 32, 245, 231, 90, 231, 136, 238, 123, 152, 9, 130, 106, 146, 112, 26, 78, 14, 73, 1, 56, 56, 14, 166, 15, 68},
			{119, 180, 57, 233, 159, 118, 74, 31, 103, 73, 230, 105, 177, 54, 31, 227, 187, 92, 228, 27, 234, 196, 181, 205, 85, 254, 81, 170, 158, 254, 60, 103},
		},
	},
	{
		[]byte{149, 179, 79, 29, 252, 65, 254, 212, 129, 21, 202, 49, 189, 67, 34, 93, 255, 147, 245, 64, 56, 124, 35, 10, 207, 166, 67, 226, 103, 248, 141, 120},
		[][]byte{
			{250, 174, 33, 61, 215, 33, 81, 114, 138, 36, 195, 111, 154, 163, 224, 126, 251, 227, 38, 192, 88, 248, 95, 104, 34, 193, 220, 33, 117, 224, 157, 153},
			{41, 233, 15, 204, 75, 28, 149, 19, 188, 21, 92, 1, 141, 183, 150, 208, 126, 151, 199, 165, 0, 155, 215, 165, 238, 212, 40, 30, 147, 222, 148, 19},
			{249, 60, 52, 8, 71, 52, 73, 153, 101, 28, 27, 215, 25, 73, 203, 151, 76, 124, 173, 123, 212, 33, 204, 198, 119, 103, 15, 104, 106, 229, 32, 204},
			{118, 168, 235, 254, 38, 163, 53, 60, 39, 2, 147, 113, 145, 221, 118, 98, 21, 104, 158, 90, 7, 189, 166, 15, 255, 212, 142, 207, 194, 32, 132, 212},
		},
	},
	{
		[]byte{151, 119, 38, 117, 253, 236, 112, 179, 1, 14, 240, 139, 87, 243, 203, 241, 230, 247, 178, 63, 65, 17, 80, 118, 188, 195, 74, 221, 141, 140, 10, 27},
		[][]byte{
			{252, 45, 96, 11, 46, 67, 69, 114, 33, 227, 95, 207, 66, 117, 34, 31, 102, 214, 206, 37, 11, 134, 150, 135, 157, 124, 231, 164, 151, 79, 151, 93},
			{163, 250, 12, 46, 19, 21, 31, 211, 195, 208, 2, 165, 69, 8, 25, 174, 113, 80, 161, 23, 45, 236, 173, 69, 226, 170, 147, 5, 106, 178, 69, 182},
			{235, 14, 67, 121, 148, 161, 107, 28, 59, 141, 254, 233, 155, 110, 134, 48, 199, 187, 177, 47, 136, 117, 158, 183, 116, 180, 227, 147, 92, 85, 17, 6},
			{58, 68, 220, 226, 251, 163, 242, 111, 14, 10, 226, 196, 116, 131, 232, 203, 29, 129, 95, 157, 153, 129, 240, 48, 237, 195, 128, 212, 239, 172, 79, 87},
			{82, 196, 7, 144, 85, 233, 108, 62, 243, 17, 76, 169, 49, 136, 65, 14, 138, 138, 8, 170, 126, 83, 223, 178, 187, 24, 195, 1, 117, 111, 175, 158},
		},
	},
}

func TestMerkleTreeKATs(t *testing.T) {
	partitiontest.PartitionTest(t)

	for j := 0; j < len(KATs); j++ {
		a := make(TestArray, len(KATs[j].elements))
		for i := 0; i < len(KATs[j].elements); i++ {
			copy(a[i][:], KATs[j].elements[i])
		}
		root := KATs[j].expectedRoot
		tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
		require.NoError(t, err)
		root2 := tree.Root()
		require.Equal(t, root, []byte(root2), "mismatched roots on KATs index %d", j)
	}
}

func TestVCKATs(t *testing.T) {
	partitiontest.PartitionTest(t)

	for j := 0; j < len(VCKATs); j++ {
		a := make(TestArray, len(VCKATs[j].elements))
		for i := 0; i < len(VCKATs[j].elements); i++ {
			copy(a[i][:], VCKATs[j].elements[i])
		}
		root := VCKATs[j].expectedRoot
		tree, err := BuildVectorCommitmentTree(a, crypto.HashFactory{HashType: crypto.Sha512_256})
		require.NoError(t, err)
		root2 := tree.Root()
		require.Equal(t, root, []byte(root2), "mismatched roots on KATs index %d", j)
	}
}

func TestMerkleTreeInternalNodeWithOneChild(t *testing.T) {
	partitiontest.PartitionTest(t)

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

	internalNode0Hash := hashInternalNode(h, leaf0Hash, leaf1Hash)
	internalNode1Hash := hashInternalNode(h, leaf2Hash, leaf3Hash)
	internalNode2Hash := hashInternalNode(h, leaf4Hash, nil)
	internalNode00Hash := hashInternalNode(h, internalNode0Hash, internalNode1Hash)
	internalNode01Hash := hashInternalNode(h, internalNode2Hash, nil)
	rootHash := hashInternalNode(h, internalNode00Hash, internalNode01Hash)

	tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	root2 := tree.Root()
	require.Equal(t, rootHash, []byte(root2))
}

func TestMerkleTreeInternalNodeFullTree(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := make(TestArray, 4)
	for i := uint64(0); i < 4; i++ {
		crypto.RandBytes(a[i][:])
	}
	h := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()
	leaf0Hash := crypto.GenereicHashObj(h, a[0])
	leaf1Hash := crypto.GenereicHashObj(h, a[1])
	leaf2Hash := crypto.GenereicHashObj(h, a[2])
	leaf3Hash := crypto.GenereicHashObj(h, a[3])

	internalNode0Hash := hashInternalNode(h, leaf0Hash, leaf1Hash)
	internalNode1Hash := hashInternalNode(h, leaf2Hash, leaf3Hash)
	rootHash := hashInternalNode(h, internalNode0Hash, internalNode1Hash)

	tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	root2 := tree.Root()
	require.Equal(t, rootHash, []byte(root2))

}

func hashInternalNode(h hash.Hash, firstLeafHash []byte, secondLeafHash []byte) []byte {
	internalNode := make([]byte, 2*h.Size()+len(protocol.MerkleArrayNode))
	copy(internalNode, protocol.MerkleArrayNode)
	copy(internalNode[len(protocol.MerkleArrayNode):], firstLeafHash)
	copy(internalNode[len(protocol.MerkleArrayNode)+h.Size():], secondLeafHash)
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

func TestMerkleVC(t *testing.T) {
	partitiontest.PartitionTest(t)

	for i := uint64(1); i < 32; i++ {
		t.Run(fmt.Sprintf("hash#%s/Size#%d", crypto.Sha512_256.String(), i), func(t *testing.T) {
			testMerkleVC(t, crypto.Sha512_256, i)
		})
	}

	for i := uint64(1); i < 8; i++ {
		t.Run(fmt.Sprintf("hash#%s/Size#%d", crypto.Sumhash.String(), i), func(t *testing.T) {
			testMerkleVC(t, crypto.Sumhash, i)
		})
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
		require.ErrorIs(t, err, ErrRootMismatch)

		allpos = append(allpos, i)
		allmap[i] = a[i]
	}

	proof, err := tree.Prove(allpos)
	require.NoError(t, err)

	err = VerifyVectorCommitment(root, allmap, proof)
	require.NoError(t, err)

	err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{0: junk}, proof)
	require.ErrorIs(t, err, ErrRootMismatch)

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

func TestMerkleTreeOneLeaf(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := make(TestArray, 1)

	copy(a[0][:], []byte{0x1, 0x2})

	h := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()
	rootHash := crypto.GenereicHashObj(h, a[0])

	tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	root2 := tree.Root()
	require.Equal(t, rootHash, []byte(root2))
}

func TestVCOneLeaf(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := make(TestArray, 1)

	copy(a[0][:], []byte{0x1, 0x2})

	h := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()
	rootHash := crypto.GenereicHashObj(h, a[0])

	tree, err := BuildVectorCommitmentTree(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	root2 := tree.Root()
	require.Equal(t, rootHash, []byte(root2))
}

func TestTreeDepthField(t *testing.T) {
	partitiontest.PartitionTest(t)

	var sizes = []int{1, 2, 3}
	var expectedDepth = []int{0, 1, 2}

	// array with 0 elements
	a := require.New(t)
	size := uint64(0)
	arr := make(TestArray, size)
	for i := uint64(0); i < size; i++ {
		crypto.RandBytes(arr[i][:])
	}

	tree, err := BuildVectorCommitmentTree(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	p, err := tree.Prove([]uint64{})
	require.NoError(t, err)
	require.Equal(t, p.TreeDepth, uint8(0))

	tree, err = Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	p, err = tree.Prove([]uint64{})
	require.NoError(t, err)
	require.Equal(t, p.TreeDepth, uint8(0))

	for i := 0; i < len(sizes); i++ {
		a = require.New(t)
		size = uint64(sizes[i])
		arr = make(TestArray, size)
		for i := uint64(0); i < size; i++ {
			crypto.RandBytes(arr[i][:])
		}

		tree, err = BuildVectorCommitmentTree(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
		a.NoError(err)
		p, err = tree.Prove([]uint64{})
		require.NoError(t, err)
		require.Equal(t, p.TreeDepth, uint8(expectedDepth[i]))

		tree, err = Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
		a.NoError(err)
		p, err = tree.Prove([]uint64{})
		require.NoError(t, err)
		require.Equal(t, p.TreeDepth, uint8(expectedDepth[i]))

		p, err = tree.Prove([]uint64{uint64(i)})
		require.NoError(t, err)
		require.Equal(t, p.TreeDepth, uint8(expectedDepth[i]))

		tree, err = Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
		a.NoError(err)
		p, err = tree.Prove([]uint64{uint64(i)})
		require.NoError(t, err)
		require.Equal(t, p.TreeDepth, uint8(expectedDepth[i]))
	}
}

func TestTreeNumOfLeavesField(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	arr := make(TestArray, 1)
	crypto.RandBytes(arr[0][:])
	tree, err := Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	a.Equal(tree.NumOfElements, uint64(1))

	arr = make(TestArray, 2)
	crypto.RandBytes(arr[0][:])
	crypto.RandBytes(arr[1][:])
	tree, err = Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	a.Equal(tree.NumOfElements, uint64(2))

	arr = make(TestArray, 3)
	crypto.RandBytes(arr[0][:])
	crypto.RandBytes(arr[1][:])
	crypto.RandBytes(arr[2][:])
	tree, err = Build(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	a.Equal(tree.NumOfElements, uint64(3))

	arr = make(TestArray, 1)
	crypto.RandBytes(arr[0][:])
	tree, err = BuildVectorCommitmentTree(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	a.Equal(tree.NumOfElements, uint64(1))

	arr = make(TestArray, 2)
	crypto.RandBytes(arr[0][:])
	crypto.RandBytes(arr[1][:])
	tree, err = BuildVectorCommitmentTree(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	a.Equal(tree.NumOfElements, uint64(2))

	arr = make(TestArray, 3)
	crypto.RandBytes(arr[0][:])
	crypto.RandBytes(arr[1][:])
	crypto.RandBytes(arr[2][:])
	tree, err = BuildVectorCommitmentTree(arr, crypto.HashFactory{HashType: crypto.Sha512_256})
	a.NoError(err)
	a.Equal(tree.NumOfElements, uint64(3))
}

func TestProveSingleLeaf(t *testing.T) {
	partitiontest.PartitionTest(t)

	size := uint64(15)
	a := make(TestArray, size)
	for i := uint64(0); i < size; i++ {
		crypto.RandBytes(a[i][:])
	}

	tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	root := tree.Root()

	for i := uint64(0); i < size; i++ {
		proof, err := tree.Prove([]uint64{i})
		require.NoError(t, err)

		singleLeafproof, err := tree.ProveSingleLeaf(i)
		require.NoError(t, err)

		require.Equal(t, singleLeafproof.ToProof(), proof)

		err = Verify(root, map[uint64]crypto.Hashable{i: a[i]}, singleLeafproof.ToProof())
		require.NoError(t, err)
	}
}

func TestVCProveSingleLeaf(t *testing.T) {
	partitiontest.PartitionTest(t)

	size := uint64(15)
	a := make(TestArray, size)
	for i := uint64(0); i < size; i++ {
		crypto.RandBytes(a[i][:])
	}

	tree, err := BuildVectorCommitmentTree(a, crypto.HashFactory{HashType: crypto.Sha512_256})
	require.NoError(t, err)

	root := tree.Root()

	for i := uint64(0); i < size; i++ {
		proof, err := tree.Prove([]uint64{i})
		require.NoError(t, err)

		singleLeafproof, err := tree.ProveSingleLeaf(i)
		require.NoError(t, err)

		require.Equal(t, singleLeafproof.ToProof(), proof)

		err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{i: a[i]}, singleLeafproof.ToProof())
		require.NoError(t, err)
	}
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
					require.NoError(b, err)
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
	require.NoError(b, err)

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
	require.NoError(b, err)
	root := tree.Root()

	proofs := make([]*Proof, a.count)
	for i := uint64(0); i < a.count; i++ {
		proofs[i], err = tree.Prove([]uint64{i})
		require.NoError(b, err)
	}

	b.ResetTimer()

	for i := uint64(0); i < uint64(b.N); i++ {
		err := Verify(root, map[uint64]crypto.Hashable{i % a.count: msg}, proofs[i])
		require.NoError(b, err)
	}
}
