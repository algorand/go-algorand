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
	"encoding/hex"
	"fmt"
	"hash"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// Hex encoded strings representing the byte arrays
type KATElement struct {
	expectedRoot string
	elements     []string
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
	require.ErrorIs(t, err, ErrPosOutOfBound)

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
	require.ErrorIs(t, err, ErrPosOutOfBound)

	// element in the padded array - bottom leaf
	_, err = tree.Prove([]uint64{8})
	a.Error(err)
	require.ErrorIs(t, err, ErrPosOutOfBound)

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
	require.ErrorIs(t, err, ErrPosOutOfBound)

	err = Verify(root, map[uint64]crypto.Hashable{3: arr[3], 4: arr[3]}, proof)
	a.Error(err)
	require.ErrorIs(t, err, ErrPosOutOfBound)

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
	require.ErrorIs(t, err, ErrPosOutOfBound)

	err = VerifyVectorCommitment(root, map[uint64]crypto.Hashable{3: arr[3], 4: arr[3]}, proof)
	a.Error(err)
	require.ErrorIs(t, err, ErrPosOutOfBound)

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

var KATsSHA256 = []KATElement{
	{
		"5a7fb9d3fb8976d942feac36d762b8d0530476c022c297582123eca18ad8c7b8",
		[]string{
			"d43c6748520a76f81fb8250aa9e1a656f073fff1e551562fad43e9fffb1ab88b",
		},
	},
	{
		"c9bc24bd5fc8961a8721458fd93044871c9009fe4c66b9614744dd6e9216d93f",
		[]string{
			"27a9011335fc96dc095f348a6c9347d3c7cdd56c57c650297d87df95d13f770b",
			"5878453e4d5bce024b4ee07f6c57186868f3410348f5a7d601c0d9ce1efed239",
		},
	},
	{
		"ad1828b8460ec541fdbeee2eb4f9d37cfad9da54c0c3a98b1eb20d24de9af6ce",
		[]string{
			"44b5606ae49d81bc7f3451c4ff803998a8fe0057e22d6367080e5a155b661008",
			"70ce7df8bda42920f5e75ae788ee7b9809826a92701a4e0e490138380ea60f44",
			"77b439e99f764a1f6749e669b1361fe3bb5ce41beac4b5cd55fe51aa9efe3c67",
		},
	},
	{
		"d78b0c411d1360bd6d49c755a60f9ada519942911411269637287bd0b5c19bab",
		[]string{
			"faae213dd72151728a24c36f9aa3e07efbe326c058f85f6822c1dc2175e09d99",
			"29e90fcc4b1c9513bc155c018db796d07e97c7a5009bd7a5eed4281e93de9413",
			"f93c340847344999651c1bd71949cb974c7cad7bd421ccc677670f686ae520cc",
			"76a8ebfe26a3353c2702937191dd766215689e5a07bda60fffd48ecfc22084d4",
		},
	},
	{
		"f8744f4648d1974c38fca858873006126d93f1a150f0eb7da1072fef83e66341",
		[]string{
			"fc2d600b2e43457221e35fcf4275221f66d6ce250b8696879d7ce7a4974f975d",
			"a3fa0c2e13151fd3c3d002a5450819ae7150a1172decad45e2aa93056ab245b6",
			"eb0e437994a16b1c3b8dfee99b6e8630c7bbb12f88759eb774b4e3935c551106",
			"3a44dce2fba3f26f0e0ae2c47483e8cb1d815f9d9981f030edc380d4efac4f57",
			"52c4079055e96c3ef3114ca93188410e8a8a08aa7e53dfb2bb18c301756faf9e",
		},
	},
}

var KATsSUMHASH = []KATElement{
	{
		"a1951e9ec9d630a975fbbdf5fa290f66bf2c55fbf5ec5ad5de08d281a971d97a64a0475d6d93ddda4480b1dbaaf33f7d72f79f9076da029e148fca0ba354b58c",
		[]string{
			"d43c6748520a76f81fb8250aa9e1a656f073fff1e551562fad43e9fffb1ab88b",
		},
	},
	{
		"8b60182211195e366021236b8bd26b004f0773f41de837dff8c483357d26aff1c06c8692b96df11fe30b2c87e6400a005d7f6e71e9b3b1f39207fe4525719cd2",
		[]string{
			"27a9011335fc96dc095f348a6c9347d3c7cdd56c57c650297d87df95d13f770b",
			"5878453e4d5bce024b4ee07f6c57186868f3410348f5a7d601c0d9ce1efed239",
		},
	},
	{
		"8c427bfa1723d733b20ac58e2ce6c9791a25e9bdd57e1dc252e98b6b909a089e1c9077cea3852df6495cacbe750f41a777c593e5ce5d132d49b354b2790ae9a8",
		[]string{
			"44b5606ae49d81bc7f3451c4ff803998a8fe0057e22d6367080e5a155b661008",
			"70ce7df8bda42920f5e75ae788ee7b9809826a92701a4e0e490138380ea60f44",
			"77b439e99f764a1f6749e669b1361fe3bb5ce41beac4b5cd55fe51aa9efe3c67",
		},
	},
	{
		"09b34fb15d43b16a22e7830ede8df4f84f4b63f46af2f6843aaf36a08c5652bcdf033162e2002c658265f4395058af1b4cef13dee70ebef4ca2cd8e870bd50c6",
		[]string{
			"faae213dd72151728a24c36f9aa3e07efbe326c058f85f6822c1dc2175e09d99",
			"29e90fcc4b1c9513bc155c018db796d07e97c7a5009bd7a5eed4281e93de9413",
			"f93c340847344999651c1bd71949cb974c7cad7bd421ccc677670f686ae520cc",
			"76a8ebfe26a3353c2702937191dd766215689e5a07bda60fffd48ecfc22084d4",
		},
	},
	{
		"6a55c0f451c211e1c961871cc0bb640c103768f0d25ddfa0b1c1d054e92adcd1480cdca21af805da887540d343fe78a3a515c761becc7e66371b740f6ff13b6b",
		[]string{
			"fc2d600b2e43457221e35fcf4275221f66d6ce250b8696879d7ce7a4974f975d",
			"a3fa0c2e13151fd3c3d002a5450819ae7150a1172decad45e2aa93056ab245b6",
			"eb0e437994a16b1c3b8dfee99b6e8630c7bbb12f88759eb774b4e3935c551106",
			"3a44dce2fba3f26f0e0ae2c47483e8cb1d815f9d9981f030edc380d4efac4f57",
			"52c4079055e96c3ef3114ca93188410e8a8a08aa7e53dfb2bb18c301756faf9e",
		},
	},
}

var KATsSHA512_256 = []KATElement{
	{
		"dfa54c2b7683cd5397b032bbec11ec1b77b9fbec5a56c9e9420f6b9980784034",
		[]string{
			"d43c6748520a76f81fb8250aa9e1a656f073fff1e551562fad43e9fffb1ab88b",
		},
	},
	{
		"75cf3a3659502f9326dffa72da5166ebde1d13f6529c922324874644f4b7616e",
		[]string{
			"27a9011335fc96dc095f348a6c9347d3c7cdd56c57c650297d87df95d13f770b",
			"5878453e4d5bce024b4ee07f6c57186868f3410348f5a7d601c0d9ce1efed239",
		},
	},
	{
		"07b13353277a9ccb6b424f573ab4fc9e268a0127cebc4996529240b5e29b6de9",
		[]string{
			"44b5606ae49d81bc7f3451c4ff803998a8fe0057e22d6367080e5a155b661008",
			"70ce7df8bda42920f5e75ae788ee7b9809826a92701a4e0e490138380ea60f44",
			"77b439e99f764a1f6749e669b1361fe3bb5ce41beac4b5cd55fe51aa9efe3c67",
		},
	},
	{
		"32fb55ce4b38bef49a608ab2e2750cff16321af6222be11497e91af9fc92a53f",
		[]string{
			"faae213dd72151728a24c36f9aa3e07efbe326c058f85f6822c1dc2175e09d99",
			"29e90fcc4b1c9513bc155c018db796d07e97c7a5009bd7a5eed4281e93de9413",
			"f93c340847344999651c1bd71949cb974c7cad7bd421ccc677670f686ae520cc",
			"76a8ebfe26a3353c2702937191dd766215689e5a07bda60fffd48ecfc22084d4",
		},
	},
	{
		"1758e2c625df2b3c6285b78b667bdd7b0056cd351cf5e4b67834ce941b0154c2",
		[]string{
			"fc2d600b2e43457221e35fcf4275221f66d6ce250b8696879d7ce7a4974f975d",
			"a3fa0c2e13151fd3c3d002a5450819ae7150a1172decad45e2aa93056ab245b6",
			"eb0e437994a16b1c3b8dfee99b6e8630c7bbb12f88759eb774b4e3935c551106",
			"3a44dce2fba3f26f0e0ae2c47483e8cb1d815f9d9981f030edc380d4efac4f57",
			"52c4079055e96c3ef3114ca93188410e8a8a08aa7e53dfb2bb18c301756faf9e",
		},
	},
}

var VCKATs = []KATElement{
	{
		"dfa54c2b7683cd5397b032bbec11ec1b77b9fbec5a56c9e9420f6b9980784034",
		[]string{
			"d43c6748520a76f81fb8250aa9e1a656f073fff1e551562fad43e9fffb1ab88b",
		},
	},
	{
		"75cf3a3659502f9326dffa72da5166ebde1d13f6529c922324874644f4b7616e",
		[]string{
			"27a9011335fc96dc095f348a6c9347d3c7cdd56c57c650297d87df95d13f770b",
			"5878453e4d5bce024b4ee07f6c57186868f3410348f5a7d601c0d9ce1efed239",
		},
	},
	{
		"38f50a41de0aec7fe0e4f4f78f1f540d5dc611d190a0cece6f0128ea2a027f5e",
		[]string{
			"44b5606ae49d81bc7f3451c4ff803998a8fe0057e22d6367080e5a155b661008",
			"70ce7df8bda42920f5e75ae788ee7b9809826a92701a4e0e490138380ea60f44",
			"77b439e99f764a1f6749e669b1361fe3bb5ce41beac4b5cd55fe51aa9efe3c67",
		},
	},
	{
		"95b34f1dfc41fed48115ca31bd43225dff93f540387c230acfa643e267f88d78",
		[]string{
			"faae213dd72151728a24c36f9aa3e07efbe326c058f85f6822c1dc2175e09d99",
			"29e90fcc4b1c9513bc155c018db796d07e97c7a5009bd7a5eed4281e93de9413",
			"f93c340847344999651c1bd71949cb974c7cad7bd421ccc677670f686ae520cc",
			"76a8ebfe26a3353c2702937191dd766215689e5a07bda60fffd48ecfc22084d4",
		},
	},
	{
		"97772675fdec70b3010ef08b57f3cbf1e6f7b23f41115076bcc34add8d8c0a1b",
		[]string{
			"fc2d600b2e43457221e35fcf4275221f66d6ce250b8696879d7ce7a4974f975d",
			"a3fa0c2e13151fd3c3d002a5450819ae7150a1172decad45e2aa93056ab245b6",
			"eb0e437994a16b1c3b8dfee99b6e8630c7bbb12f88759eb774b4e3935c551106",
			"3a44dce2fba3f26f0e0ae2c47483e8cb1d815f9d9981f030edc380d4efac4f57",
			"52c4079055e96c3ef3114ca93188410e8a8a08aa7e53dfb2bb18c301756faf9e",
		},
	},
}

func TestMerkleTreeKATs(t *testing.T) {
	partitiontest.PartitionTest(t)

	testMerkleTreeKATsAux(t, KATsSHA512_256, crypto.Sha512_256)
	testMerkleTreeKATsAux(t, KATsSUMHASH, crypto.Sumhash)
	testMerkleTreeKATsAux(t, KATsSHA256, crypto.Sha256)
}

func testMerkleTreeKATsAux(t *testing.T, KATs []KATElement, hashType crypto.HashType) {
	for j := 0; j < len(KATs); j++ {
		a := make(TestArray, len(KATs[j].elements))
		for i := 0; i < len(KATs[j].elements); i++ {
			decodedBytes, err := hex.DecodeString(KATs[j].elements[i])
			require.NoError(t, err)
			copy(a[i][:], decodedBytes)
		}
		root := KATs[j].expectedRoot
		tree, err := Build(a, crypto.HashFactory{HashType: hashType})
		require.NoError(t, err)
		root2 := hex.EncodeToString(tree.Root())
		require.Equal(t, root, root2, "mismatched roots on KATs %s index %d", hashType.String(), j)
	}
}

func TestVCKATs(t *testing.T) {
	partitiontest.PartitionTest(t)

	for j := 0; j < len(VCKATs); j++ {
		a := make(TestArray, len(VCKATs[j].elements))
		for i := 0; i < len(VCKATs[j].elements); i++ {
			decodedBytes, err := hex.DecodeString(VCKATs[j].elements[i])
			require.NoError(t, err)
			copy(a[i][:], decodedBytes)
		}
		root := VCKATs[j].expectedRoot
		tree, err := BuildVectorCommitmentTree(a, crypto.HashFactory{HashType: crypto.Sha512_256})
		require.NoError(t, err)
		root2 := hex.EncodeToString(tree.Root())
		require.Equal(t, root, root2, "mismatched roots on VCKATs index %d", j)
	}
}

func TestMerkleTreeInternalNodeWithOneChild(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := make(TestArray, 5)
	for i := uint64(0); i < 5; i++ {
		crypto.RandBytes(a[i][:])
	}
	h := crypto.HashFactory{HashType: crypto.Sha512_256}.NewHash()
	leaf0Hash := crypto.GenericHashObj(h, a[0])
	leaf1Hash := crypto.GenericHashObj(h, a[1])
	leaf2Hash := crypto.GenericHashObj(h, a[2])
	leaf3Hash := crypto.GenericHashObj(h, a[3])
	leaf4Hash := crypto.GenericHashObj(h, a[4])

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
	leaf0Hash := crypto.GenericHashObj(h, a[0])
	leaf1Hash := crypto.GenericHashObj(h, a[1])
	leaf2Hash := crypto.GenericHashObj(h, a[2])
	leaf3Hash := crypto.GenericHashObj(h, a[3])

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
	rootHash := crypto.GenericHashObj(h, a[0])

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
	rootHash := crypto.GenericHashObj(h, a[0])

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
	b.Run("sha256", func(b *testing.B) { merkleCommitBench(b, crypto.Sha256) })
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
	b.Run("sha256", func(b *testing.B) { benchmarkMerkleProve1M(b, crypto.Sha256) })
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
	b.Run("sha256", func(b *testing.B) { benchmarkMerkleVerify1M(b, crypto.Sha256) })
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
