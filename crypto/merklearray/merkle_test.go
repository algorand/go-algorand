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
	"fmt"
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

			tree, proof := testMerkelSizeLimits(t, crypto.Sumhash, size, positions)
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

			_, proof := testMerkelSizeLimits(t, crypto.Sumhash, size, positions)
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
	tree, _ := testMerkelSizeLimits(t, crypto.Sumhash, size, []uint64{})
	bytes := protocol.Encode(tree)
	var outTree Tree
	err := protocol.Decode(bytes, &outTree)
	require.Contains(t, err.Error(), "> 17 at Levels")
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
