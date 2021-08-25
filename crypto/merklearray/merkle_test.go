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

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
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

	for i := uint64(0); i < 1024; i++ {
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
	allmap := make(map[uint64]crypto.GenericDigest)

	hsh, err := crypto.HashFactory{HashType: hashtype}.NewHash()
	require.NoError(t, err)

	for i := uint64(0); i < size; i++ {
		proof, err := tree.Prove([]uint64{i})
		require.NoError(t, err)

		err = Verify(root, map[uint64]crypto.GenericDigest{i: crypto.HashSum(hsh, a[i])}, proof)
		require.NoError(t, err)

		err = Verify(root, map[uint64]crypto.GenericDigest{i: crypto.HashSum(hsh, junk)}, proof)
		require.Error(t, err, "no error when verifying junk")

		allpos = append(allpos, i)
		allmap[i] = crypto.HashSum(hsh, a[i])
	}

	proof, err := tree.Prove(allpos)
	require.NoError(t, err)

	err = Verify(root, allmap, proof)
	require.NoError(t, err)

	err = Verify(root, map[uint64]crypto.GenericDigest{0: crypto.HashSum(hsh, junk)}, proof)
	require.Error(t, err, "no error when verifying junk batch")

	err = Verify(root, map[uint64]crypto.GenericDigest{0: crypto.HashSum(hsh, junk)}, nil)
	require.Error(t, err, "no error when verifying junk batch")

	_, err = tree.Prove([]uint64{size})
	require.Error(t, err, "no error when proving past the end")

	err = Verify(root, map[uint64]crypto.GenericDigest{size: crypto.HashSum(hsh, junk)}, nil)
	require.Error(t, err, "no error when verifying past the end")

	if size > 0 {
		var somepos []uint64
		somemap := make(map[uint64]crypto.GenericDigest)
		for i := 0; i < 10; i++ {
			pos := crypto.RandUint64() % size
			somepos = append(somepos, pos)
			somemap[pos] = crypto.HashSum(hsh, a[pos])
		}

		proof, err = tree.Prove(somepos)
		require.NoError(t, err)

		err = Verify(root, somemap, proof)
		require.NoError(t, err)
	}
}

func TestEmptyProveStructure(t *testing.T) {
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
	a := nonmarshalable{1}
	_, err := Build(&a, crypto.HashFactory{})
	require.Error(t, err)
}

func TestVerifyWithNoElements(t *testing.T) {
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
	err = Verify(tree.Root(), map[uint64]crypto.GenericDigest{}, p)
	require.Error(t, err)

	err = Verify(tree.Root(), map[uint64]crypto.GenericDigest{}, nil)
	require.NoError(t, err)
}

func TestEmptyTree(t *testing.T) {
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
	for sz := 10; sz <= 100000; sz *= 100 {
		msg := make(TestBuf, sz)
		crypto.RandBytes(msg[:])

		for cnt := 10; cnt <= 10000000; cnt *= 10 {
			var a TestRepeatingArray
			a.item = msg
			a.count = uint64(cnt)

			b.Run(fmt.Sprintf("Item%d/Count%d", sz, cnt), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
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
	msg := TestMessage("Hello world")

	var a TestRepeatingArray
	a.item = msg
	a.count = 1024 * 1024

	tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
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
	msg := TestMessage("Hello world")

	var a TestRepeatingArray
	a.item = msg
	a.count = 1024 * 1024

	tree, err := Build(a, crypto.HashFactory{HashType: crypto.Sha512_256})
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
		err := Verify(root, map[uint64]crypto.GenericDigest{i % a.count: crypto.HashObj(msg).ToSlice()}, proofs[i])
		if err != nil {
			b.Error(err)
		}
	}
}
