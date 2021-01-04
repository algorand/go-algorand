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
)

type TestMessage string

func (m TestMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, []byte(m)
}

type TestData crypto.Digest

func (d TestData) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Message, d[:]
}

type TestArray []TestData

func (a TestArray) Length() uint64 {
	return uint64(len(a))
}

func (a TestArray) Get(pos uint64) (crypto.Hashable, error) {
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

func (a TestRepeatingArray) Get(pos uint64) (crypto.Hashable, error) {
	if pos >= a.count {
		return nil, fmt.Errorf("pos %d larger than length %d", pos, a.count)
	}

	return a.item, nil
}

func TestMerkle(t *testing.T) {
	var junk TestData
	crypto.RandBytes(junk[:])

	for sz := uint64(0); sz < 1024; sz++ {
		a := make(TestArray, sz)
		for i := uint64(0); i < sz; i++ {
			crypto.RandBytes(a[i][:])
		}

		tree, err := Build(a)
		if err != nil {
			t.Error(err)
		}

		root := tree.Root()

		var allpos []uint64
		allmap := make(map[uint64]crypto.Hashable)

		for i := uint64(0); i < sz; i++ {
			proof, err := tree.Prove([]uint64{i})
			if err != nil {
				t.Error(err)
			}

			err = Verify(root, map[uint64]crypto.Hashable{i: a[i]}, proof)
			if err != nil {
				t.Error(err)
			}

			err = Verify(root, map[uint64]crypto.Hashable{i: junk}, proof)
			if err == nil {
				t.Errorf("no error when verifying junk")
			}

			allpos = append(allpos, i)
			allmap[i] = a[i]
		}

		proof, err := tree.Prove(allpos)
		if err != nil {
			t.Error(err)
		}

		err = Verify(root, allmap, proof)
		if err != nil {
			t.Error(err)
		}

		err = Verify(root, map[uint64]crypto.Hashable{0: junk}, proof)
		if err == nil {
			t.Errorf("no error when verifying junk batch")
		}

		err = Verify(root, map[uint64]crypto.Hashable{0: junk}, nil)
		if err == nil {
			t.Errorf("no error when verifying junk batch")
		}

		_, err = tree.Prove([]uint64{sz})
		if err == nil {
			t.Errorf("no error when proving past the end")
		}

		err = Verify(root, map[uint64]crypto.Hashable{sz: junk}, nil)
		if err == nil {
			t.Errorf("no error when verifying past the end")
		}

		if sz > 0 {
			var somepos []uint64
			somemap := make(map[uint64]crypto.Hashable)
			for i := 0; i < 10; i++ {
				pos := crypto.RandUint64() % sz
				somepos = append(somepos, pos)
				somemap[pos] = a[pos]
			}

			proof, err = tree.Prove(somepos)
			if err != nil {
				t.Error(err)
			}

			err = Verify(root, somemap, proof)
			if err != nil {
				t.Error(err)
			}
		}
	}
}

func BenchmarkMerkleCommit(b *testing.B) {
	msg := TestMessage("Hello world")

	var a TestRepeatingArray
	a.item = msg
	a.count = uint64(b.N)

	tree, err := Build(a)
	if err != nil {
		b.Error(err)
	}
	tree.Root()
}

func BenchmarkMerkleProve1M(b *testing.B) {
	msg := TestMessage("Hello world")

	var a TestRepeatingArray
	a.item = msg
	a.count = 1024 * 1024

	tree, err := Build(a)
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

	tree, err := Build(a)
	if err != nil {
		b.Error(err)
	}
	root := tree.Root()

	proofs := make([][]crypto.Digest, a.count)
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
