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

package merkletrie

import (
	"crypto/sha512"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestNodeSerialization tests the serialization and deserialization of nodes.
func TestNodeSerialization(t *testing.T) {
	partitiontest.PartitionTest(t)

	var memoryCommitter InMemoryCommitter
	memConfig := defaultTestMemoryConfig
	memConfig.CachedNodesCount = 1000
	mt1, _ := MakeTrie(&memoryCommitter, memConfig)
	// create 1024 hashes.
	leafsCount := 1024
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < len(hashes); i++ {
		mt1.Add(hashes[i][:])
	}
	for _, page := range mt1.cache.pageToNIDsPtr {
		for _, pnode := range page {
			buf := make([]byte, 10000)
			consumedWrite := pnode.serialize(buf[:])
			outNode, consumedRead := deserializeNode(buf[:])
			require.Equal(t, consumedWrite, consumedRead)
			require.Equal(t, pnode.leaf(), outNode.leaf())
			require.Equal(t, len(pnode.children), len(outNode.children))
			reencodedBuffer := make([]byte, 10000)
			renecodedConsumedWrite := outNode.serialize(reencodedBuffer[:])
			require.Equal(t, consumedWrite, renecodedConsumedWrite)
			require.Equal(t, buf, reencodedBuffer)
		}
	}
}

func (n *node) leafUsingChildrenMask() bool {
	return n.childrenMask.IsZero()
}

func (n *node) leafUsingChildrenLength() bool {
	return len(n.children) == 0
}

func makeHashes(n int) [][]byte {
	hashes := make([][]byte, n)
	for i := 0; i < len(hashes); i++ {
		buf := make([]byte, 32)
		binary.BigEndian.PutUint64(buf, uint64(i))
		h := crypto.Hash(buf)
		hashes[i] = h[:]
	}
	return hashes
}

func BenchmarkNodeLeafImplementation(b *testing.B) {
	hashes := makeHashes(100000)

	b.Run("leaf-ChildrenMask", func(b *testing.B) {
		var memoryCommitter InMemoryCommitter
		memConfig := defaultTestMemoryConfig
		mt1, _ := MakeTrie(&memoryCommitter, memConfig)

		for i := 0; i < len(hashes); i++ {
			mt1.Add(hashes[i][:])
		}
		b.ResetTimer()
		k := 0
		for {
			for _, pageMap := range mt1.cache.pageToNIDsPtr {
				for _, pnode := range pageMap {
					pnode.leafUsingChildrenMask()
					k++
					if k > b.N {
						return
					}
				}
			}
		}
	})
	b.Run("leaf-ChildrenLength", func(b *testing.B) {
		var memoryCommitter InMemoryCommitter
		memConfig := defaultTestMemoryConfig
		mt1, _ := MakeTrie(&memoryCommitter, memConfig)

		for i := 0; i < len(hashes); i++ {
			mt1.Add(hashes[i][:])
		}
		b.ResetTimer()
		k := 0
		for {
			for _, pageMap := range mt1.cache.pageToNIDsPtr {
				for _, pnode := range pageMap {
					pnode.leafUsingChildrenLength()
					k++
					if k > b.N {
						return
					}
				}
			}
		}
	})
}

// calculateHashIncrementally uses the Writer interface to the crypto digest to
// avoid accumulating in a buffer. Yet it's slower! I don't know why, but
// leaving it here to benchmark more carefully later. (The final use of
// d.Sum(nil) instead of d.Sum(n.hash[:0]) is needed because we share the
// backing array for the slices in node hashes. But that is not the cause of the
// slow down.)
func (n *node) calculateHashIncrementally(cache *merkleTrieCache) error {
	if n.leaf() {
		return nil
	}
	path := n.hash

	d := sha512.New512_256()

	// we add this string length before the actual string so it could get "decoded"; in practice, it makes a good domain separator.
	d.Write([]byte{byte(len(path))})
	d.Write(path)
	for _, child := range n.children {
		childNode, err := cache.getNode(child.id)
		if err != nil {
			return err
		}
		if childNode.leaf() {
			d.Write([]byte{0})
		} else {
			d.Write([]byte{1})
		}
		// we add this string length before the actual string so it could get "decoded"; in practice, it makes a good domain separator.
		d.Write([]byte{byte(len(childNode.hash))})
		d.Write([]byte{child.hashIndex}) // adding the first byte of the child
		d.Write(childNode.hash)          // adding the reminder of the child
	}
	n.hash = d.Sum(nil)
	return nil
}

func BenchmarkAdd(b *testing.B) {
	b.ReportAllocs()

	memConfig := defaultTestMemoryConfig
	mt, _ := MakeTrie(&InMemoryCommitter{}, memConfig)
	hashes := makeHashes(b.N)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mt.Add(hashes[i])
		if i%1000 == 999 {
			mt.Commit() // not sure how often we should Commit for a nice benchmark
		}
	}
}

func BenchmarkDelete(b *testing.B) {
	b.ReportAllocs()

	memConfig := defaultTestMemoryConfig
	mt, _ := MakeTrie(&InMemoryCommitter{}, memConfig)
	hashes := makeHashes(b.N)
	for i := 0; i < b.N; i++ {
		mt.Add(hashes[i])
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mt.Delete(hashes[i])
		if i%1000 == 999 { // not sure how often we should Commit for a nice benchmark
			mt.Commit()
		}
	}
}
