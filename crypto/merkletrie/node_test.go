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

func BenchmarkNodeLeafImplementation(b *testing.B) {
	b.Run("leaf-ChildrenMask", func(b *testing.B) {
		var memoryCommitter InMemoryCommitter
		memConfig := defaultTestMemoryConfig
		mt1, _ := MakeTrie(&memoryCommitter, memConfig)
		// create 100000 hashes.
		leafsCount := 100000
		hashes := make([]crypto.Digest, leafsCount)
		for i := 0; i < len(hashes); i++ {
			hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
		}

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
		// create 100000 hashes.
		leafsCount := 100000
		hashes := make([]crypto.Digest, leafsCount)
		for i := 0; i < len(hashes); i++ {
			hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
		}

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
