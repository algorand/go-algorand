// Copyright (C) 2019-2020 Algorand, Inc.
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
)

func TestInMemoryCommitter(t *testing.T) {
	var memoryCommitter InMemoryCommitter
	mt1 := MakeMerkleTrie(&memoryCommitter)
	// create 100000 hashes.
	hashes := make([]crypto.Digest, 100000)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < len(hashes)/4; i++ {
		mt1.Add(hashes[i][:])
	}
	mt1.Commit()
	for i := len(hashes) / 4; i < len(hashes)/2; i++ {
		mt1.Add(hashes[i][:])
	}
	mt1.Commit()
	releasedNodes := mt1.Evict()
	require.Equal(t, 52048, releasedNodes)
	for i := len(hashes) / 2; i < len(hashes); i++ {
		mt1.Add(hashes[i][:])
	}

	mt1Hash, _ := mt1.RootHash()

	mt2 := MakeMerkleTrie(&memoryCommitter)

	for i := len(hashes) / 2; i < len(hashes); i++ {
		mt2.Add(hashes[i][:])
	}

	mt2Hash, _ := mt2.RootHash()

	require.Equal(t, mt1Hash, mt2Hash)
	require.Equal(t, 347, len(memoryCommitter.memStore)) // 347 pages.
	// find the size of all the storage.
	storageSize := 0
	for _, bytes := range memoryCommitter.memStore {
		storageSize += len(bytes)
	}
	require.Equal(t, 2748792, storageSize) // 2,748,792 / 50,000 ~= 55 bytes/leaf.
	stats, _ := mt1.GetStats()
	require.Equal(t, 100000, int(stats.leafCount))
	require.Equal(t, 130114, int(stats.nodesCount))

}

func (n *node) getChildren() (list []storedNodeIdentifier) {
	if n.leaf {
		return []storedNodeIdentifier{}
	}
	i := n.firstChild
	for {
		list = append(list, n.children[i])
		if i == n.childrenNext[i] {
			return
		}
		i = n.childrenNext[i]
	}
}

func TestNoRedundentPages(t *testing.T) {
	var memoryCommitter InMemoryCommitter
	mt1 := MakeMerkleTrie(&memoryCommitter)

	testSize := 20000
	// create 20000 hashes.
	hashes := make([]crypto.Digest, testSize)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}
	for i := 0; i < len(hashes); i++ {
		mt1.Add(hashes[i][:])
	}
	mt1.Commit()

	trieNodes := make(map[storedNodeIdentifier]bool)
	for _, bytes := range memoryCommitter.memStore {
		nodes, _ := decodePage(bytes)
		for nodeID := range nodes {
			trieNodes[nodeID] = true
		}
	}
	stats, _ := mt1.GetStats()
	require.Equal(t, testSize, int(stats.leafCount))
	nodesCount := int(stats.nodesCount)
	require.Equal(t, nodesCount, len(trieNodes))
	require.Equal(t, nodesCount, len(mt1.cache.idToPtr))
}
