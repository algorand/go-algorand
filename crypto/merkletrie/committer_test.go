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

// Duplicate duplicates the current memory committer.
func (mc *InMemoryCommitter) Duplicate() (out *InMemoryCommitter) {
	out = &InMemoryCommitter{memStore: make(map[uint64][]byte)}
	for k, v := range mc.memStore {
		out.memStore[k] = v
	}
	return
}

func TestInMemoryCommitter(t *testing.T) {
	var memoryCommitter InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter, defaultTestEvictSize)
	// create 50000 hashes.
	leafsCount := 50000
	hashes := make([]crypto.Digest, leafsCount)
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
	releasedNodes, err := mt1.Evict(true)
	require.NoError(t, err)
	savedMemoryCommitter := memoryCommitter.Duplicate()
	require.Equal(t, 18957, releasedNodes)
	for i := len(hashes) / 2; i < len(hashes); i++ {
		mt1.Add(hashes[i][:])
	}

	mt1Hash, _ := mt1.RootHash()

	mt2, _ := MakeTrie(savedMemoryCommitter, defaultTestEvictSize)

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
	require.Equal(t, 2427986, storageSize) // 2,427,986 / 50,000 ~= 48 bytes/leaf.
	stats, _ := mt1.GetStats()
	require.Equal(t, leafsCount, int(stats.leafCount))
	require.Equal(t, 61926, int(stats.nodesCount))

}

func (n *node) getChildren() (list []storedNodeIdentifier) {
	if n.leaf() {
		return []storedNodeIdentifier{}
	}
	for _, child := range n.children {
		list = append(list, child.id)

	}
	return
}

func TestNoRedundentPages(t *testing.T) {
	var memoryCommitter InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter, defaultTestEvictSize)

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
	for page, bytes := range memoryCommitter.memStore {
		if page == 0 {
			mt2, _ := MakeTrie(nil, defaultTestEvictSize)
			_, err := mt2.deserialize(bytes)
			require.NoError(t, err)
		} else {
			nodes, _ := decodePage(bytes)
			for nodeID := range nodes {
				trieNodes[nodeID] = true
			}
		}
	}
	stats, _ := mt1.GetStats()
	require.Equal(t, testSize, int(stats.leafCount))
	nodesCount := int(stats.nodesCount)
	require.Equal(t, nodesCount, len(trieNodes))
	require.Equal(t, nodesCount, mt1.cache.cachedNodeCount)
}

func TestMultipleCommits(t *testing.T) {

	testSize := 5000
	commitsCount := 5

	hashes := make([]crypto.Digest, testSize)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	var memoryCommitter1 InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter1, defaultTestEvictSize)
	for i := 0; i < len(hashes); i++ {

		mt1.Add(hashes[i][:])
		if i%(len(hashes)/commitsCount) == 0 {
			mt1.Commit()
		}
	}
	mt1.Commit()

	var memoryCommitter2 InMemoryCommitter
	mt2, _ := MakeTrie(&memoryCommitter2, defaultTestEvictSize)
	for i := 0; i < len(hashes); i++ {
		mt2.Add(hashes[i][:])
	}
	mt2.Commit()

	require.Equal(t, len(memoryCommitter1.memStore), len(memoryCommitter2.memStore))

	storageSize1 := 0
	for _, bytes := range memoryCommitter1.memStore {
		storageSize1 += len(bytes)
	}

	storageSize2 := 0
	for _, bytes := range memoryCommitter1.memStore {
		storageSize2 += len(bytes)
	}
	require.Equal(t, storageSize1, storageSize2)
}
