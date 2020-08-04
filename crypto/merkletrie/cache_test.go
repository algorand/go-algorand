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

func verifyCacheNodeCount(t *testing.T, trie *Trie) {
	count := 0
	for _, pageNodes := range trie.cache.pageToNIDsPtr {
		count += len(pageNodes)
	}
	require.Equal(t, count, trie.cache.cachedNodeCount)

	// make sure that the pagesPrioritizationMap aligns with pagesPrioritizationList
	require.Equal(t, len(trie.cache.pagesPrioritizationMap), trie.cache.pagesPrioritizationList.Len())

	for e := trie.cache.pagesPrioritizationList.Back(); e != nil; e = e.Next() {
		page := e.Value.(uint64)
		_, has := trie.cache.pagesPrioritizationMap[page]
		require.True(t, has)
		_, has = trie.cache.pageToNIDsPtr[page]
		require.True(t, has)
	}
}

func TestCacheEviction1(t *testing.T) {
	var memoryCommitter InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter, defaultTestEvictSize)
	// create 13000 hashes.
	leafsCount := 13000
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < defaultTestEvictSize; i++ {
		mt1.Add(hashes[i][:])
	}

	for i := defaultTestEvictSize; i < len(hashes); i++ {
		mt1.Add(hashes[i][:])
		mt1.Evict(true)
		require.GreaterOrEqual(t, defaultTestEvictSize, mt1.cache.cachedNodeCount)
		verifyCacheNodeCount(t, mt1)
	}
}

func TestCacheEviction2(t *testing.T) {
	var memoryCommitter InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter, defaultTestEvictSize)
	// create 20000 hashes.
	leafsCount := 20000
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < defaultTestEvictSize; i++ {
		mt1.Add(hashes[i][:])
	}

	for i := defaultTestEvictSize; i < len(hashes); i++ {
		mt1.Delete(hashes[i-2][:])
		mt1.Add(hashes[i][:])
		mt1.Add(hashes[i-2][:])

		if i%(len(hashes)/20) == 0 {
			mt1.Evict(true)
			require.GreaterOrEqual(t, defaultTestEvictSize, mt1.cache.cachedNodeCount)
			verifyCacheNodeCount(t, mt1)
		}
	}
}

func TestCacheEviction3(t *testing.T) {
	var memoryCommitter InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter, defaultTestEvictSize)
	// create 200000 hashes.
	leafsCount := 200000
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < defaultTestEvictSize; i++ {
		mt1.Add(hashes[i][:])
	}

	for i := defaultTestEvictSize; i < len(hashes); i++ {
		mt1.Delete(hashes[i-500][:])
		mt1.Add(hashes[i][:])

		if i%(len(hashes)/20) == 0 {
			mt1.Evict(true)
			require.GreaterOrEqual(t, defaultTestEvictSize, mt1.cache.cachedNodeCount)
			verifyCacheNodeCount(t, mt1)
		}
	}
}
