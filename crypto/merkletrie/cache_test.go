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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var defaultTestMemoryConfig = MemoryConfig{
	NodesCountPerPage:         inMemoryCommitterPageSize,
	CachedNodesCount:          defaultTestEvictSize,
	PageFillFactor:            0.90,
	MaxChildrenPagesThreshold: 32,
}

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
	}
}

func TestCacheEviction1(t *testing.T) {
	partitiontest.PartitionTest(t)

	var memoryCommitter InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter, defaultTestMemoryConfig)
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
	partitiontest.PartitionTest(t)

	var memoryCommitter InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter, defaultTestMemoryConfig)
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
	partitiontest.PartitionTest(t)

	var memoryCommitter InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter, defaultTestMemoryConfig)
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

// smallPageMemoryCommitter is an InMemoryCommitter, which has a custom page size, and knows how to "fail" per request.
type smallPageMemoryCommitter struct {
	InMemoryCommitter
	failStore int
	failLoad  int
}

// StorePage stores a single page in an in-memory persistence.
func (spmc *smallPageMemoryCommitter) StorePage(page uint64, content []byte) error {
	if spmc.failStore > 0 {
		spmc.failStore--
		return fmt.Errorf("failStore>0")
	}
	return spmc.InMemoryCommitter.StorePage(page, content)
}

// LoadPage load a single page from an in-memory persistence.
func (spmc *smallPageMemoryCommitter) LoadPage(page uint64) (content []byte, err error) {
	if spmc.failLoad > 0 {
		spmc.failLoad--
		return nil, fmt.Errorf("failLoad>0")
	}
	return spmc.InMemoryCommitter.LoadPage(page)
}

func cacheEvictionFuzzer(t *testing.T, hashes []crypto.Digest, pageSize int64, evictSize int) {
	var memoryCommitter smallPageMemoryCommitter
	memoryConfig := defaultTestMemoryConfig
	memoryConfig.CachedNodesCount = evictSize
	memoryConfig.NodesCountPerPage = pageSize
	mt1, _ := MakeTrie(&memoryCommitter, memoryConfig)

	// add the first 10 hashes.
	for i := 0; i < 10; i++ {
		mt1.Add(hashes[i][:])
	}

	for i := 10; i < len(hashes)-10; i++ {
		for k := 0; k < int(hashes[i-2][0]%5); k++ {
			if hashes[i+k-3][0]%7 == 0 {
				memoryCommitter.failLoad++
			}
			if hashes[i+k-4][0]%7 == 0 {
				memoryCommitter.failStore++
			}
			if hashes[i+k][0]%7 == 0 {
				mt1.Delete(hashes[i+k-int(hashes[i][0]%7)][:])
			}
			mt1.Add(hashes[i+k+3-int(hashes[i+k-1][0]%7)][:])
		}
		if hashes[i][0]%5 == 0 {
			verifyCacheNodeCount(t, mt1)
			mt1.Evict(true)
			verifyCacheNodeCount(t, mt1)
		}
	}
}

// TestCacheEvictionFuzzer generates bursts of random Add/Delete operations on the trie, and
// testing the correctness of the cache internal buffers priodically.
func TestCacheEvictionFuzzer(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create 2000 hashes.
	leafsCount := 2000
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}
	for _, pageSize := range []int64{2, 3, 8, 12, 17} {
		for _, evictSize := range []int{5, 10, 13, 30} {
			t.Run(fmt.Sprintf("Fuzzer-%d-%d", pageSize, evictSize), func(t *testing.T) {
				cacheEvictionFuzzer(t, hashes, pageSize, evictSize)
			})
		}
	}
}

// TestCacheEvictionFuzzer generates bursts of random Add/Delete operations on the trie, and
// testing the correctness of the cache internal buffers priodically.
func TestCacheEvictionFuzzer2(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create 1000 hashes.
	leafsCount := 1000
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}
	for i := 0; i < 80; i++ {
		pageSize := int64(1 + crypto.RandUint64()%101)
		evictSize := int(1 + crypto.RandUint64()%37)
		hashesCount := uint64(100) + crypto.RandUint64()%uint64(leafsCount-100)
		t.Run(fmt.Sprintf("Fuzzer-%d-%d", pageSize, evictSize), func(t *testing.T) {
			cacheEvictionFuzzer(t, hashes[:hashesCount], pageSize, evictSize)
		})
	}
}

// TestCacheMidTransactionPageDeletion ensures that if we need to
// delete a in-memory page during merkleTrieCache.commitTransaction(),
// it's being deleted correctly.
func TestCacheMidTransactionPageDeletion(t *testing.T) {
	partitiontest.PartitionTest(t)

	var memoryCommitter smallPageMemoryCommitter
	memoryConfig := defaultTestMemoryConfig
	memoryConfig.NodesCountPerPage = 2
	mt1, _ := MakeTrie(&memoryCommitter, memoryConfig)

	// create 10000 hashes.
	leafsCount := 10000
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < len(hashes); i++ {
		added, err := mt1.Add(hashes[i][:])
		require.NoError(t, err)
		require.True(t, added)
	}
	for i := 0; i < len(hashes)/4; i++ {
		deleted, err := mt1.Delete(hashes[i][:])
		require.NoError(t, err)
		require.True(t, deleted)
	}

	stats, err := mt1.Commit()
	require.NoError(t, err)

	// compare committed pages to the in-memory pages.
	for page, pageContent := range memoryCommitter.memStore {
		if page == storedNodeIdentifierNull {
			continue
		}

		decodedPage, err := decodePage(pageContent)
		require.NoError(t, err)

		// stored page should have more than a single node.
		require.Greaterf(t, len(decodedPage), 0, "page %d has no nodes", page)
	}

	for page, pageContent := range mt1.cache.pageToNIDsPtr {
		// memory page should have more than a single node.
		require.NotZerof(t, len(pageContent), "Memory page %d has zero nodes", page)

		// memory page should also be available on disk:
		require.NotNilf(t, memoryCommitter.memStore[page], "committed page %d is empty while memory node has %d items\nStats : %#v", page, len(pageContent), stats)
	}
}

// TestDeleteRollback is a modified version of the real Trie.Delete,
// which always "fails" and rollback the transaction.
// this function is used in TestCacheTransactionRollbackPageDeletion
func (mt *Trie) TestDeleteRollback(d []byte) (bool, error) {
	if mt.root == storedNodeIdentifierNull {
		return false, nil
	}
	if len(d) != mt.elementLength {
		return false, ErrMismatchingElementLength
	}
	pnode, err := mt.cache.getNode(mt.root)
	if err != nil {
		return false, err
	}
	found, err := pnode.find(&mt.cache, d[:])
	if !found || err != nil {
		return false, err
	}
	mt.cache.beginTransaction()
	if pnode.leaf() {
		// remove the root.
		mt.cache.deleteNode(mt.root)
		mt.root = storedNodeIdentifierNull
		mt.cache.commitTransaction()
		mt.elementLength = 0
		return true, nil
	}
	_, err = pnode.remove(&mt.cache, d[:], make([]byte, 0, len(d)))
	// unlike the "real" function, we want always to fail here to test the rollbackTransaction() functionality.
	mt.cache.rollbackTransaction()
	return false, fmt.Errorf("this is a test for failing a Delete request")
}

// TestCacheTransactionRollbackPageDeletion ensures that if we need to
// delete a in-memory page during merkleTrieCache.rollbackTransaction(),
// it's being deleted correctly.
func TestCacheTransactionRollbackPageDeletion(t *testing.T) {
	partitiontest.PartitionTest(t)

	var memoryCommitter smallPageMemoryCommitter
	memConfig := defaultTestMemoryConfig
	memConfig.CachedNodesCount = 5
	memConfig.NodesCountPerPage = 2
	mt1, _ := MakeTrie(&memoryCommitter, memConfig)

	// create 1000 hashes.
	leafsCount := 1000
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < len(hashes); i++ {
		added, err := mt1.Add(hashes[i][:])
		require.NoError(t, err)
		require.True(t, added)
	}

	mt1.Evict(true)

	var deleted bool
	var err error
	for i := 0; i < len(hashes); i++ {
		deleted, err = mt1.TestDeleteRollback(hashes[i][:])
		if err != nil {
			break
		}
		require.True(t, deleted)
	}

	for page, pageContent := range mt1.cache.pageToNIDsPtr {
		// memory page should have more than a single node.
		require.NotZerof(t, len(pageContent), "Memory page %d has zero nodes", page)
	}
}

// TestCacheDeleteNodeMidTransaction ensures that if we need to
// delete a in-memory page during merkleTrieCache.deleteNode(),
// it's being deleted correctly.
func TestCacheDeleteNodeMidTransaction(t *testing.T) {
	partitiontest.PartitionTest(t)

	var memoryCommitter smallPageMemoryCommitter
	memConfig := defaultTestMemoryConfig
	memConfig.CachedNodesCount = 5
	memConfig.NodesCountPerPage = 1
	mt1, _ := MakeTrie(&memoryCommitter, memConfig)

	// create 1000 hashes.
	leafsCount := 10000
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < len(hashes); i++ {
		added, err := mt1.Add(hashes[i][:])
		require.NoError(t, err)
		require.True(t, added)
	}
	for i := 0; i < len(hashes); i++ {
		deleted, err := mt1.Delete(hashes[i][:])
		require.NoError(t, err)
		require.True(t, deleted)
	}

	for page, pageContent := range mt1.cache.pageToNIDsPtr {
		// memory page should have more than a single node.
		require.NotZerof(t, len(pageContent), "Memory page %d has zero nodes", page)
	}
}

// TestCachePageLoading ensures that during page loading, the number of cachedNodeCount is not
// increased if the page was already loaded previously into memory.
func TestCachePageReloading(t *testing.T) {
	partitiontest.PartitionTest(t)

	var memoryCommitter InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter, defaultTestMemoryConfig)
	// create 10 hashes.
	leafsCount := 10
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < len(hashes); i++ {
		mt1.Add(hashes[i][:])
	}
	_, err := mt1.Evict(true)
	require.NoError(t, err)

	earlyCachedNodeCount := mt1.cache.cachedNodeCount
	// reloading existing cached page multiple time should not cause increase cached node count.
	page := uint64(mt1.nextNodeID-1) / uint64(defaultTestMemoryConfig.NodesCountPerPage)
	err = mt1.cache.loadPage(page)
	require.NoError(t, err)
	lateCachedNodeCount := mt1.cache.cachedNodeCount
	require.Equal(t, earlyCachedNodeCount, lateCachedNodeCount)

	// manually remove one item off this page
	for k := range mt1.cache.pageToNIDsPtr[page] {
		delete(mt1.cache.pageToNIDsPtr[page], k)
		break
	}
	mt1.cache.cachedNodeCount--

	// reload to see if that would "fix" the missing entry.
	err = mt1.cache.loadPage(page)
	require.NoError(t, err)
	lateCachedNodeCount = mt1.cache.cachedNodeCount
	require.Equal(t, earlyCachedNodeCount, lateCachedNodeCount)
}

// TestCachePagedOutTip verifies that the evict function would prioritize
// evicting other pages before evicting the top page.
func TestCachePagedOutTip(t *testing.T) {
	partitiontest.PartitionTest(t)

	var memoryCommitter InMemoryCommitter
	memConfig := defaultTestMemoryConfig
	memConfig.CachedNodesCount = 600
	mt1, _ := MakeTrie(&memoryCommitter, memConfig)
	// create 2048 hashes.
	leafsCount := 2048
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < len(hashes)/2; i++ {
		mt1.Add(hashes[i][:])
	}
	_, err := mt1.Commit()
	require.NoError(t, err)

	for i := 0; i < len(hashes)/2; i++ {
		mt1.Add(hashes[i+len(hashes)/2][:])
	}

	// check the tip page before evicting
	page := uint64(mt1.root) / uint64(memConfig.NodesCountPerPage)
	require.NotNil(t, mt1.cache.pageToNIDsPtr[page])

	_, err = mt1.Evict(true)
	require.NoError(t, err)

	// ensures that the tip page was not flushed out. ( the root might have been reallocated, so recheck is needed )
	page = uint64(mt1.root) / uint64(memConfig.NodesCountPerPage)
	require.NotNil(t, mt1.cache.pageToNIDsPtr[page])
}

// TestCacheLoadingDeferedPage verifies that the loadPage
// method correcly resets the mtc.deferedPageLoad on the correct page.
func TestCacheLoadingDeferedPage(t *testing.T) {
	partitiontest.PartitionTest(t)

	var memoryCommitter1 InMemoryCommitter
	mt1, _ := MakeTrie(&memoryCommitter1, defaultTestMemoryConfig)
	// create 100000 hashes.
	leafsCount := 100000
	hashes := make([]crypto.Digest, leafsCount)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
	}

	for i := 0; i < len(hashes); i++ {
		mt1.Add(hashes[i][:])
	}
	_, err := mt1.Commit()
	require.NoError(t, err)

	// verify that the cache doesn't reset the mtc.deferedPageLoad on loading a non-defered page.
	dupMem := memoryCommitter1.Duplicate(false)
	mt2, _ := MakeTrie(dupMem, defaultTestMemoryConfig)
	lastPage := int64(mt2.nextNodeID) / defaultTestMemoryConfig.NodesCountPerPage
	require.Equal(t, uint64(lastPage), mt2.cache.deferedPageLoad)
	err = mt2.cache.loadPage(uint64(lastPage - 1))
	require.NoError(t, err)
	require.Equal(t, uint64(lastPage), mt2.cache.deferedPageLoad)

	// verify that the cache does reset the mtc.deferedPageLoad on loading a defered page.
	err = mt2.cache.loadPage(uint64(lastPage))
	require.NoError(t, err)
	require.Equal(t, uint64(0), mt2.cache.deferedPageLoad)
}
