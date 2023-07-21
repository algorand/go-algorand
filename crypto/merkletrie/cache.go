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
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// storedNodeIdentifier is the "equivalent" of a node-ptr, but oriented around persisting the
// nodes to disk. ( i.e. think of a virtual memory address )
type storedNodeIdentifier uint64

const (
	storedNodeIdentifierNull = 0x0
	storedNodeIdentifierBase = 0x4160
	// maxNodeSerializedSize is the serialized size of the biggest node. used for memory preallocation before serializing
	maxNodeSerializedSize = 3000
)

// ErrLoadedPageMissingNode is returned when a request is made for a specific node identifier, and that identifier cannot
// be found in neither the in-memory cache or on the persistent storage.
var ErrLoadedPageMissingNode = errors.New("loaded page is missing a node")

// ErrPageDecodingFailure is returned if the decoding of a page has failed.
var ErrPageDecodingFailure = errors.New("error encountered while decoding page")

type merkleTrieCache struct {
	// mt is a pointer to the originating trie
	mt *Trie
	// committer is the backing store for the cache. ( memory, database, etc. )
	committer Committer
	// cachedNodeCount is the number of currently cached, in-memory, nodes stored in the pageToNIDsPtr structure.
	cachedNodeCount int
	// cachedNodeCountTarget is the number of desired in-memory nodes, used during eviction.
	cachedNodeCountTarget int
	// pageToNIDsPtr contains the mapping of page id to node id, and following that node id to node pointer
	pageToNIDsPtr map[uint64]map[storedNodeIdentifier]*node
	// modified determines whether the cache has been modified since it was last committed.
	modified bool
	// nodesPerPage is number of nodes per page
	nodesPerPage int64

	// txCreatedNodeIDs is the list of nodes created in the current local-transaction ( i.e. internally during the atomic trie operation )
	txCreatedNodeIDs map[storedNodeIdentifier]bool
	// txDeletedNodeIDs is the list of nodes deleted in the current local-transaction ( i.e. internally during the atomic trie operation )
	txDeletedNodeIDs map[storedNodeIdentifier]bool
	// txNextNodeID is the next node id that we had before starting the local-transaction. It allows us to roll back the operation if needed.
	txNextNodeID storedNodeIdentifier

	// pendingCreatedNID contains a list of the node ids that has been created since the last commit and need to be stored.
	pendingCreatedNID map[storedNodeIdentifier]bool
	// pendingDeletionPage contains a map of pages that had at least one node removed from. This require these pages to be either deleted or updated.
	pendingDeletionPages map[uint64]bool

	// a list of the pages priorities. The item in the front has higher priority and would not get evicted as quickly as the item on the back
	pagesPrioritizationList *list.List
	// the list element of each of the priorities. The pagesPrioritizationMap maps a page id to the page priority list element.
	pagesPrioritizationMap map[uint64]*list.Element
	// the page to load before the nextNodeID at init time. If zero, then nothing is being reloaded.
	deferedPageLoad uint64

	// pages reallocation map, used during the commit() execution to identify pages and nodes that would get remapped to ensure the
	// stored pages are sufficiently "packed"
	reallocatedPages map[uint64]map[storedNodeIdentifier]*node

	// targetPageFillFactor is the desired threshold for page fill factor. Newly created pages would follow this fill factor.
	targetPageFillFactor float32

	// maxChildrenPagesThreshold is used during the commit(), evaluating the number of children pages each updated node is referring to. If the number
	// exceed this number, the node children would be reallocated.
	maxChildrenPagesThreshold uint64

	// hashAccumulationBuffer is a shared buffer used for the node.calculateHash function. It avoids memory reallocation.
	hashAccumulationBuffer [64 * 256]byte
}

// initialize perform the initialization for the cache
func (mtc *merkleTrieCache) initialize(mt *Trie, committer Committer, memoryConfig MemoryConfig) {
	mtc.mt = mt
	mtc.pageToNIDsPtr = make(map[uint64]map[storedNodeIdentifier]*node)
	mtc.txNextNodeID = storedNodeIdentifierNull
	mtc.committer = committer
	mtc.cachedNodeCount = 0
	mtc.pendingCreatedNID = make(map[storedNodeIdentifier]bool)
	mtc.pendingDeletionPages = make(map[uint64]bool)
	mtc.pagesPrioritizationList = list.New()
	mtc.pagesPrioritizationMap = make(map[uint64]*list.Element)
	mtc.cachedNodeCountTarget = memoryConfig.CachedNodesCount
	mtc.deferedPageLoad = storedNodeIdentifierNull
	mtc.nodesPerPage = memoryConfig.NodesCountPerPage
	mtc.targetPageFillFactor = memoryConfig.PageFillFactor
	mtc.maxChildrenPagesThreshold = memoryConfig.MaxChildrenPagesThreshold
	if mt.nextNodeID != storedNodeIdentifierBase {
		// If the next node would reside on a page that already has a few entries in it, make sure to mark it for late loading.
		// Otherwise, the next node is going to be the first node on this page, we don't need to reload that page ( since it doesn't exist! ).
		if (int64(mtc.mt.nextNodeID) % mtc.nodesPerPage) > 0 {
			mtc.deferedPageLoad = uint64(mtc.mt.nextNodeID) / uint64(mtc.nodesPerPage)
		}
	}
	mtc.modified = false
	return
}

// allocateNewNode allocates a new node
func (mtc *merkleTrieCache) allocateNewNode() (pnode *node, nid storedNodeIdentifier) {
	nextID := mtc.mt.nextNodeID
	mtc.mt.nextNodeID++
	newNode := &node{}
	page := uint64(nextID) / uint64(mtc.nodesPerPage)
	if mtc.pageToNIDsPtr[page] == nil {
		mtc.pageToNIDsPtr[page] = make(map[storedNodeIdentifier]*node, mtc.nodesPerPage)
	}
	mtc.pageToNIDsPtr[page][nextID] = newNode
	mtc.cachedNodeCount++
	mtc.txCreatedNodeIDs[nextID] = true
	mtc.modified = true
	return newNode, nextID
}

// refurbishNode releases a given node and reallocate a new node while avoiding changing the underlaying buffer.
func (mtc *merkleTrieCache) refurbishNode(nid storedNodeIdentifier) (nextID storedNodeIdentifier) {
	page := uint64(nid) / uint64(mtc.nodesPerPage)
	pNode := mtc.pageToNIDsPtr[page][nid]
	if mtc.txCreatedNodeIDs[nid] {
		delete(mtc.txCreatedNodeIDs, nid)
		delete(mtc.pageToNIDsPtr[page], nid)
		if len(mtc.pageToNIDsPtr[page]) == 0 {
			delete(mtc.pageToNIDsPtr, page)
		}
		mtc.cachedNodeCount--
	} else {
		mtc.txDeletedNodeIDs[nid] = true
	}

	nextID = mtc.mt.nextNodeID
	mtc.mt.nextNodeID++
	page = uint64(nextID) / uint64(mtc.nodesPerPage)
	if mtc.pageToNIDsPtr[page] == nil {
		mtc.pageToNIDsPtr[page] = make(map[storedNodeIdentifier]*node, mtc.nodesPerPage)
	}
	mtc.pageToNIDsPtr[page][nextID] = pNode
	mtc.cachedNodeCount++
	mtc.txCreatedNodeIDs[nextID] = true
	mtc.modified = true
	return nextID
}

// getNode retrieves the given node by its identifier, loading the page if it
// cannot be found in cache, and returning an error if it's not in cache nor in committer.
func (mtc *merkleTrieCache) getNode(nid storedNodeIdentifier) (pnode *node, err error) {
	nodePage := uint64(nid) / uint64(mtc.nodesPerPage)
	pageNodes := mtc.pageToNIDsPtr[nodePage]
	if pageNodes != nil {
		pnode = pageNodes[nid]
		if pnode != nil {
			if mtc.reallocatedPages == nil {
				mtc.prioritizeNodeFront(nid)
			}
			return
		}
	}

	// if we don't have it in memory, try to load it from disk
	err = mtc.loadPage(nodePage)
	if err != nil {
		return
	}
	var have bool
	pageNodes = mtc.pageToNIDsPtr[nodePage]
	if pnode, have = pageNodes[nid]; !have {
		err = ErrLoadedPageMissingNode
	} else {
		// if we're current reallocating pages, the mtc.reallocatedPages would be non-nil, and
		// the newly prioritized pages should be placed on the back. Otherwise, we're on the
		// "normal" path, adding/deleting elements from the trie, in which case new pages should
		// always be placed on the front.
		if mtc.reallocatedPages == nil {
			mtc.prioritizeNodeFront(nid)
		} else {
			mtc.prioritizeNodeBack(nid)
		}

	}
	return
}

// prioritizeNodeFront make sure to adjust the priority of the given node id.
// nodes are prioritized based on the page the belong to.
// a new page would be placed on front, and an existing page would get moved
// to the front.
func (mtc *merkleTrieCache) prioritizeNodeFront(nid storedNodeIdentifier) {
	page := uint64(nid) / uint64(mtc.nodesPerPage)

	element := mtc.pagesPrioritizationMap[page]

	if element != nil {
		// if we already have this page as an element, move it to the front.
		mtc.pagesPrioritizationList.MoveToFront(element)
		return
	}
	// add it at the front.
	mtc.pagesPrioritizationMap[page] = mtc.pagesPrioritizationList.PushFront(page)
}

// prioritizeNodeBack make sure to adjust the priority of the given node id.
// nodes are prioritized based on the page the belong to.
// a new page would be placed on front, and an existing page would get moved
// to the front.
func (mtc *merkleTrieCache) prioritizeNodeBack(nid storedNodeIdentifier) {
	page := uint64(nid) / uint64(mtc.nodesPerPage)

	element := mtc.pagesPrioritizationMap[page]

	if element != nil {
		// if we already have this page as an element, move it to the back.
		mtc.pagesPrioritizationList.MoveToBack(element)
		return
	}
	// add it at the back.
	mtc.pagesPrioritizationMap[page] = mtc.pagesPrioritizationList.PushBack(page)
}

// loadPage loads a give page id into memory.
func (mtc *merkleTrieCache) loadPage(page uint64) (err error) {
	pageBytes, err := mtc.committer.LoadPage(page)
	if err != nil {
		return
	}
	if len(pageBytes) == 0 {
		return fmt.Errorf("page %d is missing", page)
	}
	decodedNodes, err := decodePage(pageBytes)
	if err != nil {
		return
	}
	if mtc.pageToNIDsPtr[page] == nil {
		mtc.pageToNIDsPtr[page] = decodedNodes
		mtc.cachedNodeCount += len(mtc.pageToNIDsPtr[page])
	} else {
		mtc.cachedNodeCount -= len(mtc.pageToNIDsPtr[page])
		for nodeID, pnode := range decodedNodes {
			mtc.pageToNIDsPtr[page][nodeID] = pnode
		}
		mtc.cachedNodeCount += len(mtc.pageToNIDsPtr[page])
	}

	// if we've just loaded a deferred page, no need to reload it during the commit.
	if mtc.deferedPageLoad == page {
		mtc.deferedPageLoad = storedNodeIdentifierNull
	}
	return
}

// deleteNode marks the given node to be deleted, or ( if it was never flushed )
// deletes it right away.
func (mtc *merkleTrieCache) deleteNode(nid storedNodeIdentifier) {
	if mtc.txCreatedNodeIDs[nid] {
		delete(mtc.txCreatedNodeIDs, nid)
		page := uint64(nid) / uint64(mtc.nodesPerPage)
		delete(mtc.pageToNIDsPtr[page], nid)
		if len(mtc.pageToNIDsPtr[page]) == 0 {
			delete(mtc.pageToNIDsPtr, page)
		}
		mtc.cachedNodeCount--
	} else {
		mtc.txDeletedNodeIDs[nid] = true
	}
	mtc.modified = true
}

// beginTransaction - used internaly by the Trie
func (mtc *merkleTrieCache) beginTransaction() {
	mtc.txCreatedNodeIDs = make(map[storedNodeIdentifier]bool)
	mtc.txDeletedNodeIDs = make(map[storedNodeIdentifier]bool)
	mtc.txNextNodeID = mtc.mt.nextNodeID
}

// commitTransaction - used internally by the Trie
func (mtc *merkleTrieCache) commitTransaction() {
	// the created nodes are already on the list.
	for nodeID := range mtc.txCreatedNodeIDs {
		mtc.pendingCreatedNID[nodeID] = true
		mtc.prioritizeNodeFront(nodeID)
	}
	mtc.txCreatedNodeIDs = nil

	// delete the ones that we don't want from the list.
	for nodeID := range mtc.txDeletedNodeIDs {
		page := uint64(nodeID) / uint64(mtc.nodesPerPage)
		if mtc.pendingCreatedNID[nodeID] {
			// it was never flushed.
			delete(mtc.pendingCreatedNID, nodeID)
			delete(mtc.pageToNIDsPtr[page], nodeID)
			// if the page is empty, and it's not on the pendingDeletionPages, it means that we have no further references to it,
			// so we can delete it right away.
			if len(mtc.pageToNIDsPtr[page]) == 0 && mtc.pendingDeletionPages[page] == false {
				delete(mtc.pageToNIDsPtr, page)
			}
		} else {
			mtc.pendingDeletionPages[page] = true
			delete(mtc.pageToNIDsPtr[page], nodeID)
			// no need to clear out the mtc.pageToNIDsPtr page, since it will be taken care by the commit() function.
		}
	}
	mtc.cachedNodeCount -= len(mtc.txDeletedNodeIDs)
	mtc.txDeletedNodeIDs = nil
}

// rollbackTransaction - used internaly by the Trie
func (mtc *merkleTrieCache) rollbackTransaction() {
	// no need to delete anything.
	mtc.txDeletedNodeIDs = nil
	// drop all the created nodes ids
	for nodeID := range mtc.txCreatedNodeIDs {
		page := uint64(nodeID) / uint64(mtc.nodesPerPage)
		delete(mtc.pageToNIDsPtr[page], nodeID)
		if len(mtc.pageToNIDsPtr[page]) == 0 {
			delete(mtc.pageToNIDsPtr, page)
		}
	}
	mtc.cachedNodeCount -= len(mtc.txCreatedNodeIDs)
	mtc.txDeletedNodeIDs = nil
	mtc.mt.nextNodeID = mtc.txNextNodeID
	mtc.txNextNodeID = storedNodeIdentifierNull
}

// CommitStats provides statistics about the operation of the commit() function
type CommitStats struct {
	NewPageCount                int
	NewNodeCount                int
	UpdatedPageCount            int
	UpdatedNodeCount            int
	DeletedPageCount            int
	FanoutReallocatedNodeCount  int
	PackingReallocatedNodeCount int
	LoadedPages                 int
}

// commit - used as part of the Trie Commit functionality
func (mtc *merkleTrieCache) commit() (CommitStats, error) {
	var stats CommitStats

	// if we have a pending page load, do that now.
	if mtc.deferedPageLoad != storedNodeIdentifierNull {
		err := mtc.loadPage(mtc.deferedPageLoad)
		if err != nil {
			return CommitStats{}, err
		}
		mtc.deferedPageLoad = storedNodeIdentifierNull
	}

	pagesToCreate, pagesToDelete, pagesToUpdate, err := mtc.reallocatePendingPages(&stats)
	if err != nil {
		return CommitStats{}, err
	}

	// allocate a staging area for the page encoder. buffer should be big enough so
	// we won't need any reallocation to take place.
	encodeBuffer := make([]byte, maxNodeSerializedSize*256+32)

	// store all the new pages ( which have a sequential ordering )
	for _, page := range pagesToCreate {
		nodeIDs := mtc.pageToNIDsPtr[page]
		pageContent := mtc.encodePage(nodeIDs, encodeBuffer)
		err := mtc.committer.StorePage(uint64(page), pageContent)
		if err != nil {
			return CommitStats{}, err
		}
		stats.NewPageCount++
		stats.NewNodeCount += len(nodeIDs)
	}

	// delete the pages that we don't need anymore.
	for page := range pagesToDelete {
		err := mtc.committer.StorePage(uint64(page), nil)
		if err != nil {
			return CommitStats{}, err
		}

		// since the entire page was removed from memory, we can also remove it from the priority list.
		element := mtc.pagesPrioritizationMap[uint64(page)]
		if element != nil {
			mtc.pagesPrioritizationList.Remove(element)
			delete(mtc.pagesPrioritizationMap, uint64(page))
		}
		stats.DeletedPageCount++

		mtc.cachedNodeCount -= len(mtc.pageToNIDsPtr[uint64(page)])
		delete(mtc.pageToNIDsPtr, uint64(page))
	}

	// updated pages
	for page, nodeIDs := range pagesToUpdate {
		pageContent := mtc.encodePage(nodeIDs, encodeBuffer)
		err := mtc.committer.StorePage(uint64(page), pageContent)
		if err != nil {
			return CommitStats{}, err
		}
		stats.UpdatedPageCount++
		stats.UpdatedNodeCount += len(nodeIDs)
	}

	mtc.pendingCreatedNID = make(map[storedNodeIdentifier]bool)
	mtc.pendingDeletionPages = make(map[uint64]bool)
	mtc.modified = false
	return stats, nil
}

// reallocatePendingPages is called by the commit() function, and is responsible for performing two tasks -
// 1. calculate the hashes of all the newly created nodes
// 2. reorganize the pending flush nodes into an optimal page list, and construct a list of pages that need to be created, deleted and updated.
func (mtc *merkleTrieCache) reallocatePendingPages(stats *CommitStats) (pagesToCreate []uint64, pagesToDelete map[uint64]bool, pagesToUpdate map[uint64]map[storedNodeIdentifier]*node, err error) {
	// newPageThreshold is the threshold at which all the pages are newly created pages that were never committed.
	newPageThreshold := uint64(mtc.mt.lastCommittedNodeID) / uint64(mtc.nodesPerPage)
	if int64(mtc.mt.lastCommittedNodeID)%mtc.nodesPerPage > 0 {
		newPageThreshold++
	}

	createdPages := make(map[uint64]map[storedNodeIdentifier]*node)
	toUpdatePages := make(map[uint64]map[storedNodeIdentifier]*node)

	// create a list of all the pages that need to be created/updated
	for nodeID := range mtc.pendingCreatedNID {
		nodePage := uint64(nodeID) / uint64(mtc.nodesPerPage)
		if nil == createdPages[nodePage] {
			createdPages[nodePage] = mtc.pageToNIDsPtr[uint64(nodePage)]
		}
	}

	// create a sorted list of created pages
	sortedCreatedPages := maps.Keys(createdPages)
	slices.Sort(sortedCreatedPages)

	mtc.reallocatedPages = make(map[uint64]map[storedNodeIdentifier]*node)

	// move the next node id to the next page, so that all reallocated nodes would be packed on new pages.
	mtc.mt.nextNodeID = storedNodeIdentifier(((uint64(mtc.mt.nextNodeID) + uint64(mtc.nodesPerPage-1)) / uint64(mtc.nodesPerPage)) * uint64(mtc.nodesPerPage))
	reallocatedNodesBasePage := uint64(mtc.mt.nextNodeID) / uint64(mtc.nodesPerPage)

	beforeHashCalculationPageCount := len(mtc.pageToNIDsPtr)
	beforeHashCalculationPendingDeletionPages := len(mtc.pendingDeletionPages)

	// updated the hashes of these pages. this works correctly
	// since all trie modification are done with ids that are bottom-up
	for _, page := range sortedCreatedPages {
		relocatedNodes, err := mtc.calculatePageHashes(int64(page), page >= newPageThreshold)
		if err != nil {
			return nil, nil, nil, err
		}
		stats.FanoutReallocatedNodeCount += int(relocatedNodes)
	}

	stats.LoadedPages = len(mtc.pendingDeletionPages) - beforeHashCalculationPendingDeletionPages + len(mtc.pageToNIDsPtr) - beforeHashCalculationPageCount
	// reallocate each of the new page content, if not meeting the desired fill factor.
	reallocationMap := make(map[storedNodeIdentifier]storedNodeIdentifier)
	for _, page := range sortedCreatedPages {
		if page < newPageThreshold {
			continue
		}
		if mtc.getPageFillFactor(page) >= mtc.targetPageFillFactor {
			if len(createdPages[page]) > 0 {
				pagesToCreate = append(pagesToCreate, page)
			}
			continue
		}

		stats.PackingReallocatedNodeCount += mtc.reallocatePage(page, reallocationMap)
		delete(createdPages, page)
	}

	for pageID, page := range mtc.reallocatedPages {
		createdPages[pageID] = page
	}

	for _, nodeIDs := range createdPages {
		for _, node := range nodeIDs {
			node.remapChildren(reallocationMap)
		}
	}

	if newRootID, has := reallocationMap[mtc.mt.root]; has {
		delete(reallocationMap, mtc.mt.root)
		mtc.mt.root = newRootID
	}
	mtc.reallocatedPages = nil

	// pages that contains elemets that were removed.
	toRemovePages := mtc.pendingDeletionPages

	// The initial page is moved to the "update" step.
	if len(sortedCreatedPages) > 0 && mtc.pageToNIDsPtr[sortedCreatedPages[0]] != nil {
		toRemovePages[sortedCreatedPages[0]] = true
	}

	for page := reallocatedNodesBasePage; len(createdPages[page]) > 0; page++ {
		nodeIDs := createdPages[page]
		delete(createdPages, page)
		if len(nodeIDs) == 0 {
			continue
		}
		pagesToCreate = append(pagesToCreate, page)
	}

	// iterate over the existing list and ensure we don't delete any page that has active elements
	for pageRemovalCandidate := range toRemovePages {
		if len(mtc.pageToNIDsPtr[uint64(pageRemovalCandidate)]) == 0 {
			// we have no nodes associated with this page, so
			// it means that we can remove this page safely.
			continue
		}
		// otherwise, it seems that this page has other live items, so we'd better keep it around.
		toUpdatePages[pageRemovalCandidate] = mtc.pageToNIDsPtr[uint64(pageRemovalCandidate)]
		delete(toRemovePages, pageRemovalCandidate)
	}

	return pagesToCreate, toRemovePages, toUpdatePages, nil
}

// calculatePageHashes calculate hashes of a specific page
// It is vital that the hashes for all the preceding page would have
// already been calculated for this function to work correctly.
func (mtc *merkleTrieCache) calculatePageHashes(page int64, newPage bool) (fanoutRelocatedNodes int64, err error) {
	nodes := mtc.pageToNIDsPtr[uint64(page)]
	for i := storedNodeIdentifier(page * mtc.nodesPerPage); i < storedNodeIdentifier((page+1)*mtc.nodesPerPage); i++ {
		if !newPage && mtc.pendingCreatedNID[i] == false {
			continue
		}
		node := nodes[i]
		if node == nil {
			continue
		}

		if err = node.calculateHash(mtc); err != nil {
			return
		}

		nodeChildCount := node.getChildCount()
		if nodeChildCount > mtc.maxChildrenPagesThreshold {
			nodeUniqueChildPages := node.getUniqueChildPageCount(mtc.nodesPerPage)
			if nodeUniqueChildPages > mtc.maxChildrenPagesThreshold {
				// see if we can fit all the child nodes into the existing page or not. If not, we might want to start
				// a new page as long as there is a chance that all the children would be able to fit into that page.
				if nodeChildCount < uint64(mtc.nodesPerPage) &&
					mtc.getPageFillFactor(uint64(mtc.mt.nextNodeID)/uint64(mtc.nodesPerPage)) > mtc.targetPageFillFactor {
					// adjust the next node id to align with the next page.
					mtc.mt.nextNodeID = storedNodeIdentifier((1 + uint64(mtc.mt.nextNodeID)/uint64(mtc.nodesPerPage)) * uint64(mtc.nodesPerPage))
				}
				node.reallocateChildren(mtc)
				fanoutRelocatedNodes++
			}
		}
	}
	return
}

// getPageFillFactor calculates the fill factor for a given page, or return 0 if the page is not in memory.
func (mtc *merkleTrieCache) getPageFillFactor(page uint64) float32 {
	if pageMap := mtc.pageToNIDsPtr[page]; pageMap != nil {
		return float32(len(pageMap)) / float32(mtc.nodesPerPage)
	}
	return 0.0
}

// reallocatePage reallocates an entire page into the latest page(s). It also update the reallocationMap for all the nodes that have been moved,
// so that we could update the needed node dependencies.
func (mtc *merkleTrieCache) reallocatePage(page uint64, reallocationMap map[storedNodeIdentifier]storedNodeIdentifier) (reallocatedNodes int) {
	nextID := mtc.mt.nextNodeID
	reallocatedNodes = len(mtc.pageToNIDsPtr[page])
	nextPage := uint64(nextID) / uint64(mtc.nodesPerPage)
	if reallocatedNodes == 0 {
		// if we aren't going to reallocate any nodes, no need to allocate (maybe)
		// new pages for these.
		goto skipContentDeletion
	}

	if _, has := mtc.pageToNIDsPtr[nextPage]; has {
		// see if we will need another allocated page:
		lastID := mtc.mt.nextNodeID + storedNodeIdentifier(reallocatedNodes) - 1
		lastPage := uint64(lastID) / uint64(mtc.nodesPerPage)
		if _, has := mtc.pageToNIDsPtr[lastPage]; !has {
			nextPage = lastPage
		} else {
			nextPage = storedNodeIdentifierNull
		}
	}

	if nextPage > storedNodeIdentifierNull {
		pageMap := make(map[storedNodeIdentifier]*node, mtc.nodesPerPage)
		mtc.reallocatedPages[nextPage] = pageMap
		mtc.pageToNIDsPtr[nextPage] = pageMap
		mtc.pagesPrioritizationMap[nextPage] = mtc.pagesPrioritizationList.PushFront(nextPage)
	}

	mtc.mt.nextNodeID += storedNodeIdentifier(reallocatedNodes)
	for nid, node := range mtc.pageToNIDsPtr[page] {
		reallocationMap[nid] = nextID
		mtc.pageToNIDsPtr[uint64(nextID)/uint64(mtc.nodesPerPage)][nextID] = node
		delete(mtc.pageToNIDsPtr[page], nid)
		nextID++
	}
skipContentDeletion:
	delete(mtc.pageToNIDsPtr, page)
	delete(mtc.reallocatedPages, page)
	if element, has := mtc.pagesPrioritizationMap[page]; has {
		mtc.pagesPrioritizationList.Remove(element)
		delete(mtc.pagesPrioritizationMap, page)
	}
	return
}

// reallocateNode reallocates a given node into the latest page. Unlike refurbishNode, it's not expected to be called
// from within the context of a transaction.
func (mtc *merkleTrieCache) reallocateNode(nid storedNodeIdentifier) storedNodeIdentifier {
	nextID := mtc.mt.nextNodeID
	nextPage := uint64(nextID) / uint64(mtc.nodesPerPage)
	currentPage := uint64(nid) / uint64(mtc.nodesPerPage)
	if currentPage == nextPage {
		return nid
	}
	mtc.mt.nextNodeID++

	pnode := mtc.pageToNIDsPtr[currentPage][nid]

	delete(mtc.pageToNIDsPtr[currentPage], nid)
	if len(mtc.pageToNIDsPtr[currentPage]) == 0 {
		delete(mtc.pageToNIDsPtr, currentPage)
		delete(mtc.reallocatedPages, currentPage) // if there is one.
		if element, has := mtc.pagesPrioritizationMap[currentPage]; has && element != nil {
			// since the page was just deleted, we can delete it from the prioritization map as well.
			mtc.pagesPrioritizationList.Remove(element)
			delete(mtc.pagesPrioritizationMap, currentPage)
		}
	}
	mtc.pendingDeletionPages[currentPage] = true

	if mtc.pageToNIDsPtr[nextPage] == nil {
		pageMap := make(map[storedNodeIdentifier]*node, mtc.nodesPerPage)
		mtc.reallocatedPages[nextPage] = pageMap
		mtc.pageToNIDsPtr[nextPage] = pageMap
		mtc.pagesPrioritizationMap[nextPage] = mtc.pagesPrioritizationList.PushFront(nextPage)
	}
	mtc.pageToNIDsPtr[nextPage][nextID] = pnode

	return nextID
}

// decodePage decodes a byte array into a page content
func decodePage(bytes []byte) (nodesMap map[storedNodeIdentifier]*node, err error) {
	version, versionLength := binary.Uvarint(bytes[:])
	if versionLength <= 0 {
		return nil, ErrPageDecodingFailure
	}
	if version != nodePageVersion {
		return nil, ErrPageDecodingFailure
	}
	nodesCount, nodesCountLength := binary.Varint(bytes[versionLength:])
	if nodesCountLength <= 0 {
		return nil, ErrPageDecodingFailure
	}
	nodesMap = make(map[storedNodeIdentifier]*node)
	walk := nodesCountLength + versionLength
	for i := int64(0); i < nodesCount; i++ {
		nodeID, nodesIDLength := binary.Uvarint(bytes[walk:])
		if nodesIDLength <= 0 {
			return nil, ErrPageDecodingFailure
		}
		walk += nodesIDLength
		pnode, nodeLength := deserializeNode(bytes[walk:])
		if nodeLength <= 0 {
			return nil, ErrPageDecodingFailure
		}
		walk += nodeLength
		nodesMap[storedNodeIdentifier(nodeID)] = pnode
	}

	return nodesMap, nil
}

// decodePage encodes a page contents into a byte array
func (mtc *merkleTrieCache) encodePage(nodeIDs map[storedNodeIdentifier]*node, serializedBuffer []byte) []byte {
	version := binary.PutUvarint(serializedBuffer[:], nodePageVersion)
	length := binary.PutVarint(serializedBuffer[version:], int64(len(nodeIDs)))
	walk := version + length
	for nodeID, pnode := range nodeIDs {
		n := binary.PutUvarint(serializedBuffer[walk:], uint64(nodeID))
		walk += n
		n = pnode.serialize(serializedBuffer[walk:])
		walk += n
	}
	return serializedBuffer[:walk]
}

// evict releases the least used pages from cache until the number of elements in cache are less than cachedNodeCountTarget.
// the root element page is being moved to the front so that it would get flushed last.
func (mtc *merkleTrieCache) evict() (removedNodes int) {
	removedNodes = mtc.cachedNodeCount
	// check the root element ( if there is such ), and give it a higher priority, since we want
	// to release the page with the root element last.
	if mtc.mt.root != storedNodeIdentifierNull {
		rootPage := uint64(mtc.mt.root) / uint64(mtc.nodesPerPage)
		if element, has := mtc.pagesPrioritizationMap[rootPage]; has && element != nil {
			mtc.pagesPrioritizationList.MoveToFront(element)
		}
	}
	for mtc.cachedNodeCount > mtc.cachedNodeCountTarget {
		// get the least used page off the pagesPrioritizationList
		element := mtc.pagesPrioritizationList.Back()
		if element == nil {
			break
		}
		mtc.pagesPrioritizationList.Remove(element)
		pageToRemove := element.Value.(uint64)
		delete(mtc.pagesPrioritizationMap, pageToRemove)
		mtc.cachedNodeCount -= len(mtc.pageToNIDsPtr[pageToRemove])
		delete(mtc.pageToNIDsPtr, pageToRemove)
	}
	removedNodes = removedNodes - mtc.cachedNodeCount
	return
}
