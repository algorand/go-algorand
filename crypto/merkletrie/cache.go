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
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// storedNodeIdentifier is the "equivilent" of a node-ptr, but oriented around persisting the
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

// ErrPageDecodingFailuire is returned if the decoding of a page has failed.
var ErrPageDecodingFailuire = errors.New("error encountered while decoding page")

type merkleTrieCache struct {
	// mt is a point to the originating trie
	mt *Trie
	// committer is the backing up storage for the cache. ( memory, database, etc. )
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
	// pendingDeletionNID contains a list of the node ids that has been deleted since the last commit and need to be removed.
	pendingDeletionNID map[storedNodeIdentifier]bool

	// a list of the pages priorities. The item in the front has higher priority and would not get evicted as quickly as the item on the back
	pagesPrioritizationList *list.List
	// the list element of each of the priorities. The pagesPrioritizationMap maps a page id to the page priority list element.
	pagesPrioritizationMap map[uint64]*list.Element
	// the page to load before the nextNodeID at init time. If zero, then nothing is being reloaded.
	deferedPageLoad uint64
}

// initialize perform the initialization for the cache
func (mtc *merkleTrieCache) initialize(mt *Trie, committer Committer, cachedNodeCountTarget int) {
	mtc.mt = mt
	mtc.pageToNIDsPtr = make(map[uint64]map[storedNodeIdentifier]*node)
	mtc.txNextNodeID = storedNodeIdentifierNull
	mtc.committer = committer
	mtc.cachedNodeCount = 0
	mtc.pendingCreatedNID = make(map[storedNodeIdentifier]bool)
	mtc.pendingDeletionNID = make(map[storedNodeIdentifier]bool)
	mtc.pagesPrioritizationList = list.New()
	mtc.pagesPrioritizationMap = make(map[uint64]*list.Element)
	mtc.cachedNodeCountTarget = cachedNodeCountTarget
	mtc.deferedPageLoad = storedNodeIdentifierNull
	mtc.nodesPerPage = committer.GetNodesCountPerPage()
	if mt.nextNodeID != storedNodeIdentifierBase {
		// if the next node is going to be on a new page, no need to reload the last page.
		if (int64(mtc.mt.nextNodeID) / mtc.nodesPerPage) == (int64(mtc.mt.nextNodeID-1) / mtc.nodesPerPage) {
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

// getNode retrieves the given node by its identifier, loading the page if it
// cannot be found in cache, and returning an error if it's not in cache nor in committer.
func (mtc *merkleTrieCache) getNode(nid storedNodeIdentifier) (pnode *node, err error) {
	nodePage := uint64(nid) / uint64(mtc.nodesPerPage)
	pageNodes := mtc.pageToNIDsPtr[nodePage]
	if pageNodes != nil {
		pnode = pageNodes[nid]
		if pnode != nil {
			mtc.prioritizeNode(nid)
			return
		}
	}

	err = mtc.loadPage(nodePage)
	if err != nil {
		return
	}
	var have bool
	pageNodes = mtc.pageToNIDsPtr[nodePage]
	if pnode, have = pageNodes[nid]; !have {
		err = ErrLoadedPageMissingNode
	} else {
		mtc.prioritizeNode(nid)
	}
	return
}

// prioritizeNode make sure to adjust the priority of the given node id.
// nodes are prioritized based on the page the belong to.
// a new page would be placed on front, and an older page would get moved
// to the front.
func (mtc *merkleTrieCache) prioritizeNode(nid storedNodeIdentifier) {
	page := uint64(nid) / uint64(mtc.nodesPerPage)

	element := mtc.pagesPrioritizationMap[page]
	if element != nil {
		// if we already have this page as an element, move it to the front.
		mtc.pagesPrioritizationList.MoveToFront(element)
		return
	}
	// add it at the front.
	element = mtc.pagesPrioritizationList.PushFront(page)
	mtc.pagesPrioritizationMap[page] = element
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
		mtc.pageToNIDsPtr[page] = make(map[storedNodeIdentifier]*node, mtc.nodesPerPage)
	}
	for nodeID, pnode := range decodedNodes {
		mtc.pageToNIDsPtr[page][nodeID] = pnode
	}
	mtc.cachedNodeCount += len(mtc.pageToNIDsPtr[page])

	// if we've just loaded a deferred page, no need to reload it during the commit.
	if mtc.deferedPageLoad != page {
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
			mtc.pageToNIDsPtr[page] = nil
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

// commitTransaction - used internaly by the Trie
func (mtc *merkleTrieCache) commitTransaction() {
	// the created nodes are already on the list.
	for nodeID := range mtc.txCreatedNodeIDs {
		mtc.pendingCreatedNID[nodeID] = true
		mtc.prioritizeNode(nodeID)
	}
	mtc.txCreatedNodeIDs = nil

	// delete the ones that we don't want from the list.
	for nodeID := range mtc.txDeletedNodeIDs {
		if mtc.pendingCreatedNID[nodeID] {
			// it was never flushed.
			delete(mtc.pendingCreatedNID, nodeID)
		} else {
			mtc.pendingDeletionNID[nodeID] = true
		}

		page := uint64(nodeID) / uint64(mtc.nodesPerPage)
		delete(mtc.pageToNIDsPtr[page], nodeID)
		if len(mtc.pageToNIDsPtr[page]) == 0 {
			mtc.pageToNIDsPtr[page] = nil
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
			mtc.pageToNIDsPtr[page] = nil
		}
	}
	mtc.cachedNodeCount -= len(mtc.txCreatedNodeIDs)
	mtc.txDeletedNodeIDs = nil
	mtc.mt.nextNodeID = mtc.txNextNodeID
	mtc.txNextNodeID = storedNodeIdentifierNull
}

// Int64Slice attaches the methods of Interface to []uint64, sorting in increasing order.
type Int64Slice []int64

func (p Int64Slice) Len() int           { return len(p) }
func (p Int64Slice) Less(i, j int) bool { return p[i] < p[j] }
func (p Int64Slice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// SortInt64 sorts a slice of uint64s in increasing order.
func SortInt64(a []int64) {
	sort.Sort(Int64Slice(a))
}

// commit - used as part of the Trie Commit functionality
func (mtc *merkleTrieCache) commit() error {
	// if we have a pending page load, do that now.
	if mtc.deferedPageLoad != storedNodeIdentifierNull {
		err := mtc.loadPage(mtc.deferedPageLoad)
		if err != nil {
			return err
		}
		mtc.deferedPageLoad = storedNodeIdentifierNull
	}

	createdPages := make(map[int64]map[storedNodeIdentifier]*node)

	// create a list of all the pages that need to be created/updated
	for nodeID := range mtc.pendingCreatedNID {
		nodePage := int64(nodeID) / mtc.nodesPerPage
		if nil == createdPages[nodePage] {
			createdPages[nodePage] = mtc.pageToNIDsPtr[uint64(nodePage)]
		}
	}

	// create a sorted list of created pages
	sortedCreatedPages := make([]int64, 0, len(createdPages))
	for page := range createdPages {
		sortedCreatedPages = append(sortedCreatedPages, page)
	}
	SortInt64(sortedCreatedPages)
	// updated the hashes of these pages. this works correctly
	// since all trie modification are done with ids that are bottom-up
	for _, page := range sortedCreatedPages {
		err := mtc.calculatePageHashes(page)
		if err != nil {
			return err
		}
	}

	// store the pages.
	for page, nodeIDs := range createdPages {
		pageContent := mtc.encodePage(nodeIDs)
		err := mtc.committer.StorePage(uint64(page), pageContent)
		if err != nil {
			return err
		}
	}

	// pages that contains elemets that were removed.
	toRemovePages := make(map[int64]map[storedNodeIdentifier]*node)
	toUpdatePages := make(map[int64]map[storedNodeIdentifier]*node)
	for nodeID := range mtc.pendingDeletionNID {
		nodePage := int64(nodeID) / mtc.nodesPerPage
		if toRemovePages[nodePage] == nil {
			toRemovePages[nodePage] = make(map[storedNodeIdentifier]*node, mtc.nodesPerPage)
		}
		toRemovePages[nodePage][nodeID] = nil
	}

	// iterate over the existing list and ensure we don't delete any page that has active elements
	for pageRemovalCandidate := range toRemovePages {
		if mtc.pageToNIDsPtr[uint64(pageRemovalCandidate)] == nil {
			// we have no nodes associated with this page, so
			// it means that we can remove this page safely.
			continue
		}
		// otherwise, it seems that this page has other live items, so we'd better keep it around.
		toUpdatePages[pageRemovalCandidate] = mtc.pageToNIDsPtr[uint64(pageRemovalCandidate)]
		delete(toRemovePages, pageRemovalCandidate)
	}

	// delete the pages that we don't need anymore.
	for page := range toRemovePages {
		err := mtc.committer.StorePage(uint64(page), nil)
		if err != nil {
			return err
		}

		// since the entire page was removed from memory, we can also remove it from the priority list.
		element := mtc.pagesPrioritizationMap[uint64(page)]
		if element != nil {
			mtc.pagesPrioritizationList.Remove(element)
			delete(mtc.pagesPrioritizationMap, uint64(page))
			mtc.cachedNodeCount -= len(mtc.pageToNIDsPtr[uint64(page)])
			delete(mtc.pageToNIDsPtr, uint64(page))
		}
	}

	// updated pages
	for page, nodeIDs := range toUpdatePages {
		if createdPages[page] != nil {
			continue
		}
		pageContent := mtc.encodePage(nodeIDs)
		err := mtc.committer.StorePage(uint64(page), pageContent)
		if err != nil {
			return err
		}
	}

	mtc.pendingCreatedNID = make(map[storedNodeIdentifier]bool)
	mtc.pendingDeletionNID = make(map[storedNodeIdentifier]bool)
	mtc.modified = false
	return nil
}

// calculatePageHashes calculate hashes of a specific page
// It is vital that the hashes for all the preceding page would have
// already been calculated for this function to work correctly.
func (mtc *merkleTrieCache) calculatePageHashes(page int64) (err error) {
	nodes := mtc.pageToNIDsPtr[uint64(page)]
	for i := page * mtc.nodesPerPage; i < (page+1)*mtc.nodesPerPage; i++ {
		if mtc.pendingCreatedNID[storedNodeIdentifier(i)] == false {
			continue
		}
		node := nodes[storedNodeIdentifier(i)]
		if node != nil {
			if err = node.calculateHash(mtc); err != nil {
				return
			}
		}
	}
	return
}

// decodePage decodes a byte array into a page content
func decodePage(bytes []byte) (nodesMap map[storedNodeIdentifier]*node, err error) {
	version, versionLength := binary.Uvarint(bytes[:])
	if versionLength <= 0 {
		return nil, ErrPageDecodingFailuire
	}
	if version != NodePageVersion {
		return nil, ErrPageDecodingFailuire
	}
	nodesCount, nodesCountLength := binary.Varint(bytes[versionLength:])
	if nodesCountLength <= 0 {
		return nil, ErrPageDecodingFailuire
	}
	nodesMap = make(map[storedNodeIdentifier]*node)
	walk := nodesCountLength + versionLength
	for i := int64(0); i < nodesCount; i++ {
		nodeID, nodesIDLength := binary.Uvarint(bytes[walk:])
		if nodesIDLength <= 0 {
			return nil, ErrPageDecodingFailuire
		}
		walk += nodesIDLength
		pnode, nodeLength := deserializeNode(bytes[walk:])
		if nodeLength <= 0 {
			return nil, ErrPageDecodingFailuire
		}
		walk += nodeLength
		nodesMap[storedNodeIdentifier(nodeID)] = pnode
	}

	return nodesMap, nil
}

// decodePage encodes a page contents into a byte array
func (mtc *merkleTrieCache) encodePage(nodeIDs map[storedNodeIdentifier]*node) []byte {
	serializedBuffer := make([]byte, maxNodeSerializedSize*len(nodeIDs)+32)
	version := binary.PutUvarint(serializedBuffer[:], NodePageVersion)
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

// evict releases the least used pages from cache until the number of elements in cache are less than cachedNodeCountTarget
func (mtc *merkleTrieCache) evict() (removedNodes int) {
	removedNodes = mtc.cachedNodeCount

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
