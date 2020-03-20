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
)

// storedNodeIdentifier is the "equivilent" of a node-ptr, but oriented around persisting the
// nodes to disk. ( i.e. think of a virtual memory address )
type storedNodeIdentifier uint64

const (
	storedNodeIdentifierNull = 0x0
	storedNodeIdentifierBase = 0x4160
	maxNodeSerializedSize    = 3000
)

// ErrLoadedPageMissingNode is returned when a request is made for a specific node identifier, and that identifier cannot
// be found in neither the in-memory cache or on the persistent storage.
var ErrLoadedPageMissingNode = errors.New("loaded page is missing a node")

// ErrPageDecodingFailuire is returned if the decoding of a page has failed.
var ErrPageDecodingFailuire = errors.New("error encountered while decoding page")

type merkleTrieCache struct {
	idToPtr   map[storedNodeIdentifier]*node
	mt        *MerkleTrie
	committer Committer

	txCreatedNodeIDs map[storedNodeIdentifier]bool
	txDeletedNodeIDs map[storedNodeIdentifier]bool
	txNextNodeID     storedNodeIdentifier

	pendingCreatedNID  map[storedNodeIdentifier]bool
	pendingDeletionNID map[storedNodeIdentifier]bool

	pagesPrioritizationList *list.List               // a list of the pages priorities. The item in the front has higher priority and would not get evicted as quickly as the item on the back
	pagesPrioritizationMap  map[uint64]*list.Element // the list element of each of the priorities
}

func (mtc *merkleTrieCache) initialize(mt *MerkleTrie, committer Committer) {
	mtc.mt = mt
	mtc.idToPtr = make(map[storedNodeIdentifier]*node)
	mtc.txNextNodeID = storedNodeIdentifierNull
	mtc.committer = committer
	mtc.pendingCreatedNID = make(map[storedNodeIdentifier]bool)
	mtc.pendingDeletionNID = make(map[storedNodeIdentifier]bool)
	mtc.pagesPrioritizationList = list.New()
	mtc.pagesPrioritizationMap = make(map[uint64]*list.Element)
}

func (mtc *merkleTrieCache) allocateNewNode() (pnode *node, nid storedNodeIdentifier) {
	nextID := mtc.mt.nextNodeID
	mtc.mt.nextNodeID++
	newNode := &node{}
	mtc.idToPtr[nextID] = newNode

	mtc.txCreatedNodeIDs[nextID] = true
	return newNode, nextID
}

func (mtc *merkleTrieCache) getNode(nid storedNodeIdentifier) (pnode *node, err error) {
	pnode = mtc.idToPtr[nid]
	if pnode != nil {
		mtc.prioritizeNode(nid)
		return
	}
	nodesPerPage := mtc.committer.GetNodesCountPerPage()
	nodePage := uint64(nid) / uint64(nodesPerPage)
	err = mtc.loadPage(nodePage)
	if err != nil {
		return
	}
	var have bool
	if pnode, have = mtc.idToPtr[nid]; !have {
		err = ErrLoadedPageMissingNode
	} else {
		mtc.prioritizeNode(nid)
	}
	return
}

func (mtc *merkleTrieCache) prioritizeNode(nid storedNodeIdentifier) {
	nodesPerPage := mtc.committer.GetNodesCountPerPage()
	page := uint64(nid) / uint64(nodesPerPage)

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

func (mtc *merkleTrieCache) loadPage(page uint64) (err error) {
	pageBytes, err := mtc.committer.LoadPage(page)
	if err != nil {
		return
	}
	decodedNodes, err := decodePage(pageBytes)
	if err != nil {
		return
	}
	for nodeID, pnode := range decodedNodes {
		mtc.idToPtr[nodeID] = pnode
	}
	return
}

func (mtc *merkleTrieCache) deleteNode(nid storedNodeIdentifier) {
	if mtc.txCreatedNodeIDs[nid] {
		delete(mtc.txCreatedNodeIDs, nid)
		delete(mtc.idToPtr, nid)
	} else {
		mtc.txDeletedNodeIDs[nid] = true
	}
}

// beginTransaction - used internaly by the merkleTrie
func (mtc *merkleTrieCache) beginTransaction() {
	mtc.txCreatedNodeIDs = make(map[storedNodeIdentifier]bool)
	mtc.txDeletedNodeIDs = make(map[storedNodeIdentifier]bool)
	mtc.txNextNodeID = mtc.mt.nextNodeID
}

// commitTransaction - used internaly by the merkleTrie
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
			delete(mtc.idToPtr, nodeID)
			continue
		}
		mtc.pendingDeletionNID[nodeID] = true
		delete(mtc.idToPtr, nodeID)
	}
	mtc.txDeletedNodeIDs = nil
}

// rollbackTransaction - used internaly by the merkleTrie
func (mtc *merkleTrieCache) rollbackTransaction() {
	// no need to delete anything.
	mtc.txDeletedNodeIDs = nil
	// drop all the created nodes ids
	for nodeID := range mtc.txCreatedNodeIDs {
		delete(mtc.idToPtr, nodeID)
	}
	mtc.txDeletedNodeIDs = nil
	mtc.mt.nextNodeID = mtc.txNextNodeID
	mtc.txNextNodeID = storedNodeIdentifierNull
}

// commit - used as part of the merkleTrie Commit functionality
func (mtc *merkleTrieCache) commit() error {
	pageSize := mtc.committer.GetNodesCountPerPage()

	createdPages := make(map[int64][]storedNodeIdentifier)

	// create a list of all the pages that need to be created/updated
	for nodeID := range mtc.pendingCreatedNID {
		createdPages[int64(nodeID)/pageSize] = make([]storedNodeIdentifier, 0, pageSize)
	}

	// go over all the items that we have, and populate each of the pages.
	for nodeID := range mtc.idToPtr {
		page := int64(nodeID) / pageSize
		if _, has := createdPages[page]; has {
			createdPages[page] = append(createdPages[page], nodeID)
		}
	}

	// store the pages.
	for page, nodeIDs := range createdPages {
		pageContent := mtc.encodePage(nodeIDs)
		mtc.committer.StorePage(uint64(page), pageContent)
	}

	// pages that contains elemets that were removed.
	toRemovePages := make(map[int64]bool)
	for nodeID := range mtc.pendingDeletionNID {
		toRemovePages[int64(nodeID)/pageSize] = true
	}

	// iterate over the existing list and ensure we don't delete any page that has active elements
	for nodeID := range mtc.idToPtr {
		page := int64(nodeID) / pageSize
		if toRemovePages[page] {
			delete(toRemovePages, page)
		}
	}

	// delete the pages that we don't need anymore.
	for page := range toRemovePages {
		mtc.committer.StorePage(uint64(page), nil)
	}

	mtc.pendingCreatedNID = make(map[storedNodeIdentifier]bool)
	mtc.pendingDeletionNID = make(map[storedNodeIdentifier]bool)
	return nil
}

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

func (mtc *merkleTrieCache) encodePage(nodeIDs []storedNodeIdentifier) []byte {
	serializedBuffer := make([]byte, maxNodeSerializedSize*len(nodeIDs)+32)
	version := binary.PutUvarint(serializedBuffer[:], NodePageVersion)
	length := binary.PutVarint(serializedBuffer[version:], int64(len(nodeIDs)))
	walk := version + length
	for _, nodeID := range nodeIDs {
		n := binary.PutUvarint(serializedBuffer[walk:], uint64(nodeID))
		walk += n
		pnode := mtc.idToPtr[nodeID]
		n = pnode.serialize(serializedBuffer[walk:])
		walk += n
	}
	return serializedBuffer[:walk]
}

func (mtc *merkleTrieCache) evict(targetCacheSize int) (removedNodes int) {
	pageSize := mtc.committer.GetNodesCountPerPage()
	for len(mtc.idToPtr) > targetCacheSize {
		// get the least used page off the pagesPrioritizationList
		element := mtc.pagesPrioritizationList.Back()
		if element == nil {
			break
		}
		mtc.pagesPrioritizationList.Remove(element)
		pageToRemove := element.Value.(uint64)
		elementsToRemove := make([]storedNodeIdentifier, 0, pageSize)
		for nodeID := range mtc.idToPtr {
			page := uint64(nodeID) / uint64(pageSize)
			if page != pageToRemove {
				continue
			}
			elementsToRemove = append(elementsToRemove, nodeID)
		}
		for _, nodeID := range elementsToRemove {
			delete(mtc.idToPtr, nodeID)
			removedNodes++

		}
	}
	return
}
