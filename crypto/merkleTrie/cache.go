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
	"encoding/binary"
	"errors"
)

// storedNodeIdentifier is the "equivilent" of a node-ptr, but oriented around persisting the
// nodes to disk. ( i.e. think of a virtual memory address )
type storedNodeIdentifier uint64

const (
	storedNodeIdentifierNull = 0x0
	storedNodeIdentifierBase = 0x4160
	pageMaxSerializedSize    = 1024 * 1024
)

// ErrLoadedPageMissingNode is returned when a request is made for a specific node identifier, and that identifier cannot
// be found in neither the in-memory cache or on the persistent storage.
var ErrLoadedPageMissingNode = errors.New("loaded page is missing a node")

// ErrPageDecodingError is returned if the decoding of a page has failed.
var ErrPageDecodingError = errors.New("error encountered while decoding page")

type merkleTrieCache struct {
	idToPtr   map[storedNodeIdentifier]*node
	mt        *MerkleTrie
	committer Committer

	txCreatedNodeIDs map[storedNodeIdentifier]bool
	txDeletedNodeIDs map[storedNodeIdentifier]bool
	txNextNodeID     storedNodeIdentifier

	pendingCreatedNID  map[storedNodeIdentifier]bool
	pendingDeletionNID map[storedNodeIdentifier]bool
}

func (mtc *merkleTrieCache) initialize(mt *MerkleTrie) {
	mtc.mt = mt
	mtc.idToPtr = make(map[storedNodeIdentifier]*node)
	mtc.txNextNodeID = storedNodeIdentifierNull
	mtc.committer = &InMemoryCommitter{}
	mtc.pendingCreatedNID = make(map[storedNodeIdentifier]bool)
	mtc.pendingDeletionNID = make(map[storedNodeIdentifier]bool)
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
		return
	}
	nodesPerPage := mtc.committer.GetNodesCountPerPage()
	pageBytes, err := mtc.committer.LoadPage(uint64(nid) / uint64(nodesPerPage))
	if err != nil {
		return
	}
	decodedNodes, err := mtc.decodePage(pageBytes)
	if err != nil {
		return
	}
	if _, has := decodedNodes[nid]; !has {
		return nil, ErrLoadedPageMissingNode
	}
	for nodeID, pnode := range decodedNodes {
		mtc.idToPtr[nodeID] = pnode
	}
	pnode = decodedNodes[nid]
	return
}

func (mtc *merkleTrieCache) deleteNode(nid storedNodeIdentifier) (err error) {
	if mtc.txCreatedNodeIDs[nid] {
		delete(mtc.txCreatedNodeIDs, nid)
	} else {
		mtc.txDeletedNodeIDs[nid] = true
	}

	return nil
}

func (mtc *merkleTrieCache) beginTransaction() {
	mtc.txCreatedNodeIDs = make(map[storedNodeIdentifier]bool)
	mtc.txDeletedNodeIDs = make(map[storedNodeIdentifier]bool)
	mtc.txNextNodeID = mtc.mt.nextNodeID
}

func (mtc *merkleTrieCache) commitTransaction() {
	// the created nodes are already on the list.
	for nodeID := range mtc.txCreatedNodeIDs {
		mtc.pendingCreatedNID[nodeID] = true
	}
	mtc.txCreatedNodeIDs = nil

	// delete the ones that we don't want from the list.
	for nodeID := range mtc.txDeletedNodeIDs {
		if mtc.pendingCreatedNID[nodeID] {
			// it was never flushed.
			delete(mtc.pendingCreatedNID, nodeID)
			continue
		}
		mtc.pendingDeletionNID[nodeID] = true
		delete(mtc.idToPtr, nodeID)
	}
	mtc.txDeletedNodeIDs = nil
}

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
	toRemovePages := make(map[int64]struct{})
	for nodeID := range mtc.pendingDeletionNID {
		toRemovePages[int64(nodeID)/pageSize] = struct{}{}
	}

	// iterate over the existing list and ensure we don't delete any page that has active elements
	for nodeID := range mtc.idToPtr {
		page := int64(nodeID) / pageSize
		if _, has := toRemovePages[page]; has {
			delete(toRemovePages, page)
		}
	}

	// delete the pages that we don't need anymore.
	for page := range toRemovePages {
		mtc.committer.StorePage(uint64(page), nil)
	}

	return nil
}

func (mtc *merkleTrieCache) decodePage(bytes []byte) (nodesMap map[storedNodeIdentifier]*node, err error) {
	version, versionLength := binary.Uvarint(bytes[:])
	if versionLength <= 0 {
		return nil, ErrPageDecodingError
	}
	if version != NodePageVersion {
		return nil, ErrPageDecodingError
	}
	nodesCount, nodesCountLength := binary.Varint(bytes[versionLength:])
	if nodesCountLength <= 0 {
		return nil, ErrPageDecodingError
	}
	nodesMap = make(map[storedNodeIdentifier]*node)
	walk := nodesCountLength + versionLength
	for i := int64(0); i < nodesCount; i++ {
		nodeID, nodesIDLength := binary.Uvarint(bytes[walk:])
		if nodesIDLength <= 0 {
			return nil, ErrPageDecodingError
		}
		walk += nodesIDLength
		pnode, nodeLength := deserializeNode(bytes[walk:])
		if nodeLength <= 0 {
			return nil, ErrPageDecodingError
		}
		walk += nodeLength
		nodesMap[storedNodeIdentifier(nodeID)] = pnode
	}

	return nodesMap, nil
}

func (mtc *merkleTrieCache) encodePage(nodeIDs []storedNodeIdentifier) []byte {
	serializedBuffer := make([]byte, pageMaxSerializedSize)
	version := binary.PutUvarint(serializedBuffer[:], NodePageVersion)
	length := binary.PutVarint(serializedBuffer[version:], int64(len(mtc.idToPtr)))
	walk := version + length
	for nodeID, pnode := range mtc.idToPtr {
		n := binary.PutUvarint(serializedBuffer[walk:], uint64(nodeID))
		walk += n
		n = pnode.serialize(serializedBuffer[walk:])
		walk += n
	}
	return nil
}
