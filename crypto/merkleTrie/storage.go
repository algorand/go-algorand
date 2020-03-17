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

// storedNodeIdentifier is the "equivilent" of a node-ptr, but oriented around persisting the
// nodes to disk. ( i.e. think of a virtual memory address )
type storedNodeIdentifier uint64

const (
	storedNodeIdentifierNull = 0x0
	storedNodeIdentifierBase = 0x4160
)

/*
type MerkleTrieStorage interface {
	allocateNewNode() *node
}*/

type merkleTrieCache struct {
	cacheSize  int // number of nodes that would reside in the case after evict is called.
	nextNodeID storedNodeIdentifier
	idToPtr    map[storedNodeIdentifier]*node

	createdNodeIDs map[storedNodeIdentifier]bool
	deletedNodeIDs map[storedNodeIdentifier]bool
}

func (mtc *merkleTrieCache) initialize() {
	mtc.cacheSize = 1024
	mtc.nextNodeID = storedNodeIdentifierBase
	mtc.idToPtr = make(map[storedNodeIdentifier]*node)
}

func (mtc *merkleTrieCache) allocateNewNode() (pnode *node, nid storedNodeIdentifier) {
	nextID := mtc.nextNodeID
	mtc.nextNodeID++
	newNode := &node{}
	mtc.idToPtr[nextID] = newNode

	mtc.createdNodeIDs[nextID] = true
	return newNode, nextID
}

func (mtc *merkleTrieCache) getNode(nid storedNodeIdentifier) (pnode *node, err error) {
	pnode = mtc.idToPtr[nid]
	if pnode == nil {
		// todo - load it from disk.
	}
	return
}

func (mtc *merkleTrieCache) deleteNode(nid storedNodeIdentifier) (err error) {
	/*pnode := mtc.idToPtr[nid]
	if pnode == nil {
		// todo - load from disk
	}
	delete(mtc.idToPtr, nid)*/
	if mtc.createdNodeIDs[nid] {
		delete(mtc.createdNodeIDs, nid)
	} else {
		mtc.deletedNodeIDs[nid] = true
	}

	return nil
}

func (mtc *merkleTrieCache) beginTransaction() {
	mtc.createdNodeIDs = make(map[storedNodeIdentifier]bool)
	mtc.deletedNodeIDs = make(map[storedNodeIdentifier]bool)
}

func (mtc *merkleTrieCache) commitTransaction() {
	// the created nodes are already on the list.
	mtc.createdNodeIDs = nil
	// delete the ones that we don't want from the list.
	for nodeID := range mtc.deletedNodeIDs {
		delete(mtc.idToPtr, nodeID)
	}
	mtc.deletedNodeIDs = nil
}

func (mtc *merkleTrieCache) rollbackTransaction() {
	// no need to delete anything.
	mtc.deletedNodeIDs = nil
	// drop all the created nodes ids
	for nodeID := range mtc.createdNodeIDs {
		delete(mtc.idToPtr, nodeID)
	}
	mtc.createdNodeIDs = nil
}
