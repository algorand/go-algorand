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
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/algorand/go-algorand/crypto"
)

type childEntry struct {
	id    storedNodeIdentifier
	index byte
}
type node struct {
	hash         []byte
	children     []childEntry
	childrenMask bitset
}

func (n *node) leaf() bool {
	return n.childrenMask.IsZero()
}
func (n *node) stats(cache *merkleTrieCache, stats *Stats, depth int) (err error) {
	stats.nodesCount++
	if n.leaf() {
		stats.leafCount++
		if depth > stats.depth {
			stats.depth = depth
		}
		stats.size += 4 + len(n.hash) + 1
		return nil
	}
	stats.size += 32 + len(n.hash) + len(n.children)*9
	for _, child := range n.children {
		childNode, err := cache.getNode(child.id)
		if err != nil {
			return err
		}
		err = childNode.stats(cache, stats, depth+1)
		if err != nil {
			return err
		}
	}
	return nil
}

func (n *node) indexOf(b byte) byte {
	// find the child using binary search:
	return byte(sort.Search(len(n.children), func(i int) bool { return n.children[i].index >= b }))
}

// find searches the trie for the element, recursively.
func (n *node) find(cache *merkleTrieCache, d []byte) (bool, error) {
	if n.leaf() {
		return 0 == bytes.Compare(d, n.hash), nil
	}
	if n.childrenMask.Bit(d[0]) == false {
		return false, nil
	}
	childNodeID := n.children[n.indexOf(d[0])].id
	childNode, err := cache.getNode(childNodeID)
	if err != nil {
		return false, err
	}
	return childNode.find(cache, d[1:])
}

// add adds an element to the sub-trie
// assumption : we know that the key is absent from the tree
func (n *node) add(cache *merkleTrieCache, d []byte, path []byte) (nodeID storedNodeIdentifier, err error) {
	// allocate a new node to replace the current one.
	var pnode *node
	if n.leaf() {
		// find the diff index:
		idiff := 0
		for ; n.hash[idiff] == d[idiff]; idiff++ {
		}

		curChildNode, curChildNodeID := cache.allocateNewNode()
		newChildNode, newChildNodeID := cache.allocateNewNode()

		curChildNode.hash = n.hash[idiff+1:]
		newChildNode.hash = d[idiff+1:]

		pnode, nodeID = cache.allocateNewNode()
		pnode.childrenMask.SetBit(n.hash[idiff], true)
		pnode.childrenMask.SetBit(d[idiff], true)

		if n.hash[idiff] < d[idiff] {
			pnode.children = []childEntry{
				childEntry{
					id:    curChildNodeID,
					index: n.hash[idiff],
				},
				childEntry{
					id:    newChildNodeID,
					index: d[idiff],
				},
			}
		} else {
			pnode.children = []childEntry{
				childEntry{
					id:    newChildNodeID,
					index: d[idiff],
				},
				childEntry{
					id:    curChildNodeID,
					index: n.hash[idiff],
				},
			}
		}
		pnode.hash = append(path, d[:idiff]...)

		for i := idiff - 1; i >= 0; i-- {
			// create a parent node for pnode.
			pnode2, nodeID2 := cache.allocateNewNode()
			pnode2.childrenMask.SetBit(d[i], true)
			pnode2.children = []childEntry{
				childEntry{
					id:    nodeID,
					index: d[i],
				},
			}
			pnode2.hash = append(path, d[:i]...)

			pnode = pnode2
			nodeID = nodeID2
		}
		return nodeID, nil
	}

	if n.childrenMask.Bit(d[0]) == false {
		// no such child.
		var childNode *node
		var childNodeID storedNodeIdentifier
		childNode, childNodeID = cache.allocateNewNode()
		childNode.hash = d[1:]

		pnode, nodeID = cache.allocateNewNode()
		pnode.childrenMask = n.childrenMask
		pnode.childrenMask.SetBit(d[0], true)

		pnode.children = make([]childEntry, len(n.children)+1, len(n.children)+1)
		if d[0] > n.children[len(n.children)-1].index {
			// the new entry comes after all the existing ones.
			for i, child := range n.children {
				pnode.children[i] = child
			}
			pnode.children[len(pnode.children)-1] = childEntry{
				id:    childNodeID,
				index: d[0],
			}
		} else {
			for i, child := range n.children {
				if d[0] < child.index {
					pnode.children[i] = childEntry{
						index: d[0],
						id:    childNodeID,
					}
					// copy the rest of the items.
					for ; i < len(n.children); i++ {
						pnode.children[i+1] = n.children[i]
					}
					break
				}
				pnode.children[i] = child
			}
		}
	} else {
		// there is already a child there.
		curNodeIndex := n.indexOf(d[0])
		curNodeID := n.children[curNodeIndex].id
		childNode, err := cache.getNode(curNodeID)
		if err != nil {
			return storedNodeIdentifierNull, err
		}
		updatedChild, err := childNode.add(cache, d[1:], append(path, d[0]))
		if err != nil {
			return storedNodeIdentifierNull, err
		}
		pnode, nodeID = n.duplicate(cache)
		cache.deleteNode(curNodeID)
		pnode.children[curNodeIndex].id = updatedChild
	}
	pnode.hash = path
	return nodeID, nil
}

// calculateHash calculate the hash of the non-leaf nodes
// when this function is called, the hashes of all the child node are expected
// to have been calculated already. This is achived by doing the following:
// 1. all node id allocations are done in incremental monolitic order, from the bottom up.
// 2. hash calculations are being doing in node id incremental ordering
func (n *node) calculateHash(cache *merkleTrieCache) error {
	if n.leaf() {
		return nil
	}
	path := n.hash
	hashAccumulator := make([]byte, 0, 64*256)                 // we can have up to 256 elements, so preallocate sufficient storage; append would expand the storage if it won't be enough.
	hashAccumulator = append(hashAccumulator, byte(len(path))) // we add this string length before the actual string so it could get "decoded"; in practice, it makes a good domain separator.
	hashAccumulator = append(hashAccumulator, path...)
	for _, child := range n.children {
		childNode, err := cache.getNode(child.id)
		if err != nil {
			return err
		}
		if childNode.leaf() {
			hashAccumulator = append(hashAccumulator, byte(0))
		} else {
			hashAccumulator = append(hashAccumulator, byte(1))
		}
		hashAccumulator = append(hashAccumulator, byte(len(childNode.hash))) // we add this string length before the actual string so it could get "decoded"; in practice, it makes a good domain separator.
		hashAccumulator = append(hashAccumulator, child.index)               // adding the first byte of the child
		hashAccumulator = append(hashAccumulator, childNode.hash...)         // adding the reminder of the child
	}
	hash := crypto.Hash(hashAccumulator)
	n.hash = hash[:]
	return nil
}

// remove removes an element from the sub-trie
// function remove is called only on non-leaf nodes.
// assumption : we know that the key is already included in the tree
func (n *node) remove(cache *merkleTrieCache, key []byte, path []byte) (nodeID storedNodeIdentifier, err error) {
	// allocate a new node to replace the current one.
	var pnode, childNode *node
	childIndex := n.indexOf(key[0])
	childNodeID := n.children[childIndex].id
	childNode, err = cache.getNode(childNodeID)
	if err != nil {
		return
	}
	if childNode.leaf() {
		pnode, nodeID = n.duplicate(cache)
		// we are guaranteed to have other children, because our tree forbids nodes that have exactly one leaf child and no other children.
		pnode.children = append(pnode.children[:childIndex], pnode.children[childIndex+1:]...)
		pnode.childrenMask.SetBit(key[0], false)
	} else {
		var updatedChildNodeID storedNodeIdentifier
		updatedChildNodeID, err = childNode.remove(cache, key[1:], append(path, key[0]))
		if err != nil {
			return storedNodeIdentifierNull, err
		}
		pnode, nodeID = n.duplicate(cache)
		pnode.children[childIndex].id = updatedChildNodeID
	}
	cache.deleteNode(childNodeID)

	// at this point, we might end up with a single leaf child. collapse that.
	if len(pnode.children) == 1 {
		childNode, err = cache.getNode(pnode.children[0].id)
		if err != nil {
			return
		}
		if childNode.leaf() {
			// convert current node into a leaf.
			pnode.hash = append([]byte{pnode.children[0].index}, childNode.hash...)
			cache.deleteNode(pnode.children[0].id)
			pnode.childrenMask.SetBit(pnode.children[0].index, false)
			pnode.children = nil
		}
	}
	if !pnode.leaf() {
		pnode.hash = path
	}
	return nodeID, nil
}

// duplicate creates a copy of the current node
func (n *node) duplicate(cache *merkleTrieCache) (pnode *node, nodeID storedNodeIdentifier) {
	pnode, nodeID = cache.allocateNewNode()
	pnode.hash = n.hash // the hash is safe for just copy without duplicate, since it's always being reallocated upon change.
	pnode.childrenMask = n.childrenMask
	if !pnode.leaf() {
		pnode.children = make([]childEntry, len(n.children), len(n.children))
		for i, v := range n.children {
			pnode.children[i] = v
		}
	}
	return
}

// serialize the content of the node into the buffer, and return the number of bytes consumed in the process.
func (n *node) serialize(buf []byte) int {
	w := binary.PutUvarint(buf[:], uint64(len(n.hash)))
	copy(buf[w:], n.hash)
	w += len(n.hash)
	if n.leaf() {
		buf[w] = 0 // leaf
		return w + 1
	}
	// non-leaf
	buf[w] = 1 // non-leaf
	w++
	// store all the children, and terminate with a null.
	for _, child := range n.children {
		buf[w] = child.index
		w++
		x := binary.PutUvarint(buf[w:], uint64(child.id))
		w += x
	}
	buf[w] = n.children[len(n.children)-1].index
	w++
	return w
}

// deserializeNode deserializes the node from a byte array
func deserializeNode(buf []byte) (n *node, s int) {
	n = &node{}
	hashLength, hashLength2 := binary.Uvarint(buf[:])
	if hashLength2 <= 0 {
		return nil, hashLength2
	}
	n.hash = make([]byte, hashLength)
	copy(n.hash, buf[hashLength2:hashLength2+int(hashLength)])
	s = hashLength2 + int(hashLength)
	isLeaf := (buf[s] == 0)
	s++
	if isLeaf {
		return
	}
	var childEntries [256]childEntry
	first := true
	prevChildIndex := byte(0)
	i := 0
	for {
		childIndex := buf[s]
		s++
		if childIndex <= prevChildIndex && !first {
			break
		}
		first = false
		nodeID, nodeIDLength := binary.Uvarint(buf[s:])
		if nodeIDLength <= 0 {
			return nil, nodeIDLength
		}
		s += nodeIDLength

		childEntries[i] = childEntry{index: childIndex, id: storedNodeIdentifier(nodeID)}
		n.childrenMask.SetBit(childIndex, true)
		prevChildIndex = childIndex
		i++
	}
	n.children = make([]childEntry, i, i)
	copy(n.children, childEntries[:i])
	return
}

func (n *node) getUniqueChildPageCount(nodesPerPage int64) uint64 {
	uniquePages := make(map[int64]struct{}, len(n.children))
	for _, child := range n.children {
		uniquePages[int64(child.id)/nodesPerPage] = struct{}{}
	}
	return uint64(len(uniquePages))
}

func (n *node) reallocateChildren(cache *merkleTrieCache) {
	for i := range n.children {
		n.children[i].id = cache.reallocateNode(n.children[i].id)
	}
}

func (n *node) getChildCount() uint64 {
	return uint64(len(n.children))
}

func (n *node) remapChildren(reallocationMap map[storedNodeIdentifier]storedNodeIdentifier) {
	for i := range n.children {
		if newID, has := reallocationMap[n.children[i].id]; has {
			delete(reallocationMap, n.children[i].id)
			n.children[i].id = newID
		}
	}
}
