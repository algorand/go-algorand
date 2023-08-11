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
	"bytes"
	"encoding/binary"
	"sort"
	"unsafe"

	"github.com/algorand/go-algorand/crypto"
	"golang.org/x/exp/slices"
)

type childEntry struct {
	id        storedNodeIdentifier
	hashIndex byte
}
type node struct {
	hash         []byte
	children     []childEntry
	childrenMask bitset
}

// leaf returns whether the current node is a leaf node, or a non-leaf node
func (n *node) leaf() bool {
	return len(n.children) == 0
}

// these sizing constants are being used exclusively in node.stats()
var sliceSize int = int(unsafe.Sizeof([]byte{}))
var bitsetSize int = int(unsafe.Sizeof(bitset{}))
var childEntrySize int = int(unsafe.Sizeof(childEntry{}))

// stats recursively update the provided Stats structure with the current node information
func (n *node) stats(cache *merkleTrieCache, stats *Stats, depth int) (err error) {
	stats.NodesCount++
	if n.leaf() {
		stats.LeafCount++
		if depth > stats.Depth {
			stats.Depth = depth
		}
		stats.Size += sliceSize + len(n.hash) + bitsetSize
		return nil
	}
	stats.Size += sliceSize + len(n.hash) + sliceSize + len(n.children)*childEntrySize + bitsetSize
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

// indexOf returns the index into the children array of the first child whose hashIndex field is less or equal to b
// it's being used in conjunction with the bitset, so we test only the equality path ( i.e. get the index of the
// child that has hashIndex of value x )
func (n *node) indexOf(b byte) byte {
	// find the child using binary search:
	return byte(sort.Search(len(n.children), func(i int) bool { return n.children[i].hashIndex >= b }))
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
		pnode.childrenMask.SetBit(n.hash[idiff])
		pnode.childrenMask.SetBit(d[idiff])

		if n.hash[idiff] < d[idiff] {
			pnode.children = []childEntry{
				{
					id:        curChildNodeID,
					hashIndex: n.hash[idiff],
				},
				{
					id:        newChildNodeID,
					hashIndex: d[idiff],
				},
			}
		} else {
			pnode.children = []childEntry{
				{
					id:        newChildNodeID,
					hashIndex: d[idiff],
				},
				{
					id:        curChildNodeID,
					hashIndex: n.hash[idiff],
				},
			}
		}
		pnode.hash = append(path, d[:idiff]...)

		// create ancestors from pnode up to the new split
		for i := idiff - 1; i >= 0; i-- {
			// create a parent node for pnode, and move up
			pnode2, nodeID2 := cache.allocateNewNode()
			pnode2.childrenMask.SetBit(d[i])
			pnode2.children = []childEntry{
				{
					id:        nodeID,
					hashIndex: d[i],
				},
			}
			pnode2.hash = append(path, d[:i]...)

			nodeID = nodeID2
		}
		return nodeID, nil
	}

	if n.childrenMask.Bit(d[0]) == false {
		// no such child.
		childNode, childNodeID := cache.allocateNewNode()
		childNode.hash = d[1:]

		pnode, nodeID = cache.allocateNewNode()
		pnode.childrenMask = n.childrenMask
		pnode.childrenMask.SetBit(d[0])

		pnode.children = make([]childEntry, len(n.children)+1)
		if d[0] > n.children[len(n.children)-1].hashIndex {
			// the new entry comes after all the existing ones.
			for i, child := range n.children {
				pnode.children[i] = child
			}
			pnode.children[len(pnode.children)-1] = childEntry{
				id:        childNodeID,
				hashIndex: d[0],
			}
		} else {
			for i, child := range n.children {
				if d[0] < child.hashIndex {
					pnode.children[i] = childEntry{
						id:        childNodeID,
						hashIndex: d[0],
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

		pnode, nodeID = childNode, cache.refurbishNode(curNodeID)
		pnode.childrenMask = n.childrenMask
		if len(pnode.children) < len(n.children) {
			pnode.children = make([]childEntry, len(n.children))
		} else {
			pnode.children = pnode.children[:len(n.children)]
		}
		copy(pnode.children, n.children)
		pnode.children[curNodeIndex].id = updatedChild
	}
	pnode.hash = path
	return nodeID, nil
}

// calculateHash calculate the hash of the non-leaf nodes
// when this function is called, the hashes of all the child node are expected
// to have been calculated already. This is achieved by doing the following:
// 1. all node id allocations are done in incremental monolitic order, from the bottom up.
// 2. hash calculations are being doing in node id incremental ordering
func (n *node) calculateHash(cache *merkleTrieCache) error {
	if n.leaf() {
		return nil
	}
	path := n.hash
	hashAccumulator := cache.hashAccumulationBuffer[:0]        // use a preallocated storage and reuse the storage to avoid reallocation.
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
		hashAccumulator = append(hashAccumulator, child.hashIndex)           // adding the first byte of the child
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
		pnode, nodeID = childNode, cache.refurbishNode(childNodeID)
		pnode.childrenMask = n.childrenMask
		// we are guaranteed to have other children, because our tree forbids nodes that have exactly one leaf child and no other children.
		pnode.children = make([]childEntry, len(n.children)-1)
		copy(pnode.children, append(n.children[:childIndex], n.children[childIndex+1:]...))
		pnode.childrenMask.ClearBit(key[0])
	} else {
		var updatedChildNodeID storedNodeIdentifier
		updatedChildNodeID, err = childNode.remove(cache, key[1:], append(path, key[0]))
		if err != nil {
			return storedNodeIdentifierNull, err
		}

		pnode, nodeID = childNode, cache.refurbishNode(childNodeID)
		pnode.childrenMask = n.childrenMask
		if len(pnode.children) < len(n.children) {
			pnode.children = make([]childEntry, len(n.children))
		} else {
			pnode.children = pnode.children[:len(n.children)]
		}
		copy(pnode.children, n.children)
		pnode.children[childIndex].id = updatedChildNodeID
	}

	// at this point, we might end up with a single leaf child. collapse that.
	if len(pnode.children) == 1 {
		childNode, err = cache.getNode(pnode.children[0].id)
		if err != nil {
			return
		}
		if childNode.leaf() {
			// convert current node into a leaf.
			pnode.hash = append([]byte{pnode.children[0].hashIndex}, childNode.hash...)
			cache.deleteNode(pnode.children[0].id)
			pnode.childrenMask.ClearBit(pnode.children[0].hashIndex)
			pnode.children = nil
		}
	}
	if !pnode.leaf() {
		pnode.hash = path
	}
	return nodeID, nil
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
		buf[w] = child.hashIndex
		w++
		x := binary.PutUvarint(buf[w:], uint64(child.id))
		w += x
	}
	buf[w] = n.children[len(n.children)-1].hashIndex
	return w + 1
}

// deserializeNode deserializes the node from a byte array
func deserializeNode(buf []byte) (n *node, s int) {
	n = &node{}
	hashLength, hashLength2 := binary.Uvarint(buf[:])
	if hashLength2 <= 0 {
		return nil, hashLength2
	}
	n.hash = slices.Clone(buf[hashLength2 : hashLength2+int(hashLength)])
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

		childEntries[i] = childEntry{hashIndex: childIndex, id: storedNodeIdentifier(nodeID)}
		n.childrenMask.SetBit(childIndex)
		prevChildIndex = childIndex
		i++
	}
	n.children = make([]childEntry, i)
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
		for {
			if newID, has := reallocationMap[n.children[i].id]; has {
				delete(reallocationMap, n.children[i].id)
				n.children[i].id = newID
				continue
			}
			break
		}
	}
}
