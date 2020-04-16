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

	"github.com/algorand/go-algorand/crypto"
)

type node struct {
	hash         []byte
	children     []storedNodeIdentifier
	childrenNext []byte
	firstChild   byte
	leaf         bool
}

func (n *node) stats(cache *merkleTrieCache, stats *Stats, depth int) (err error) {
	stats.nodesCount++
	if n.leaf {
		stats.leafCount++
		if depth > stats.depth {
			stats.depth = depth
		}
		stats.size += 4 + len(n.hash) + 1
		return nil
	}
	i := n.firstChild
	stats.size += 4 + len(n.hash) + cap(n.children)*8 + cap(n.childrenNext) + 1
	for {
		childNode, err := cache.getNode(n.children[i])
		if err != nil {
			return err
		}
		err = childNode.stats(cache, stats, depth+1)
		if err != nil {
			return err
		}
		if i == n.childrenNext[i] {
			break
		}
		i = n.childrenNext[i]
	}
	return nil
}

func (n *node) find(cache *merkleTrieCache, d []byte) (bool, error) {
	if n.leaf {
		return 0 == bytes.Compare(d, n.hash), nil
	}
	i := n.firstChild
	for {
		if i > d[0] {
			break
		}
		if i == d[0] {
			childNode, err := cache.getNode(n.children[i])
			if err != nil {
				return false, err
			}
			found, err := childNode.find(cache, d[1:])
			if err != nil {
				return false, err
			}
			if found {
				return true, nil
			}
		}
		if i == n.childrenNext[i] {
			break
		}
		i = n.childrenNext[i]
	}
	return false, nil
}

// assumption : we know that the key is absent from the tree
func (n *node) add(cache *merkleTrieCache, d []byte, path []byte) (nodeID storedNodeIdentifier, err error) {
	// allocate a new node to replace the current one.
	var pnode *node
	if n.leaf {
		// find the diff index:
		idiff := 0
		for ; n.hash[idiff] == d[idiff]; idiff++ {
		}

		curChildNode, curChildNodeID := cache.allocateNewNode()
		newChildNode, newChildNodeID := cache.allocateNewNode()

		curChildNode.leaf = true
		curChildNode.hash = n.hash[idiff+1:]
		newChildNode.leaf = true
		newChildNode.hash = d[idiff+1:]

		pnode, nodeID = cache.allocateNewNode()
		pnode.leaf = false
		pnode.children = make([]storedNodeIdentifier, 256)
		pnode.childrenNext = make([]byte, 256)

		pnode.children[n.hash[idiff]] = curChildNodeID
		pnode.children[d[idiff]] = newChildNodeID
		if n.hash[idiff] < d[idiff] {
			pnode.firstChild = n.hash[idiff]
			pnode.childrenNext[pnode.firstChild] = d[idiff]
			pnode.childrenNext[d[idiff]] = d[idiff]
		} else {
			pnode.firstChild = d[idiff]
			pnode.childrenNext[pnode.firstChild] = n.hash[idiff]
			pnode.childrenNext[n.hash[idiff]] = n.hash[idiff]
		}
		err = pnode.recalculateHash(cache, append(path, d[:idiff]...))

		for i := idiff - 1; i >= 0; i-- {
			// create a parent node for pnode.
			pnode2, nodeID2 := cache.allocateNewNode()
			pnode2.leaf = false
			pnode2.children = make([]storedNodeIdentifier, 256)
			pnode2.childrenNext = make([]byte, 256)
			pnode2.children[d[i]] = nodeID
			pnode2.firstChild = d[i]
			pnode2.childrenNext[d[i]] = d[i]
			err = pnode2.recalculateHash(cache, append(path, d[:i]...))

			pnode = pnode2
			nodeID = nodeID2
		}

		return nodeID, err
	}

	if n.children[d[0]] == storedNodeIdentifierNull {
		// no such child.
		var childNode *node
		var childNodeID storedNodeIdentifier
		childNode, childNodeID = cache.allocateNewNode()
		childNode.leaf = true
		childNode.hash = d[1:]

		pnode, nodeID = n.duplicate(cache)
		pnode.children[d[0]] = childNodeID

		if pnode.firstChild > d[0] {
			pnode.childrenNext[d[0]] = pnode.firstChild
			pnode.firstChild = d[0]
		} else {
			// iterate on all the entries.
			i := pnode.firstChild
			for {
				if pnode.childrenNext[i] < d[0] {
					if pnode.childrenNext[i] == i {
						pnode.childrenNext[i] = d[0]
						pnode.childrenNext[d[0]] = d[0]
						break
					}
				} else {
					pnode.childrenNext[d[0]] = pnode.childrenNext[i]
					pnode.childrenNext[i] = d[0]
					break
				}
				i = pnode.childrenNext[i]
			}
		}
	} else {
		// there is already a child there.
		childNode, err := cache.getNode(n.children[d[0]])
		if err != nil {
			_, nodeID = cache.allocateNewNode()
			return nodeID, err
		}
		updatedChild, err := childNode.add(cache, d[1:], append(path, d[0]))
		if err != nil {
			cache.deleteNode(updatedChild)
			_, nodeID = cache.allocateNewNode()
			return nodeID, err
		}
		pnode, nodeID = n.duplicate(cache)
		cache.deleteNode(n.children[d[0]])
		pnode.children[d[0]] = updatedChild
	}
	err = pnode.recalculateHash(cache, path)
	return nodeID, err
}

func (n *node) recalculateHash(cache *merkleTrieCache, path []byte) error {
	hashAccumulator := make([]byte, 0, 64*256)                 // we can have up to 256 elements, so preallocate sufficient storage; append would expand the storage if it won't be enough.
	hashAccumulator = append(hashAccumulator, byte(len(path))) // we add this string length before the actual string so it could get "decoded"; in practice, it makes a good domain separator.
	hashAccumulator = append(hashAccumulator, path...)
	i := n.firstChild
	for {
		childNode, err := cache.getNode(n.children[i])
		if err != nil {
			return err
		}
		hashAccumulator = append(hashAccumulator, byte(len(childNode.hash)+1)) // we add this string length before the actual string so it could get "decoded"; in practice, it makes a good domain separator.
		hashAccumulator = append(hashAccumulator, i)                           // adding the first byte of the child
		hashAccumulator = append(hashAccumulator, childNode.hash...)           // adding the reminder of the child
		if n.childrenNext[i] == i {
			break
		}
		i = n.childrenNext[i]
	}
	hash := crypto.Hash(hashAccumulator)
	n.hash = hash[:]
	return nil
}

// function remove is called only on non-leaf nodes.
// assumption : we know that the key is already included in the tree
func (n *node) remove(cache *merkleTrieCache, key []byte, path []byte) (nodeID storedNodeIdentifier, err error) {
	// allocate a new node to replace the current one.
	var pnode, childNode *node
	childNode, err = cache.getNode(n.children[key[0]])
	if err != nil {
		return
	}
	if childNode.leaf {
		pnode, nodeID = n.duplicate(cache)
		cache.deleteNode(pnode.children[key[0]]) // add now
		// we have one or more children, see if it's the first child:
		if pnode.firstChild == key[0] {
			// we're removing the first child.
			next := pnode.childrenNext[pnode.firstChild]
			pnode.children[pnode.firstChild] = storedNodeIdentifierNull
			pnode.childrenNext[pnode.firstChild] = 0
			pnode.firstChild = next
		} else {
			// wer're removing a child off the list ( known to be there, and not to be the first )
			i := pnode.firstChild
			for {
				if pnode.childrenNext[i] == key[0] {
					// is this the last item ?
					if pnode.childrenNext[key[0]] == key[0] {
						// yes, it's the last item.
						pnode.childrenNext[i] = i
						// clear out pointers.
						pnode.childrenNext[key[0]] = 0
						pnode.children[key[0]] = storedNodeIdentifierNull
						break
					}
					pnode.childrenNext[i] = pnode.childrenNext[key[0]]
					// clear out pointers
					pnode.childrenNext[key[0]] = 0
					pnode.children[key[0]] = storedNodeIdentifierNull
					break
				}
				i = pnode.childrenNext[i]
			}
		}
	} else {
		var updatedChildNodeID storedNodeIdentifier
		updatedChildNodeID, err = childNode.remove(cache, key[1:], append(path, key[0]))

		if err != nil {
			cache.deleteNode(updatedChildNodeID)
			_, nodeID = cache.allocateNewNode()
			return nodeID, err
		}
		pnode, nodeID = n.duplicate(cache)
		pnode.children[key[0]] = updatedChildNodeID
	}
	// at this point, we migth end up with a single leaf child. collapse that.
	if pnode.childrenNext[pnode.firstChild] == pnode.firstChild {
		childNode, err = cache.getNode(pnode.children[pnode.firstChild])
		if err != nil {
			return
		}
		if childNode.leaf {
			// convert current node into a leaf.
			pnode.leaf = true
			pnode.hash = append([]byte{pnode.firstChild}, childNode.hash...)
			pnode.childrenNext[key[0]] = 0
			cache.deleteNode(pnode.children[key[0]])
			pnode.children[key[0]] = storedNodeIdentifierNull
			pnode.firstChild = 0
		}
	}
	if !pnode.leaf {
		err = pnode.recalculateHash(cache, path)
	}
	return nodeID, nil
}

func (n *node) duplicate(cache *merkleTrieCache) (pnode *node, nodeID storedNodeIdentifier) {
	pnode, nodeID = cache.allocateNewNode()
	pnode.firstChild = n.firstChild
	pnode.hash = n.hash // the hash is safe for just copy without duplicate, since it's always being reallocated upon change.
	pnode.leaf = n.leaf
	if !pnode.leaf {
		pnode.children = make([]storedNodeIdentifier, 256)
		pnode.childrenNext = make([]byte, 256)
		// copy the elements starting the first known entry.
		copy(pnode.children[n.firstChild:], n.children[n.firstChild:])
		copy(pnode.childrenNext[n.firstChild:], n.childrenNext[n.firstChild:])
	}
	return
}

// serialize the content of the node into the buffer, and return the number of bytes consumed in the process.
func (n *node) serialize(buf []byte) int {
	w := binary.PutUvarint(buf[:], uint64(len(n.hash)))
	copy(buf[w:], n.hash)
	w += len(n.hash)
	if n.leaf {
		buf[w] = 0 // leaf
		return w + 1
	}
	// non-leaf
	buf[w] = 1 // non-leaf
	w++
	// store all the children, and terminate with a null.
	i := n.firstChild
	for {
		buf[w] = i
		w++
		x := binary.PutUvarint(buf[w:], uint64(n.children[i]))
		w += x
		if i == n.childrenNext[i] {
			break
		}
		i = n.childrenNext[i]
	}
	buf[w] = i
	w++
	return w
}

func deserializeNode(buf []byte) (n *node, s int) {
	n = &node{}
	hashLength, hashLength2 := binary.Uvarint(buf[:])
	if hashLength2 <= 0 {
		return nil, hashLength2
	}
	n.hash = make([]byte, hashLength)
	copy(n.hash, buf[hashLength2:hashLength2+int(hashLength)])
	s = hashLength2 + int(hashLength)
	n.leaf = (buf[s] == 0)
	s++
	if n.leaf {
		return
	}
	n.children = make([]storedNodeIdentifier, 256)
	n.childrenNext = make([]byte, 256)
	first := true
	prevChildIndex := byte(0)

	for {
		childIndex := buf[s]
		s++
		if childIndex <= prevChildIndex && !first {
			break
		}
		if first {
			first = false
			n.firstChild = childIndex
		} else {
			n.childrenNext[prevChildIndex] = childIndex
		}
		nodeID, nodeIDLength := binary.Uvarint(buf[s:])
		if nodeIDLength <= 0 {
			return nil, nodeIDLength
		}
		s += nodeIDLength
		n.children[childIndex] = storedNodeIdentifier(nodeID)
		prevChildIndex = childIndex
	}
	n.childrenNext[prevChildIndex] = prevChildIndex
	return
}
