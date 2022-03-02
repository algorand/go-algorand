// Copyright (C) 2019-2022 Algorand, Inc.
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

package ledger

// persistedResourcesDataList represents a doubly linked list.
// must initiate with newPersistedAccountList.
type persistedResourcesDataList struct {
	root     persistedResourcesDataListNode  // sentinel list element, only &root, root.prev, and root.next are used
	freeList *persistedResourcesDataListNode // preallocated nodes location
}

type persistedResourcesDataListNode struct {
	// Next and previous pointers in the doubly-linked list of elements.
	// To simplify the implementation, internally a list l is implemented
	// as a ring, such that &l.root is both the next element of the last
	// list element (l.Back()) and the previous element of the first list
	// element (l.Front()).
	next, prev *persistedResourcesDataListNode

	Value *cachedResourceData
}

func newPersistedResourcesList() *persistedResourcesDataList {
	l := new(persistedResourcesDataList)
	l.root.next = &l.root
	l.root.prev = &l.root
	// used as a helper but does not store value
	l.freeList = new(persistedResourcesDataListNode)

	return l
}

func (l *persistedResourcesDataList) insertNodeToFreeList(otherNode *persistedResourcesDataListNode) {
	otherNode.next = l.freeList.next
	otherNode.prev = nil
	otherNode.Value = nil

	l.freeList.next = otherNode
}

func (l *persistedResourcesDataList) getNewNode() *persistedResourcesDataListNode {
	if l.freeList.next == nil {
		return new(persistedResourcesDataListNode)
	}
	newNode := l.freeList.next
	l.freeList.next = newNode.next

	return newNode
}

func (l *persistedResourcesDataList) allocateFreeNodes(numAllocs int) *persistedResourcesDataList {
	if l.freeList == nil {
		return l
	}
	for i := 0; i < numAllocs; i++ {
		l.insertNodeToFreeList(new(persistedResourcesDataListNode))
	}

	return l
}

// Back returns the last element of list l or nil if the list is empty.
func (l *persistedResourcesDataList) back() *persistedResourcesDataListNode {
	isEmpty := func(list *persistedResourcesDataList) bool {
		// assumes we are inserting correctly to the list - using pushFront.
		return list.root.next == &list.root
	}
	if isEmpty(l) {
		return nil
	}
	return l.root.prev
}

// remove removes e from l if e is an element of list l.
// It returns the element value e.Value.
// The element must not be nil.
func (l *persistedResourcesDataList) remove(e *persistedResourcesDataListNode) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil // avoid memory leaks
	e.prev = nil // avoid memory leaks

	l.insertNodeToFreeList(e)
}

// pushFront inserts a new element e with value v at the front of list l and returns e.
func (l *persistedResourcesDataList) pushFront(v *cachedResourceData) *persistedResourcesDataListNode {
	newNode := l.getNewNode()
	newNode.Value = v
	return l.insertValue(newNode, &l.root)
}

// insertValue inserts e after at, increments l.len, and returns e.
func (l *persistedResourcesDataList) insertValue(newNode *persistedResourcesDataListNode, at *persistedResourcesDataListNode) *persistedResourcesDataListNode {
	n := at.next
	at.next = newNode
	newNode.prev = at
	newNode.next = n
	n.prev = newNode

	return newNode
}

// moveToFront moves element e to the front of list l.
// If e is not an element of l, the list is not modified.
// The element must not be nil.
func (l *persistedResourcesDataList) moveToFront(e *persistedResourcesDataListNode) {
	if l.root.next == e {
		return
	}
	l.move(e, &l.root)
}

// move moves e to next to at and returns e.
func (l *persistedResourcesDataList) move(e, at *persistedResourcesDataListNode) *persistedResourcesDataListNode {
	if e == at {
		return e
	}
	e.prev.next = e.next
	e.next.prev = e.prev

	n := at.next
	at.next = e
	e.prev = at
	e.next = n
	n.prev = e

	return e
}
