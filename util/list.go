// Copyright (C) 2019-2024 Algorand, Inc.
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

package util

// List represents a doubly linked list.
// must initiate with NewList.
type List[T any] struct {
	root     ListNode[T]  // sentinel list element, only &root, root.prev, and root.next are used
	freeList *ListNode[T] // preallocated nodes location
}

// ListNode represent a list node holding next/prev pointers and a value of type T.
type ListNode[T any] struct {
	// Next and previous pointers in the doubly-linked list of elements.
	// To simplify the implementation, internally a list l is implemented
	// as a ring, such that &l.root is both the next element of the last
	// list element (l.Back()) and the previous element of the first list
	// element (l.Front()).
	next, prev *ListNode[T]

	Value T
}

// NewList creates a new list for storing values of type T.
func NewList[T any]() *List[T] {
	l := new(List[T])
	l.root.next = &l.root
	l.root.prev = &l.root
	// used as a helper but does not store value
	l.freeList = new(ListNode[T])

	return l
}

func (l *List[T]) insertNodeToFreeList(otherNode *ListNode[T]) {
	otherNode.next = l.freeList.next
	otherNode.prev = nil
	var empty T
	otherNode.Value = empty

	l.freeList.next = otherNode
}

func (l *List[T]) getNewNode() *ListNode[T] {
	if l.freeList.next == nil {
		return new(ListNode[T])
	}
	newNode := l.freeList.next
	l.freeList.next = newNode.next

	return newNode
}

// AllocateFreeNodes adds N nodes to the free list
func (l *List[T]) AllocateFreeNodes(numAllocs int) *List[T] {
	if l.freeList == nil {
		return l
	}
	for i := 0; i < numAllocs; i++ {
		l.insertNodeToFreeList(new(ListNode[T]))
	}

	return l
}

// Back returns the last element of list l or nil if the list is empty.
func (l *List[T]) Back() *ListNode[T] {
	isEmpty := func(list *List[T]) bool {
		// assumes we are inserting correctly to the list - using pushFront.
		return list.root.next == &list.root
	}
	if isEmpty(l) {
		return nil
	}
	return l.root.prev
}

// Remove removes e from l if e is an element of list l.
// The element must not be nil.
func (l *List[T]) Remove(e *ListNode[T]) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil // avoid memory leaks
	e.prev = nil // avoid memory leaks

	l.insertNodeToFreeList(e)
}

// PushFront inserts a new element e with value v at the front of list l and returns e.
func (l *List[T]) PushFront(v T) *ListNode[T] {
	newNode := l.getNewNode()
	newNode.Value = v
	return l.insertValue(newNode, &l.root)
}

// insertValue inserts e after at, increments l.len, and returns e.
func (l *List[T]) insertValue(newNode *ListNode[T], at *ListNode[T]) *ListNode[T] {
	n := at.next
	at.next = newNode
	newNode.prev = at
	newNode.next = n
	n.prev = newNode

	return newNode
}

// MoveToFront moves element e to the front of list l.
// If e is not an element of l, the list is not modified.
// The element must not be nil.
func (l *List[T]) MoveToFront(e *ListNode[T]) {
	if l.root.next == e {
		return
	}
	l.move(e, &l.root)
}

// move moves e to next to at and returns e.
func (l *List[T]) move(e, at *ListNode[T]) *ListNode[T] {
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
