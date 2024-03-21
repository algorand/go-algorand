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

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func checkLen[T any](list *List[T]) int {
	if list.root.next == &list.root {
		return 0
	}

	return countListSize(&list.root)
}

func countListSize[T any](head *ListNode[T]) (counter int) {
	for i := head.next; i != head && i != nil; i = i.next {
		counter++
	}
	return counter
}

func checkListLen[T any](t *testing.T, l *List[T], len int) bool {
	if n := checkLen(l); n != len {
		t.Errorf("l.Len() = %d, want %d", n, len)
		return true
	}
	return false
}

func checkListPointers[T any](t *testing.T, l *List[T], es []*ListNode[T]) {
	root := &l.root

	if failed := checkListLen(t, l, len(es)); failed {
		return
	}

	if failed := zeroListInspection(t, l, len(es), root); failed {
		return
	}

	pointerInspection(t, es, root)
}

func zeroListInspection[T any](t *testing.T, l *List[T], len int, root *ListNode[T]) bool {
	// zero length lists must be the zero value or properly initialized (sentinel circle)
	if len == 0 {
		if l.root.next != nil && l.root.next != root || l.root.prev != nil && l.root.prev != root {
			t.Errorf("l.root.next = %p, l.root.prev = %p; both should both be nil or %p", l.root.next, l.root.prev, root)
		}
		return true
	}
	return false
}

func pointerInspection[T any](t *testing.T, es []*ListNode[T], root *ListNode[T]) {
	// check internal and external prev/next connections
	for i, e := range es {
		prev := root
		if i > 0 {
			prev = es[i-1]
		}
		if p := e.prev; p != prev {
			t.Errorf("elt[%d](%p).prev = %p, want %p", i, e, p, prev)
		}

		next := root
		if i < len(es)-1 {
			next = es[i+1]
		}
		if n := e.next; n != next {
			t.Errorf("elt[%d](%p).next = %p, want %p", i, e, n, next)
		}
	}
}

type testVal struct {
	val int
}

func TestList_RemoveFromList(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := NewList[*testVal]()
	e1 := l.PushFront(&testVal{1})
	e2 := l.PushFront(&testVal{2})
	e3 := l.PushFront(&testVal{3})
	checkListPointers(t, l, []*ListNode[*testVal]{e3, e2, e1})

	l.Remove(e2)
	checkListPointers(t, l, []*ListNode[*testVal]{e3, e1})
	l.Remove(e3)
	checkListPointers(t, l, []*ListNode[*testVal]{e1})
}

func TestList_AddingNewNodeWithAllocatedFreeListPtr(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := NewList[*testVal]().AllocateFreeNodes(10)
	checkListPointers(t, l, []*ListNode[*testVal]{})
	if countListSize(l.freeList) != 10 {
		t.Errorf("free list did not allocate nodes")
		return
	}
	// test elements
	e1 := l.PushFront(&testVal{1})
	checkListPointers(t, l, []*ListNode[*testVal]{e1})

	if countListSize(l.freeList) != 9 {
		t.Errorf("free list did not provide a node on new list entry")
		return
	}
}

func TestList_AddingNewNodeWithAllocatedFreeListValue(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := NewList[testVal]().AllocateFreeNodes(10)
	checkListPointers(t, l, []*ListNode[testVal]{})
	if countListSize(l.freeList) != 10 {
		t.Errorf("free list did not allocate nodes")
		return
	}
	// test elements
	e1 := l.PushFront(testVal{1})
	checkListPointers(t, l, []*ListNode[testVal]{e1})

	if countListSize(l.freeList) != 9 {
		t.Errorf("free list did not provide a node on new list entry")
		return
	}
}

func TestList_MultiElementListPositioning(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := NewList[*testVal]()
	checkListPointers(t, l, []*ListNode[*testVal]{})
	// test elements
	e2 := l.PushFront(&testVal{2})
	e1 := l.PushFront(&testVal{1})
	e3 := l.PushFront(&testVal{3})
	e4 := l.PushFront(&testVal{4})
	e5 := l.PushFront(&testVal{5})
	checkListPointers(t, l, []*ListNode[*testVal]{e5, e4, e3, e1, e2})

	l.move(e4, e1)
	checkListPointers(t, l, []*ListNode[*testVal]{e5, e3, e1, e4, e2})

	l.Remove(e5)
	checkListPointers(t, l, []*ListNode[*testVal]{e3, e1, e4, e2})

	l.move(e1, e4) // swap in middle
	checkListPointers(t, l, []*ListNode[*testVal]{e3, e4, e1, e2})

	l.MoveToFront(e4)
	checkListPointers(t, l, []*ListNode[*testVal]{e4, e3, e1, e2})

	l.Remove(e2)
	checkListPointers(t, l, []*ListNode[*testVal]{e4, e3, e1})

	l.MoveToFront(e3) // move from middle
	checkListPointers(t, l, []*ListNode[*testVal]{e3, e4, e1})

	l.MoveToFront(e1) // move from end
	checkListPointers(t, l, []*ListNode[*testVal]{e1, e3, e4})

	l.MoveToFront(e1) // no movement
	checkListPointers(t, l, []*ListNode[*testVal]{e1, e3, e4})

	e2 = l.PushFront(&testVal{2})
	checkListPointers(t, l, []*ListNode[*testVal]{e2, e1, e3, e4})

	l.Remove(e3) // removing from middle
	checkListPointers(t, l, []*ListNode[*testVal]{e2, e1, e4})

	l.Remove(e4) // removing from end
	checkListPointers(t, l, []*ListNode[*testVal]{e2, e1})

	l.move(e2, e1) // swapping between two elements
	checkListPointers(t, l, []*ListNode[*testVal]{e1, e2})

	l.Remove(e1) // removing front
	checkListPointers(t, l, []*ListNode[*testVal]{e2})

	l.move(e2, l.Back()) // swapping element with itself.
	checkListPointers(t, l, []*ListNode[*testVal]{e2})

	l.Remove(e2) // remove last one
	checkListPointers(t, l, []*ListNode[*testVal]{})
}

func TestList_SingleElementListPositioning(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := NewList[*testVal]()
	checkListPointers(t, l, []*ListNode[*testVal]{})
	e := l.PushFront(&testVal{1})
	checkListPointers(t, l, []*ListNode[*testVal]{e})
	l.MoveToFront(e)
	checkListPointers(t, l, []*ListNode[*testVal]{e})
	l.Remove(e)
	checkListPointers(t, l, []*ListNode[*testVal]{})
}

func TestList_RemovedNodeShouldBeMovedToFreeList(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := NewList[*testVal]()
	e1 := l.PushFront(&testVal{1})
	e2 := l.PushFront(&testVal{2})

	checkListPointers(t, l, []*ListNode[*testVal]{e2, e1})

	e := l.Back()
	l.Remove(e)

	for i := l.freeList.next; i != nil; i = i.next {
		if i == e {
			// stopping the test with good results:
			return
		}
	}
	t.Error("expected the removed node to appear at the freelist")
}

func TestList_PushMoveBackRemove(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l := NewList[testVal]().AllocateFreeNodes(4)
	e1 := l.PushFront(testVal{1})
	e2 := l.PushFront(testVal{2})
	checkListPointers(t, l, []*ListNode[testVal]{e2, e1})

	l.MoveToFront(e1)
	checkListPointers(t, l, []*ListNode[testVal]{e1, e2})

	e := l.Back()
	require.Equal(t, e, e2)
	l.Remove(e)
	checkListPointers(t, l, []*ListNode[testVal]{e1})

	e = l.Back()
	require.Equal(t, e, e1)
	l.Remove(e)
	checkListPointers(t, l, []*ListNode[testVal]{})

	e = l.Back()
	require.Nil(t, e)
}
