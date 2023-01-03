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

package ledger

import (
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type dataListNode interface {
	getNext() dataListNode
	getPrev() dataListNode
}

type dataList interface {
	getRoot() dataListNode
}

func (l *persistedAccountDataList) getRoot() dataListNode {
	return &l.root
}

func (l *persistedAccountDataListNode) getNext() dataListNode {
	// get rid of returning nil wrapped into an interface to let i = x.getNext(); i != nil work.
	if l.next == nil {
		return nil
	}
	return l.next
}

func (l *persistedAccountDataListNode) getPrev() dataListNode {
	if l.prev == nil {
		return nil
	}
	return l.prev
}

func checkLen(list dataList) int {
	if list.getRoot().getNext() == list.getRoot() {
		return 0
	}

	return countListSize(list.getRoot())
}

func countListSize(head dataListNode) (counter int) {
	for i := head.getNext(); i != head && i != nil; i = i.getNext() {
		counter++
	}
	return counter
}

func checkListLen(t *testing.T, l dataList, len int) bool {
	if n := checkLen(l); n != len {
		t.Errorf("l.Len() = %d, want %d", n, len)
		return true
	}
	return false
}

func TestRemoveFromListAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedAccountList()
	e1 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{1}})
	e2 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{2}})
	e3 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{3}})
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e3, e2, e1})

	l.remove(e2)
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e3, e1})
	l.remove(e3)
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e1})
}

func TestAddingNewNodeWithAllocatedFreeListAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedAccountList().allocateFreeNodes(10)
	checkListPointersAD(t, l, []*persistedAccountDataListNode{})
	if countListSize(l.freeList) != 10 {
		t.Errorf("free list did not allocate nodes")
		return
	}
	// test elements
	e1 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{1}})
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e1})

	if countListSize(l.freeList) != 9 {
		t.Errorf("free list did not provide a node on new list entry")
		return
	}
}

func checkListPointers(t *testing.T, l dataList, es []dataListNode) {
	root := l.getRoot()

	if failed := checkListLen(t, l, len(es)); failed {
		return
	}

	if failed := zeroListInspection(t, l, len(es), root); failed {
		return
	}

	pointerInspection(t, es, root)
}

// inspect that the list seems like the array
func checkListPointersAD(t *testing.T, l *persistedAccountDataList, es []*persistedAccountDataListNode) {
	es2 := make([]dataListNode, len(es))
	for i, el := range es {
		es2[i] = el
	}

	checkListPointers(t, l, es2)
}

func zeroListInspection(t *testing.T, l dataList, len int, root dataListNode) bool {
	// zero length lists must be the zero value or properly initialized (sentinel circle)
	if len == 0 {
		if l.getRoot().getNext() != nil && l.getRoot().getNext() != root || l.getRoot().getPrev() != nil && l.getRoot().getPrev() != root {
			t.Errorf("l.root.next = %p, l.root.prev = %p; both should both be nil or %p", l.getRoot().getNext(), l.getRoot().getPrev(), root)
		}
		return true
	}
	return false
}

func pointerInspection(t *testing.T, es []dataListNode, root dataListNode) {
	// check internal and external prev/next connections
	for i, e := range es {
		prev := root
		if i > 0 {
			prev = es[i-1]
		}
		if p := e.getPrev(); p != prev {
			t.Errorf("elt[%d](%p).prev = %p, want %p", i, e, p, prev)
		}

		next := root
		if i < len(es)-1 {
			next = es[i+1]
		}
		if n := e.getNext(); n != next {
			t.Errorf("elt[%d](%p).next = %p, want %p", i, e, n, next)
		}
	}
}

func TestMultielementListPositioningAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedAccountList()
	checkListPointersAD(t, l, []*persistedAccountDataListNode{})
	// test elements
	e2 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{2}})
	e1 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{1}})
	e3 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{3}})
	e4 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{4}})
	e5 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{5}})

	checkListPointersAD(t, l, []*persistedAccountDataListNode{e5, e4, e3, e1, e2})

	l.move(e4, e1)
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e5, e3, e1, e4, e2})

	l.remove(e5)
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e3, e1, e4, e2})

	l.move(e1, e4) // swap in middle
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e3, e4, e1, e2})

	l.moveToFront(e4)
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e4, e3, e1, e2})

	l.remove(e2)
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e4, e3, e1})

	l.moveToFront(e3) // move from middle
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e3, e4, e1})

	l.moveToFront(e1) // move from end
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e1, e3, e4})

	l.moveToFront(e1) // no movement
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e1, e3, e4})

	e2 = l.pushFront(&store.PersistedAccountData{Addr: basics.Address{2}})
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e2, e1, e3, e4})

	l.remove(e3) // removing from middle
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e2, e1, e4})

	l.remove(e4) // removing from end
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e2, e1})

	l.move(e2, e1) // swapping between two elements
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e1, e2})

	l.remove(e1) // removing front
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e2})

	l.move(e2, l.back()) // swapping element with itself.
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e2})

	l.remove(e2) // remove last one
	checkListPointersAD(t, l, []*persistedAccountDataListNode{})
}

func TestSingleElementListPositioningAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedAccountList()
	checkListPointersAD(t, l, []*persistedAccountDataListNode{})
	e := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{1}})
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e})
	l.moveToFront(e)
	checkListPointersAD(t, l, []*persistedAccountDataListNode{e})
	l.remove(e)
	checkListPointersAD(t, l, []*persistedAccountDataListNode{})
}

func TestRemovedNodeShouldBeMovedToFreeListAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedAccountList()
	e1 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{1}})
	e2 := l.pushFront(&store.PersistedAccountData{Addr: basics.Address{2}})

	checkListPointersAD(t, l, []*persistedAccountDataListNode{e2, e1})

	e := l.back()
	l.remove(e)

	for i := l.freeList.next; i != nil; i = i.next {
		if i == e {
			// stopping the tst with good results:
			return
		}
	}
	t.Error("expected the removed node to appear at the freelist")
}
