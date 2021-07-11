// Copyright (C) 2019-2021 Algorand, Inc.
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
	"github.com/algorand/go-algorand/data/basics"
	"testing"
)

func checkLen(list *persistedAccountDataList) int {
	if isEmpty(list) {
		return 0
	}
	return countListSize(&list.root)
}

func countListSize(head *persistedAccountDataListNode) (counter int) {
	for i := head.next; i != head && i != nil; i = i.next {
		counter++
	}
	return counter
}

func TestRemoveFromList(t *testing.T) {
	l := newPersistedAccountList()
	e1 := l.pushFront(&persistedAccountData{addr: basics.Address{1}})
	e2 := l.pushFront(&persistedAccountData{addr: basics.Address{2}})
	e3 := l.pushFront(&persistedAccountData{addr: basics.Address{3}})
	checkListPointers(t, l, []*persistedAccountDataListNode{e3, e2, e1})

	l.remove(e2)
	checkListPointers(t, l, []*persistedAccountDataListNode{e3, e1})
	l.remove(e3)
	checkListPointers(t, l, []*persistedAccountDataListNode{e1})
}

func TestAddingNewNodeWithAllocatedFreeList(t *testing.T) {
	l := newPersistedAccountList().allocateFreeNodes(10)
	checkListPointers(t, l, []*persistedAccountDataListNode{})
	if countListSize(l.freeList) != 10 {
		t.Errorf("free list did not allocate nodes")
		return
	}
	// test elements
	e1 := l.pushFront(&persistedAccountData{addr: basics.Address{1}})
	checkListPointers(t, l, []*persistedAccountDataListNode{e1})

	if countListSize(l.freeList) != 9 {
		t.Errorf("free list did not provide a node on new list entry")
		return
	}
}

func checkListLen(t *testing.T, l *persistedAccountDataList, len int) bool {
	if n := checkLen(l); n != len {
		t.Errorf("l.Len() = %d, want %d", n, len)
		return true
	}
	return false
}

// inspect that the list seems like the array
func checkListPointers(t *testing.T, l *persistedAccountDataList, es []*persistedAccountDataListNode) {
	root := &l.root

	if failed := checkListLen(t, l, len(es)); failed {
		return
	}

	if failed := zeroListInspection(t, l, es, root); failed {
		return
	}

	// len(es) > 0
	pointerInspection(t, es, root)
}

func zeroListInspection(t *testing.T, l *persistedAccountDataList, es []*persistedAccountDataListNode, root *persistedAccountDataListNode) bool {
	// zero length lists must be the zero value or properly initialized (sentinel circle)
	if len(es) == 0 {
		if l.root.next != nil && l.root.next != root || l.root.prev != nil && l.root.prev != root {
			t.Errorf("l.root.next = %p, l.root.prev = %p; both should both be nil or %p", l.root.next, l.root.prev, root)
		}
		return true
	}
	return false
}

func pointerInspection(t *testing.T, es []*persistedAccountDataListNode, root *persistedAccountDataListNode) {
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

func TestMultielementListPositioning(t *testing.T) {
	l := newPersistedAccountList()
	checkListPointers(t, l, []*persistedAccountDataListNode{})
	// test elements
	e2 := l.pushFront(&persistedAccountData{addr: basics.Address{2}})
	e1 := l.pushFront(&persistedAccountData{addr: basics.Address{1}})
	e3 := l.pushFront(&persistedAccountData{addr: basics.Address{3}})
	e4 := l.pushFront(&persistedAccountData{addr: basics.Address{4}})
	e5 := l.pushFront(&persistedAccountData{addr: basics.Address{5}})

	checkListPointers(t, l, []*persistedAccountDataListNode{e5, e4, e3, e1, e2})

	l.move(e4, e1)
	checkListPointers(t, l, []*persistedAccountDataListNode{e5, e3, e1, e4, e2})

	l.remove(e5)
	checkListPointers(t, l, []*persistedAccountDataListNode{e3, e1, e4, e2})

	l.move(e1, e4) // swap in middle
	checkListPointers(t, l, []*persistedAccountDataListNode{e3, e4, e1, e2})

	l.moveToFront(e4)
	checkListPointers(t, l, []*persistedAccountDataListNode{e4, e3, e1, e2})

	l.remove(e2)
	checkListPointers(t, l, []*persistedAccountDataListNode{e4, e3, e1})

	l.moveToFront(e3) // move from middle
	checkListPointers(t, l, []*persistedAccountDataListNode{e3, e4, e1})

	l.moveToFront(e1) // move from end
	checkListPointers(t, l, []*persistedAccountDataListNode{e1, e3, e4})

	l.moveToFront(e1) // no movement
	checkListPointers(t, l, []*persistedAccountDataListNode{e1, e3, e4})

	e2 = l.pushFront(&persistedAccountData{addr: basics.Address{2}})
	checkListPointers(t, l, []*persistedAccountDataListNode{e2, e1, e3, e4})

	l.remove(e3) // removing from middle
	checkListPointers(t, l, []*persistedAccountDataListNode{e2, e1, e4})

	l.remove(e4) // removing from end
	checkListPointers(t, l, []*persistedAccountDataListNode{e2, e1})

	l.move(e2, e1) // swapping between two elements
	checkListPointers(t, l, []*persistedAccountDataListNode{e1, e2})

	l.remove(e1) // removing front
	checkListPointers(t, l, []*persistedAccountDataListNode{e2})

	l.move(e2, l.back()) // swapping element with itself.
	checkListPointers(t, l, []*persistedAccountDataListNode{e2})

	l.remove(e2) // remove last one
	checkListPointers(t, l, []*persistedAccountDataListNode{})
}

func TestSingleElementListPositioning(t *testing.T) {
	l := newPersistedAccountList()
	checkListPointers(t, l, []*persistedAccountDataListNode{})
	e := l.pushFront(&persistedAccountData{addr: basics.Address{1}})
	checkListPointers(t, l, []*persistedAccountDataListNode{e})
	l.moveToFront(e)
	checkListPointers(t, l, []*persistedAccountDataListNode{e})
	l.remove(e)
	checkListPointers(t, l, []*persistedAccountDataListNode{})
}

func TestRemovedNodeShouldBeMovedToFreeList(t *testing.T) {
	l := newPersistedAccountList()
	e1 := l.pushFront(&persistedAccountData{addr: basics.Address{1}})
	e2 := l.pushFront(&persistedAccountData{addr: basics.Address{2}})

	checkListPointers(t, l, []*persistedAccountDataListNode{e2, e1})

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
