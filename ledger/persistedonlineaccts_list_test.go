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

func (l *persistedOnlineAccountDataList) getRoot() dataListNode {
	return &l.root
}

func (l *persistedOnlineAccountDataListNode) getNext() dataListNode {
	// get rid of returning nil wrapped into an interface to let i = x.getNext(); i != nil work.
	if l.next == nil {
		return nil
	}
	return l.next
}

func (l *persistedOnlineAccountDataListNode) getPrev() dataListNode {
	if l.prev == nil {
		return nil
	}
	return l.prev
}

func TestRemoveFromListOAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedOnlineAccountList()
	e1 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{1}})
	e2 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{2}})
	e3 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{3}})
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e3, e2, e1})

	l.remove(e2)
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e3, e1})
	l.remove(e3)
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e1})
}

func TestAddingNewNodeWithAllocatedFreeListOAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedOnlineAccountList().allocateFreeNodes(10)
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{})
	if countListSize(l.freeList) != 10 {
		t.Errorf("free list did not allocate nodes")
		return
	}
	// test elements
	e1 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{1}})
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e1})

	if countListSize(l.freeList) != 9 {
		t.Errorf("free list did not provide a node on new list entry")
		return
	}
}

// inspect that the list seems like the array
func checkListPointersOAD(t *testing.T, l *persistedOnlineAccountDataList, es []*persistedOnlineAccountDataListNode) {
	es2 := make([]dataListNode, len(es))
	for i, el := range es {
		es2[i] = el
	}

	checkListPointers(t, l, es2)
}

func TestMultielementListPositioningOAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedOnlineAccountList()
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{})
	// test elements
	e2 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{2}})
	e1 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{1}})
	e3 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{3}})
	e4 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{4}})
	e5 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{5}})

	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e5, e4, e3, e1, e2})

	l.move(e4, e1)
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e5, e3, e1, e4, e2})

	l.remove(e5)
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e3, e1, e4, e2})

	l.move(e1, e4) // swap in middle
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e3, e4, e1, e2})

	l.moveToFront(e4)
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e4, e3, e1, e2})

	l.remove(e2)
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e4, e3, e1})

	l.moveToFront(e3) // move from middle
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e3, e4, e1})

	l.moveToFront(e1) // move from end
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e1, e3, e4})

	l.moveToFront(e1) // no movement
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e1, e3, e4})

	e2 = l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{2}})
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e2, e1, e3, e4})

	l.remove(e3) // removing from middle
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e2, e1, e4})

	l.remove(e4) // removing from end
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e2, e1})

	l.move(e2, e1) // swapping between two elements
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e1, e2})

	l.remove(e1) // removing front
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e2})

	l.move(e2, l.back()) // swapping element with itself.
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e2})

	l.remove(e2) // remove last one
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{})
}

func TestSingleElementListPositioningOD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedOnlineAccountList()
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{})
	e := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{1}})
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e})
	l.moveToFront(e)
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e})
	l.remove(e)
	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{})
}

func TestRemovedNodeShouldBeMovedToFreeListOAD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedOnlineAccountList()
	e1 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{1}})
	e2 := l.pushFront(&store.PersistedOnlineAccountData{Addr: basics.Address{2}})

	checkListPointersOAD(t, l, []*persistedOnlineAccountDataListNode{e2, e1})

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
