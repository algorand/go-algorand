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
	"github.com/algorand/go-algorand/test/partitiontest"
)

func (l *persistedResourcesDataList) getRoot() dataListNode {
	return &l.root
}

func (l *persistedResourcesDataListNode) getNext() dataListNode {
	// get rid of returning nil wrapped into an interface to let i = x.getNext(); i != nil work.
	if l.next == nil {
		return nil
	}
	return l.next
}

func (l *persistedResourcesDataListNode) getPrev() dataListNode {
	if l.prev == nil {
		return nil
	}
	return l.prev
}

// inspect that the list seems like the array
func checkListPointersRD(t *testing.T, l *persistedResourcesDataList, es []*persistedResourcesDataListNode) {
	es2 := make([]dataListNode, len(es))
	for i, el := range es {
		es2[i] = el
	}

	checkListPointers(t, l, es2)
}

func TestRemoveFromListRD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedResourcesList()
	e1 := l.pushFront(&cachedResourceData{address: basics.Address{1}})
	e2 := l.pushFront(&cachedResourceData{address: basics.Address{2}})
	e3 := l.pushFront(&cachedResourceData{address: basics.Address{3}})
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e3, e2, e1})

	l.remove(e2)
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e3, e1})
	l.remove(e3)
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e1})
}

func TestAddingNewNodeWithAllocatedFreeListRD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedResourcesList().allocateFreeNodes(10)
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{})
	if countListSize(l.freeList) != 10 {
		t.Errorf("free list did not allocate nodes")
		return
	}
	// test elements
	e1 := l.pushFront(&cachedResourceData{address: basics.Address{1}})
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e1})

	if countListSize(l.freeList) != 9 {
		t.Errorf("free list did not provide a node on new list entry")
		return
	}
}

func TestMultielementListPositioningRD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedResourcesList()
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{})
	// test elements
	e2 := l.pushFront(&cachedResourceData{address: basics.Address{2}})
	e1 := l.pushFront(&cachedResourceData{address: basics.Address{1}})
	e3 := l.pushFront(&cachedResourceData{address: basics.Address{3}})
	e4 := l.pushFront(&cachedResourceData{address: basics.Address{4}})
	e5 := l.pushFront(&cachedResourceData{address: basics.Address{5}})

	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e5, e4, e3, e1, e2})

	l.move(e4, e1)
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e5, e3, e1, e4, e2})

	l.remove(e5)
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e3, e1, e4, e2})

	l.move(e1, e4) // swap in middle
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e3, e4, e1, e2})

	l.moveToFront(e4)
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e4, e3, e1, e2})

	l.remove(e2)
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e4, e3, e1})

	l.moveToFront(e3) // move from middle
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e3, e4, e1})

	l.moveToFront(e1) // move from end
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e1, e3, e4})

	l.moveToFront(e1) // no movement
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e1, e3, e4})

	e2 = l.pushFront(&cachedResourceData{address: basics.Address{2}})
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e2, e1, e3, e4})

	l.remove(e3) // removing from middle
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e2, e1, e4})

	l.remove(e4) // removing from end
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e2, e1})

	l.move(e2, e1) // swapping between two elements
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e1, e2})

	l.remove(e1) // removing front
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e2})

	l.move(e2, l.back()) // swapping element with itself.
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e2})

	l.remove(e2) // remove last one
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{})
}

func TestSingleElementListPositioningRD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedResourcesList()
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{})
	e := l.pushFront(&cachedResourceData{address: basics.Address{1}})
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e})
	l.moveToFront(e)
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e})
	l.remove(e)
	checkListPointersRD(t, l, []*persistedResourcesDataListNode{})
}

func TestRemovedNodeShouldBeMovedToFreeListRD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedResourcesList()
	e1 := l.pushFront(&cachedResourceData{address: basics.Address{1}})
	e2 := l.pushFront(&cachedResourceData{address: basics.Address{2}})

	checkListPointersRD(t, l, []*persistedResourcesDataListNode{e2, e1})

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
