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

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func (l *persistedKVDataList) getRoot() dataListNode {
	return &l.root
}

func (l *persistedKVDataListNode) getNext() dataListNode {
	// get rid of returning nil wrapped into an interface to let i = x.getNext(); i != nil work.
	if l.next == nil {
		return nil
	}
	return l.next
}

func (l *persistedKVDataListNode) getPrev() dataListNode {
	if l.prev == nil {
		return nil
	}
	return l.prev
}

// inspect that the list seems like the array
func checkListPointersBD(t *testing.T, l *persistedKVDataList, es []*persistedKVDataListNode) {
	es2 := make([]dataListNode, len(es))
	for i, el := range es {
		es2[i] = el
	}

	checkListPointers(t, l, es2)
}

func TestRemoveFromListBD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedKVList()
	e1 := l.pushFront(&cachedKVData{key: "key1"})
	e2 := l.pushFront(&cachedKVData{key: "key2"})
	e3 := l.pushFront(&cachedKVData{key: "key3"})
	checkListPointersBD(t, l, []*persistedKVDataListNode{e3, e2, e1})

	l.remove(e2)
	checkListPointersBD(t, l, []*persistedKVDataListNode{e3, e1})
	l.remove(e3)
	checkListPointersBD(t, l, []*persistedKVDataListNode{e1})
}

func TestAddingNewNodeWithAllocatedFreeListBD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedKVList().allocateFreeNodes(10)
	checkListPointersBD(t, l, []*persistedKVDataListNode{})
	if countListSize(l.freeList) != 10 {
		t.Errorf("free list did not allocate nodes")
		return
	}
	// test elements
	e1 := l.pushFront(&cachedKVData{key: "key1"})
	checkListPointersBD(t, l, []*persistedKVDataListNode{e1})

	if countListSize(l.freeList) != 9 {
		t.Errorf("free list did not provide a node on new list entry")
		return
	}
}

func TestMultielementListPositioningBD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedKVList()
	checkListPointersBD(t, l, []*persistedKVDataListNode{})
	// test elements
	e2 := l.pushFront(&cachedKVData{key: "key1"})
	e1 := l.pushFront(&cachedKVData{key: "key2"})
	e3 := l.pushFront(&cachedKVData{key: "key3"})
	e4 := l.pushFront(&cachedKVData{key: "key4"})
	e5 := l.pushFront(&cachedKVData{key: "key5"})

	checkListPointersBD(t, l, []*persistedKVDataListNode{e5, e4, e3, e1, e2})

	l.move(e4, e1)
	checkListPointersBD(t, l, []*persistedKVDataListNode{e5, e3, e1, e4, e2})

	l.remove(e5)
	checkListPointersBD(t, l, []*persistedKVDataListNode{e3, e1, e4, e2})

	l.move(e1, e4) // swap in middle
	checkListPointersBD(t, l, []*persistedKVDataListNode{e3, e4, e1, e2})

	l.moveToFront(e4)
	checkListPointersBD(t, l, []*persistedKVDataListNode{e4, e3, e1, e2})

	l.remove(e2)
	checkListPointersBD(t, l, []*persistedKVDataListNode{e4, e3, e1})

	l.moveToFront(e3) // move from middle
	checkListPointersBD(t, l, []*persistedKVDataListNode{e3, e4, e1})

	l.moveToFront(e1) // move from end
	checkListPointersBD(t, l, []*persistedKVDataListNode{e1, e3, e4})

	l.moveToFront(e1) // no movement
	checkListPointersBD(t, l, []*persistedKVDataListNode{e1, e3, e4})

	e2 = l.pushFront(&cachedKVData{key: "key2"})
	checkListPointersBD(t, l, []*persistedKVDataListNode{e2, e1, e3, e4})

	l.remove(e3) // removing from middle
	checkListPointersBD(t, l, []*persistedKVDataListNode{e2, e1, e4})

	l.remove(e4) // removing from end
	checkListPointersBD(t, l, []*persistedKVDataListNode{e2, e1})

	l.move(e2, e1) // swapping between two elements
	checkListPointersBD(t, l, []*persistedKVDataListNode{e1, e2})

	l.remove(e1) // removing front
	checkListPointersBD(t, l, []*persistedKVDataListNode{e2})

	l.move(e2, l.back()) // swapping element with itself.
	checkListPointersBD(t, l, []*persistedKVDataListNode{e2})

	l.remove(e2) // remove last one
	checkListPointersBD(t, l, []*persistedKVDataListNode{})
}

func TestSingleElementListPositioningBD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedKVList()
	checkListPointersBD(t, l, []*persistedKVDataListNode{})
	e := l.pushFront(&cachedKVData{key: "key1"})
	checkListPointersBD(t, l, []*persistedKVDataListNode{e})
	l.moveToFront(e)
	checkListPointersBD(t, l, []*persistedKVDataListNode{e})
	l.remove(e)
	checkListPointersBD(t, l, []*persistedKVDataListNode{})
}

func TestRemovedNodeShouldBeMovedToFreeListBD(t *testing.T) {
	partitiontest.PartitionTest(t)
	l := newPersistedKVList()
	e1 := l.pushFront(&cachedKVData{key: "key1"})
	e2 := l.pushFront(&cachedKVData{key: "key2"})

	checkListPointersBD(t, l, []*persistedKVDataListNode{e2, e1})

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
