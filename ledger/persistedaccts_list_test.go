package ledger

import (
	"github.com/algorand/go-algorand/data/basics"
	"testing"
)

func TestPersistedAccountDataList(t *testing.T) {
	t.Run("single element list movements", testSingleElementListPositioning)

	t.Run("multi-element list movements", testMultielementListPositioning)

	t.Run("test remove", testRemove)

	t.Run("test freelist usage", testFreeListMovement)
}

func testRemove(t *testing.T) {
	t.Run("remove from list", removeFromListTest)
}

func removeFromListTest(t *testing.T) {
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

func testFreeListMovement(t *testing.T) {
	t.Run("removed node should be moved to freelist", removedNodeShouldBeMovedToFreeList)

	t.Run("new node should come from free list", testAddingNewNodeWithAllocatedFreeList)
}

func testAddingNewNodeWithAllocatedFreeList(t *testing.T) {
	l := newPersistedAccountList().allocateFreeNodes(10)
	checkListPointers(t, l, []*persistedAccountDataListNode{})
	if l.freeList.len != 10 {
		t.Errorf("free list did not allocate nodes")
		return
	}
	// test elements
	e1 := l.pushFront(&persistedAccountData{addr: basics.Address{1}})
	checkListPointers(t, l, []*persistedAccountDataListNode{e1})

	if l.freeList.len != 9 {
		t.Errorf("free list did not provide a node on new list entry")
		return
	}
}

func checkListLen(t *testing.T, l *persistedAccountDataList, len int) bool {
	if n := l.len; n != len {
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

func testMultielementListPositioning(t *testing.T) {
	l := newPersistedAccountList()
	checkListPointers(t, l, []*persistedAccountDataListNode{})
	// test elements
	e2 := l.pushFront(&persistedAccountData{addr: basics.Address{2}})
	e1 := l.pushFront(&persistedAccountData{addr: basics.Address{1}})
	e3 := l.pushFront(&persistedAccountData{addr: basics.Address{3}})
	e4 := l.pushFront(&persistedAccountData{addr: basics.Address{4}})

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

	l.remove(e2) // removing front
	checkListPointers(t, l, []*persistedAccountDataListNode{e1})

	l.remove(e1) // remove last one
	checkListPointers(t, l, []*persistedAccountDataListNode{})

}

func testSingleElementListPositioning(t *testing.T) {
	l := newPersistedAccountList()
	checkListPointers(t, l, []*persistedAccountDataListNode{})
	e := l.pushFront(&persistedAccountData{addr: basics.Address{1}})
	checkListPointers(t, l, []*persistedAccountDataListNode{e})
	l.moveToFront(e)
	checkListPointers(t, l, []*persistedAccountDataListNode{e})
	l.remove(e)
	checkListPointers(t, l, []*persistedAccountDataListNode{})
}

func removedNodeShouldBeMovedToFreeList(t *testing.T) {
	t.Skip()
	l := newPersistedAccountList()
	e1 := l.pushFront(&persistedAccountData{addr: basics.Address{1}})
	e2 := l.pushFront(&persistedAccountData{addr: basics.Address{2}})

	checkListPointers(t, l, []*persistedAccountDataListNode{e2, e1})

	e := l.back()
	l.remove(e)

}

func createTwoLists() (*persistedAccountDataList, *persistedAccountDataList) {
	l1 := newPersistedAccountList()
	l1.pushFront(&persistedAccountData{addr: basics.Address{1}})
	l1.pushFront(&persistedAccountData{addr: basics.Address{2}})

	l2 := newPersistedAccountList()
	l2.pushFront(&persistedAccountData{addr: basics.Address{3}})
	l2.pushFront(&persistedAccountData{addr: basics.Address{4}})
	return l1, l2
}
