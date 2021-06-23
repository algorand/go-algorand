package ledger

import (
	"github.com/algorand/go-algorand/data/basics"
	"testing"
)

func TestPersistedAccountDataList(t *testing.T) {

	t.Run("single element list movements", testSingleElementListPositioning)

	t.Run("multi-element list movements", testMultielementListPositioning)

	t.Run("test remove", testRemove)
}

func testRemove(t *testing.T) {
	t.Run("attempt to remove from wrong list", attemptToRemoveFromWrongList)

	t.Run("attempt to remove from wrong list and then add to that list", attemptToRemoveFromWrongListAndAddToOtherList)

	t.Run("removed object should have value and nil pointers", testRemovedNodeContainsValueButNoLinks)
}

func checkListLen(t *testing.T, l *persistedAccountDataList, len int) bool {
	if n := l.Len(); n != len {
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
	l := newPersistentAccountList()
	checkListPointers(t, l, []*persistedAccountDataListNode{})
	// test elements
	e2 := l.PushFront(&persistedAccountData{addr: basics.Address{2}})
	e1 := l.PushFront(&persistedAccountData{addr: basics.Address{1}})
	e3 := l.PushFront(&persistedAccountData{addr: basics.Address{3}})
	e4 := l.PushFront(&persistedAccountData{addr: basics.Address{4}})

	checkListPointers(t, l, []*persistedAccountDataListNode{e4, e3, e1, e2})

	l.Remove(e2)
	checkListPointers(t, l, []*persistedAccountDataListNode{e4, e3, e1})

	l.MoveToFront(e3) // move from middle
	checkListPointers(t, l, []*persistedAccountDataListNode{e3, e4, e1})

	l.MoveToFront(e1) // move from end
	checkListPointers(t, l, []*persistedAccountDataListNode{e1, e3, e4})

	l.MoveToFront(e1) // no movement
	checkListPointers(t, l, []*persistedAccountDataListNode{e1, e3, e4})

	e2 = l.PushFront(&persistedAccountData{addr: basics.Address{2}})
	checkListPointers(t, l, []*persistedAccountDataListNode{e2, e1, e3, e4})

	l.Remove(e3) // removing from middle
	checkListPointers(t, l, []*persistedAccountDataListNode{e2, e1, e4})

	l.Remove(e4) // removing from end
	checkListPointers(t, l, []*persistedAccountDataListNode{e2, e1})

	l.Remove(e2) // removing front
	checkListPointers(t, l, []*persistedAccountDataListNode{e1})

	l.Remove(e1) // remove last one
	checkListPointers(t, l, []*persistedAccountDataListNode{})

}

func testSingleElementListPositioning(t *testing.T) {
	l := newPersistentAccountList()
	checkListPointers(t, l, []*persistedAccountDataListNode{})
	e := l.PushFront(&persistedAccountData{addr: basics.Address{1}})
	checkListPointers(t, l, []*persistedAccountDataListNode{e})
	l.MoveToFront(e)
	checkListPointers(t, l, []*persistedAccountDataListNode{e})
	l.Remove(e)
	checkListPointers(t, l, []*persistedAccountDataListNode{})
}

func attemptToRemoveFromWrongList(t *testing.T) {
	l1, l2 := createTwoLists()

	e := l1.Back()
	l2.Remove(e) // l2 should not change because e is not an element of l2
	if n := l2.Len(); n != 2 {
		t.Errorf("l2.Len() = %d, want 2", n)
	}
}

func attemptToRemoveFromWrongListAndAddToOtherList(t *testing.T) {
	l1, l2 := createTwoLists()

	e := l1.Back()
	l2.Remove(e) // l2 should not change because e is not an element of l2
	if n := l2.Len(); n != 2 {
		t.Errorf("l2.Len() = %d, want 2", n)
	}

	l1.PushFront(l2.Back().Value)
	if n := l1.Len(); n != 3 {
		t.Errorf("l1.Len() = %d, want 3", n)
	}
}

func testRemovedNodeContainsValueButNoLinks(t *testing.T) {
	l := newPersistentAccountList()
	e1 := l.PushFront(&persistedAccountData{addr: basics.Address{1}})
	e2 := l.PushFront(&persistedAccountData{addr: basics.Address{2}})

	checkListPointers(t, l, []*persistedAccountDataListNode{e2, e1})

	e := l.Back()
	l.Remove(e)
	if e.Value.addr == e2.Value.addr {
		t.Errorf("\nhave %v\nwant %v", e.Value.addr, e1.Value.addr)
	}
	if e.next != nil {
		t.Errorf("e.next != nil")
	}
	if e.prev != nil {
		t.Errorf("e.prev != nil")
	}

	if e.list != nil {
		t.Errorf("e.list != nil")
	}
}
func createTwoLists() (*persistedAccountDataList, *persistedAccountDataList) {
	l1 := newPersistentAccountList()
	l1.PushFront(&persistedAccountData{addr: basics.Address{1}})
	l1.PushFront(&persistedAccountData{addr: basics.Address{2}})

	l2 := newPersistentAccountList()
	l2.PushFront(&persistedAccountData{addr: basics.Address{3}})
	l2.PushFront(&persistedAccountData{addr: basics.Address{4}})
	return l1, l2
}
