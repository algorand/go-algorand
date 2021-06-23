package ledger

type persistedAccountDataListNode struct {
	// Next and previous pointers in the doubly-linked list of elements.
	// To simplify the implementation, internally a list l is implemented
	// as a ring, such that &l.root is both the next element of the last
	// list element (l.Back()) and the previous element of the first list
	// element (l.Front()).
	next, prev *persistedAccountDataListNode

	// The list to which this element belongs. (helps removing items fast)
	list *persistedAccountDataList

	Value *persistedAccountData
}

// List represents a doubly linked list.
// The zero value for List is an empty list ready to use.
type persistedAccountDataList struct {
	root persistedAccountDataListNode // sentinel list element, only &root, root.prev, and root.next are used
	len  int                          // current list length excluding (this) sentinel element
}

func newPersistentAccountList() *persistedAccountDataList {
	l := new(persistedAccountDataList)
	l.root.next = &l.root
	l.root.prev = &l.root
	l.len = 0
	return l
}

// Len returns the number of elements of list l.
// The complexity is O(1).
func (l *persistedAccountDataList) Len() int { return l.len }

// Back returns the last element of list l or nil if the list is empty.
func (l *persistedAccountDataList) Back() *persistedAccountDataListNode {
	if l.len == 0 {
		return nil
	}
	return l.root.prev
}

// insert inserts e after at, increments l.len, and returns e.
func (l *persistedAccountDataList) insert(e, at *persistedAccountDataListNode) *persistedAccountDataListNode {
	n := at.next
	at.next = e
	e.prev = at
	e.next = n
	n.prev = e
	e.list = l
	l.len++
	return e
}

//the item isn't shared, there's only one. why not hold a map with preallocated items?
// on prune sets the preallocated items to a specific number.
// insertValue is a convenience wrapper for insert(&Element{Value: v}, at).
func (l *persistedAccountDataList) insertValue(v *persistedAccountData, at *persistedAccountDataListNode) *persistedAccountDataListNode {
	// attempt to use pool of preallocated Element objects before creating a new one
	return l.insert(&persistedAccountDataListNode{Value: v}, at)
}

// remove removes e from its list, decrements l.len, and returns e.
func (l *persistedAccountDataList) remove(e *persistedAccountDataListNode) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil // avoid memory leaks
	e.prev = nil // avoid memory leaks
	e.list = nil
	l.len--
}

// move moves e to next to at and returns e.
func (l *persistedAccountDataList) move(e, at *persistedAccountDataListNode) *persistedAccountDataListNode {
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

// Remove removes e from l if e is an element of list l.
// It returns the element value e.Value.
// The element must not be nil.
func (l *persistedAccountDataList) Remove(e *persistedAccountDataListNode) {
	if e.list == l {
		l.remove(e)
	}
}

// PushFront inserts a new element e with value v at the front of list l and returns e.
func (l *persistedAccountDataList) PushFront(v *persistedAccountData) *persistedAccountDataListNode {
	return l.insertValue(v, &l.root)
}

// MoveToFront moves element e to the front of list l.
// If e is not an element of l, the list is not modified.
// The element must not be nil.
func (l *persistedAccountDataList) MoveToFront(e *persistedAccountDataListNode) {
	if e.list != l || l.root.next == e {
		return
	}
	l.move(e, &l.root)
}
