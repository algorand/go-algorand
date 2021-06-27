package ledger

// persistedAccountDataList represents a doubly linked list.
// must initiate with newPersistedAccountList.
type persistedAccountDataList struct {
	root     persistedAccountDataListNode // sentinel list element, only &root, root.prev, and root.next are used
	freeList *persistedAccountDataList    // preallocated nodes location
}

type persistedAccountDataListNode struct {
	// Next and previous pointers in the doubly-linked list of elements.
	// To simplify the implementation, internally a list l is implemented
	// as a ring, such that &l.root is both the next element of the last
	// list element (l.Back()) and the previous element of the first list
	// element (l.Front()).
	next, prev *persistedAccountDataListNode

	Value *persistedAccountData
}

func newPersistedAccountList() *persistedAccountDataList {
	l := new(persistedAccountDataList).init()
	l.freeList = new(persistedAccountDataList).init()

	return l
}

func (l *persistedAccountDataList) init() *persistedAccountDataList {
	l.root.next = &l.root
	l.root.prev = &l.root
	return l
}

func (l *persistedAccountDataList) allocateFreeNodes(numAllocs int) *persistedAccountDataList {
	if l.freeList == nil {
		return l
	}
	for i := 0; i < numAllocs; i++ {
		l.freeList.pushFront(&persistedAccountData{})
	}

	return l
}

func isLenZero(list *persistedAccountDataList) bool {
	// assumes we are inserting correctly to the list - using pushFront.
	return list.root.next == &list.root
}

// Back returns the last element of list l or nil if the list is empty.
func (l *persistedAccountDataList) back() *persistedAccountDataListNode {
	if isLenZero(l) {
		return nil
	}
	return l.root.prev
}

// remove removes e from l if e is an element of list l.
// It returns the element value e.Value.
// The element must not be nil.
func (l *persistedAccountDataList) remove(e *persistedAccountDataListNode) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil // avoid memory leaks
	e.prev = nil // avoid memory leaks

	if l.freeList != nil {
		// add the node back to the freelist.
		l.freeList.insertValue(e, &l.freeList.root)
	}

}

// pushFront inserts a new element e with value v at the front of list l and returns e.
func (l *persistedAccountDataList) pushFront(v *persistedAccountData) *persistedAccountDataListNode {
	var newNode *persistedAccountDataListNode
	if l.freeList != nil && !isLenZero(l.freeList) {
		newNode = l.freeList.back()
		l.freeList.remove(newNode)
		newNode.Value = v
	} else {
		newNode = &persistedAccountDataListNode{Value: v}
	}
	return l.insertValue(newNode, &l.root)
}

// insertValue inserts e after at, increments l.len, and returns e.
func (l *persistedAccountDataList) insertValue(newNode *persistedAccountDataListNode, at *persistedAccountDataListNode) *persistedAccountDataListNode {
	n := at.next
	at.next = newNode
	newNode.prev = at
	newNode.next = n
	n.prev = newNode

	return newNode
}

// moveToFront moves element e to the front of list l.
// If e is not an element of l, the list is not modified.
// The element must not be nil.
func (l *persistedAccountDataList) moveToFront(e *persistedAccountDataListNode) {
	if l.root.next == e {
		return
	}
	l.move(e, &l.root)
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
