package network

import (
	"container/list"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-deadlock"
)

type msgTracker struct {
	store       map[crypto.Digest][]byte
	orderedMsgs *list.List
	mu          deadlock.RWMutex
	limit       int
}

func makeTracker(limit int) *msgTracker {
	tracker := msgTracker{}
	tracker.store = make(map[crypto.Digest][]byte)
	tracker.orderedMsgs = list.New()
	tracker.limit = limit
	return &tracker
}

// storeMsg stores an entry in the corresponding peer's key-value store
func (tracker *msgTracker) storeMsg(msg []byte) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	tracker.insert(crypto.Hash(msg), msg)
}

func (tracker *msgTracker) exists(key crypto.Digest) bool {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	return tracker.existsUnsafe(key)
}

// LoadMessage retrieves an entry from the corresponding peer's key-value store
func (tracker *msgTracker) LoadMessage(keys []crypto.Digest) ([][]byte, bool) {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	allFound := true
	found := true
	values := make([][]byte, len(keys), len(keys))
	for i, k := range keys {
		values[i], found = tracker.store[k]
		if !found {
			allFound = false
		}

	}
	return values, allFound
}

func (tracker *msgTracker) remember(msgHash crypto.Digest) {
	tracker.insert(msgHash, nil)
}

func (tracker *msgTracker) insert(key crypto.Digest, msg []byte) {
	if !tracker.existsUnsafe(key) {
		tracker.store[key] = msg
		tracker.orderedMsgs.PushBack(key)
		for tracker.orderedMsgs.Len() > tracker.limit {
			key := tracker.orderedMsgs.Front()
			delete(tracker.store, key.Value.(crypto.Digest))
			tracker.orderedMsgs.Remove(key)
		}
	}
}

func (tracker *msgTracker) existsUnsafe(key crypto.Digest) bool {
	_, exists := tracker.store[key]
	return exists
}
