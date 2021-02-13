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

func (tracker *msgTracker) remember(msgHash crypto.Digest) {
	tracker.insert(msgHash, nil)
}

// storeMsg stores an entry in the corresponding peer's key-value store
func (tracker *msgTracker) storeMsg(msg []byte) {
	tracker.insert(crypto.Hash(msg), msg)
}

func (tracker *msgTracker) insert(key crypto.Digest, msg []byte) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
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

func (tracker *msgTracker) exists(key crypto.Digest) bool {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	return tracker.existsUnsafe(key)
}


// LoadKV retrieves an entry from the corresponding peer's key-value store
func (tracker *msgTracker) LoadKV(keys []crypto.Digest) [][]byte {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	values := make([][]byte, len(keys), len(keys))
	for i, k := range keys {
		values[i] = tracker.store[k]
	}
	return values
}

