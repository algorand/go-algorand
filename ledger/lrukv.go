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
	"github.com/algorand/go-algorand/logging"
)

//msgp:ignore cachedKVData
type cachedKVData struct {
	persistedKVData

	// kv key
	key string
}

// lruKV provides a storage class for the most recently used kv data.
// It doesn't have any synchronization primitive on it's own and require to be
// syncronized by the caller.
type lruKV struct {
	// kvList contain the list of persistedKVData, where the front ones are the most "fresh"
	// and the ones on the back are the oldest.
	kvList *persistedKVDataList

	// kvs provides fast access to the various elements in the list by using the key
	kvs map[string]*persistedKVDataListNode

	// pendingKVs are used as a way to avoid taking a write-lock. When the caller needs to "materialize" these,
	// it would call flushPendingWrites and these would be merged into the kvs/kvList
	pendingKVs chan cachedKVData

	// log interface; used for logging the threshold event.
	log logging.Logger

	// pendingWritesWarnThreshold is the threshold beyond we would write a warning for exceeding the number of pendingKVs entries
	pendingWritesWarnThreshold int
}

// init initializes the lruKV for use.
// thread locking semantics : write lock
func (m *lruKV) init(log logging.Logger, pendingWrites int, pendingWritesWarnThreshold int) {
	m.kvList = newPersistedKVList().allocateFreeNodes(pendingWrites)
	m.kvs = make(map[string]*persistedKVDataListNode, pendingWrites)
	m.pendingKVs = make(chan cachedKVData, pendingWrites)
	m.log = log
	m.pendingWritesWarnThreshold = pendingWritesWarnThreshold
}

// read the persistedKVData object that the lruKV has for the given key.
// thread locking semantics : read lock
func (m *lruKV) read(key string) (data persistedKVData, has bool) {
	if el := m.kvs[key]; el != nil {
		return el.Value.persistedKVData, true
	}
	return persistedKVData{}, false
}

// flushPendingWrites flushes the pending writes to the main lruKV cache.
// thread locking semantics : write lock
func (m *lruKV) flushPendingWrites() {
	pendingEntriesCount := len(m.pendingKVs)
	if pendingEntriesCount >= m.pendingWritesWarnThreshold {
		m.log.Warnf("lruKV: number of entries in pendingKVs(%d) exceed the warning threshold of %d", pendingEntriesCount, m.pendingWritesWarnThreshold)
	}
	for ; pendingEntriesCount > 0; pendingEntriesCount-- {
		select {
		case pendingKVData := <-m.pendingKVs:
			m.write(pendingKVData.persistedKVData, pendingKVData.key)
		default:
			return
		}
	}
}

// writePending write a single persistedKVData entry to the pendingKVs buffer.
// the function doesn't block, and in case of a buffer overflow the entry would not be added.
// thread locking semantics : no lock is required.
func (m *lruKV) writePending(kv persistedKVData, key string) {
	select {
	case m.pendingKVs <- cachedKVData{persistedKVData: kv, key: key}:
	default:
	}
}

// write a single persistedKVData to the lruKV cache.
// when writing the entry, the round number would be used to determine if it's a newer
// version of what's already on the cache or not. In all cases, the entry is going
// to be promoted to the front of the list.
// thread locking semantics : write lock
func (m *lruKV) write(kvData persistedKVData, key string) {
	if el := m.kvs[key]; el != nil {
		// already exists; is it a newer ?
		if el.Value.before(&kvData) {
			// we update with a newer version.
			el.Value = &cachedKVData{persistedKVData: kvData, key: key}
		}
		m.kvList.moveToFront(el)
	} else {
		// new entry.
		m.kvs[key] = m.kvList.pushFront(&cachedKVData{persistedKVData: kvData, key: key})
	}
}

// prune adjust the current size of the lruKV cache, by dropping the least
// recently used entries.
// thread locking semantics : write lock
func (m *lruKV) prune(newSize int) (removed int) {
	for {
		if len(m.kvs) <= newSize {
			break
		}
		back := m.kvList.back()
		delete(m.kvs, back.Value.key)
		m.kvList.remove(back)
		removed++
	}
	return
}
