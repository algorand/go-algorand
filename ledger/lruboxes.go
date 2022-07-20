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

//msgp:ignore cachedResourceData
type cachedBoxData struct {
	persistedBoxData

	// box name
	key string
}

// lruBoxes provides a storage class for the most recently used box data.
// It doesn't have any synchronization primitive on it's own and require to be
// syncronized by the caller.
type lruBoxes struct {
	// boxList contain the list of persistedBoxData, where the front ones are the most "fresh"
	// and the ones on the back are the oldest.
	boxList *persistedBoxesDataList

	// boxes provides fast access to the various elements in the list by using the key
	boxes map[string]*persistedBoxesDataListNode

	// pendingBoxes are used as a way to avoid taking a write-lock. When the caller needs to "materialize" these,
	// it would call flushPendingWrites and these would be merged into the boxes/boxesList
	pendingBoxes chan cachedBoxData

	// log interface; used for logging the threshold event.
	log logging.Logger

	// pendingWritesWarnThreshold is the threshold beyond we would write a warning for exceeding the number of pendingBoxes entries
	pendingWritesWarnThreshold int
}

// init initializes the lruBoxes for use.
// thread locking semantics : write lock
func (m *lruBoxes) init(log logging.Logger, pendingWrites int, pendingWritesWarnThreshold int) {
	m.boxList = newPersistedBoxList().allocateFreeNodes(pendingWrites)
	m.boxes = make(map[string]*persistedBoxesDataListNode, pendingWrites)
	m.pendingBoxes = make(chan cachedBoxData, pendingWrites)
	m.log = log
	m.pendingWritesWarnThreshold = pendingWritesWarnThreshold
}

// read the persistedBoxesData object that the lruBoxes has for the given key.
// thread locking semantics : read lock
func (m *lruBoxes) read(key string) (data persistedBoxData, has bool) {
	if el := m.boxes[key]; el != nil {
		return el.Value.persistedBoxData, true
	}
	return persistedBoxData{}, false
}

// flushPendingWrites flushes the pending writes to the main lruBoxes cache.
// thread locking semantics : write lock
func (m *lruBoxes) flushPendingWrites() {
	pendingEntriesCount := len(m.pendingBoxes)
	if pendingEntriesCount >= m.pendingWritesWarnThreshold {
		m.log.Warnf("lruBoxes: number of entries in pendingBoxes(%d) exceed the warning threshold of %d", pendingEntriesCount, m.pendingWritesWarnThreshold)
	}
	for ; pendingEntriesCount > 0; pendingEntriesCount-- {
		select {
		case pendingBoxData := <-m.pendingBoxes:
			m.write(pendingBoxData.persistedBoxData, pendingBoxData.key)
		default:
			return
		}
	}
}

// writePending write a single persistedBoxData entry to the pendingBoxes buffer.
// the function doesn't block, and in case of a buffer overflow the entry would not be added.
// thread locking semantics : no lock is required.
func (m *lruBoxes) writePending(box persistedBoxData, key string) {
	select {
	case m.pendingBoxes <- cachedBoxData{persistedBoxData: box, key: key}:
	default:
	}
}

// write a single persistedBoxData to the lruBoxes cache.
// when writing the entry, the round number would be used to determine if it's a newer
// version of what's already on the cache or not. In all cases, the entry is going
// to be promoted to the front of the list.
// thread locking semantics : write lock
func (m *lruBoxes) write(boxData persistedBoxData, key string) {
	if el := m.boxes[key]; el != nil {
		// already exists; is it a newer ?
		if el.Value.before(&boxData) {
			// we update with a newer version.
			el.Value = &cachedBoxData{persistedBoxData: boxData, key: key}
		}
		m.boxList.moveToFront(el)
	} else {
		// new entry.
		m.boxes[key] = m.boxList.pushFront(&cachedBoxData{persistedBoxData: boxData, key: key})
	}
}

// prune adjust the current size of the lruBoxes cache, by dropping the least
// recently used entries.
// thread locking semantics : write lock
func (m *lruBoxes) prune(newSize int) (removed int) {
	for {
		if len(m.boxes) <= newSize {
			break
		}
		back := m.boxList.back()
		delete(m.boxes, back.Value.key)
		m.boxList.remove(back)
		removed++
	}
	return
}
