// Copyright (C) 2019-2024 Algorand, Inc.
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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util"
)

//msgp:ignore cachedResourceData
type cachedResourceData struct {
	trackerdb.PersistedResourcesData

	address basics.Address
}

// lruResources provides a storage class for the most recently used resources' data.
// It doesn't have any synchronization primitive on its own and require to be
// synchronized by the caller.
type lruResources struct {
	// resourcesList contain the list of persistedResourceData, where the front ones are the most "fresh"
	// and the ones on the back are the oldest.
	resourcesList *util.List[*cachedResourceData]

	// resources provides fast access to the various elements in the list by using the account address
	// if lruResources is set with pendingWrites 0, then resources is nil
	resources map[accountCreatable]*util.ListNode[*cachedResourceData]

	// pendingResources are used as a way to avoid taking a write-lock. When the caller needs to "materialize" these,
	// it would call flushPendingWrites and these would be merged into the resources/resourcesList
	// if lruResources is set with pendingWrites 0, then pendingResources is nil
	pendingResources chan cachedResourceData

	// log interface; used for logging the threshold event.
	log logging.Logger

	// pendingWritesWarnThreshold is the threshold beyond we would write a warning for exceeding the number of pendingResources entries
	pendingWritesWarnThreshold int

	// if lruResources is set with pendingWrites 0, then pendingNotFound and notFound is nil
	pendingNotFound chan accountCreatable
	notFound        map[accountCreatable]struct{}
}

// init initializes the lruResources for use.
// thread locking semantics : write lock
func (m *lruResources) init(log logging.Logger, pendingWrites int, pendingWritesWarnThreshold int) {
	if pendingWrites > 0 {
		m.resourcesList = util.NewList[*cachedResourceData]().AllocateFreeNodes(pendingWrites)
		m.resources = make(map[accountCreatable]*util.ListNode[*cachedResourceData], pendingWrites)
		m.pendingResources = make(chan cachedResourceData, pendingWrites)
		m.notFound = make(map[accountCreatable]struct{}, pendingWrites)
		m.pendingNotFound = make(chan accountCreatable, pendingWrites)
	}
	m.log = log
	m.pendingWritesWarnThreshold = pendingWritesWarnThreshold
}

// read the persistedResourcesData object that the lruResources has for the given address and creatable index.
// thread locking semantics : read lock
func (m *lruResources) read(addr basics.Address, aidx basics.CreatableIndex) (data trackerdb.PersistedResourcesData, has bool) {
	if el := m.resources[accountCreatable{address: addr, index: aidx}]; el != nil {
		return el.Value.PersistedResourcesData, true
	}
	return trackerdb.PersistedResourcesData{}, false
}

// readNotFound returns whether we have attempted to read this address but it did not exist in the db.
// thread locking semantics : read lock
func (m *lruResources) readNotFound(addr basics.Address, idx basics.CreatableIndex) bool {
	_, ok := m.notFound[accountCreatable{address: addr, index: idx}]
	return ok
}

// read the persistedResourcesData object that the lruResources has for the given address.
// thread locking semantics : read lock
func (m *lruResources) readAll(addr basics.Address) (ret []trackerdb.PersistedResourcesData) {
	for ac, pd := range m.resources {
		if ac.address == addr {
			ret = append(ret, pd.Value.PersistedResourcesData)
		}
	}
	return
}

// flushPendingWrites flushes the pending writes to the main lruResources cache.
// thread locking semantics : write lock
func (m *lruResources) flushPendingWrites() {
	pendingEntriesCount := len(m.pendingResources)
	if pendingEntriesCount >= m.pendingWritesWarnThreshold {
		m.log.Infof("lruResources: number of entries in pendingResources(%d) exceed the warning threshold of %d", pendingEntriesCount, m.pendingWritesWarnThreshold)
	}

outer:
	for ; pendingEntriesCount > 0; pendingEntriesCount-- {
		select {
		case pendingResourceData := <-m.pendingResources:
			m.write(pendingResourceData.PersistedResourcesData, pendingResourceData.address)
		default:
			break outer
		}
	}

	pendingEntriesCount = len(m.pendingNotFound)
outer2:
	for ; pendingEntriesCount > 0; pendingEntriesCount-- {
		select {
		case key := <-m.pendingNotFound:
			m.notFound[key] = struct{}{}
		default:
			break outer2
		}
	}
}

// writePending write a single persistedAccountData entry to the pendingResources buffer.
// the function doesn't block, and in case of a buffer overflow the entry would not be added.
// thread locking semantics : no lock is required.
func (m *lruResources) writePending(acct trackerdb.PersistedResourcesData, addr basics.Address) {
	select {
	case m.pendingResources <- cachedResourceData{PersistedResourcesData: acct, address: addr}:
	default:
	}
}

// writeNotFoundPending tags an address as not existing in the db.
// the function doesn't block, and in case of a buffer overflow the entry would not be added.
// thread locking semantics : no lock is required.
func (m *lruResources) writeNotFoundPending(addr basics.Address, idx basics.CreatableIndex) {
	select {
	case m.pendingNotFound <- accountCreatable{address: addr, index: idx}:
	default:
	}
}

// write a single persistedAccountData to the lruResources cache.
// when writing the entry, the round number would be used to determine if it's a newer
// version of what's already on the cache or not. In all cases, the entry is going
// to be promoted to the front of the list.
// thread locking semantics : write lock
func (m *lruResources) write(resData trackerdb.PersistedResourcesData, addr basics.Address) {
	if m.resources == nil {
		return
	}
	if el := m.resources[accountCreatable{address: addr, index: resData.Aidx}]; el != nil {
		// already exists; is it a newer ?
		if el.Value.Before(&resData) {
			// we update with a newer version.
			el.Value = &cachedResourceData{PersistedResourcesData: resData, address: addr}
		}
		m.resourcesList.MoveToFront(el)
	} else {
		// new entry.
		m.resources[accountCreatable{address: addr, index: resData.Aidx}] = m.resourcesList.PushFront(&cachedResourceData{PersistedResourcesData: resData, address: addr})
	}
}

// prune adjust the current size of the lruResources cache, by dropping the least
// recently used entries.
// thread locking semantics : write lock
func (m *lruResources) prune(newSize int) (removed int) {
	if m.resources == nil {
		return
	}
	for {
		if len(m.resources) <= newSize {
			break
		}
		back := m.resourcesList.Back()
		delete(m.resources, accountCreatable{address: back.Value.address, index: back.Value.Aidx})
		m.resourcesList.Remove(back)
		removed++
	}

	// clear the notFound list
	m.notFound = make(map[accountCreatable]struct{}, len(m.notFound))
	return
}
