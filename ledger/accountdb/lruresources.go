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

package accountdb

import (
	"github.com/algorand/go-algorand/data/basics"

	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
)

//msgp:ignore cachedResourceData
type cachedResourceData struct {
	PersistedResourcesData

	address basics.Address
}

// LRUResources provides a storage class for the most recently used Resources Data.
// It doesn't have any synchronization primitive on it's own and require to be
// syncronized by the caller.
type LRUResources struct {
	// resourcesList contain the list of persistedResourceData, where the front ones are the most "fresh"
	// and the ones on the back are the oldest.
	resourcesList *persistedResourcesDataList

	// resources provides fast access to the various elements in the list by using the account Address
	resources map[ledgercore.AccountCreatable]*persistedResourcesDataListNode

	// pendingResources are used as a way to avoid taking a Write-lock. When the caller needs to "materialize" these,
	// it would call FlushPendingWrites and these would be merged into the resources/resourcesList
	pendingResources chan cachedResourceData

	// log interface; used for logging the threshold event.
	log logging.Logger

	// pendingWritesWarnThreshold is the threshold beyond we would Write a warning for exceeding the number of pendingResources entries
	pendingWritesWarnThreshold int
}

// Init initializes the LRUResources for use.
// thread locking semantics : Write lock
func (m *LRUResources) Init(log logging.Logger, pendingWrites int, pendingWritesWarnThreshold int) {
	m.resourcesList = newPersistedResourcesList().allocateFreeNodes(pendingWrites)
	m.resources = make(map[ledgercore.AccountCreatable]*persistedResourcesDataListNode, pendingWrites)
	m.pendingResources = make(chan cachedResourceData, pendingWrites)
	m.log = log
	m.pendingWritesWarnThreshold = pendingWritesWarnThreshold
}

// Read the persistedResourcesData object that the LRUResources has for the given Address and creatable Index.
// thread locking semantics : Read lock
func (m *LRUResources) Read(addr basics.Address, aidx basics.CreatableIndex) (data PersistedResourcesData, has bool) {
	if el := m.resources[ledgercore.AccountCreatable{Address: addr, Index: aidx}]; el != nil {
		return el.Value.PersistedResourcesData, true
	}
	return PersistedResourcesData{}, false
}

// Read the persistedResourcesData object that the LRUResources has for the given Address.
// thread locking semantics : Read lock
func (m *LRUResources) ReadAll(addr basics.Address) (ret []PersistedResourcesData) {
	for ac, pd := range m.resources {
		if ac.Address == addr {
			ret = append(ret, pd.Value.PersistedResourcesData)
		}
	}
	return
}

// FlushPendingWrites flushes the pending writes to the main LRUResources cache.
// thread locking semantics : Write lock
func (m *LRUResources) FlushPendingWrites() {
	pendingEntriesCount := len(m.pendingResources)
	if pendingEntriesCount >= m.pendingWritesWarnThreshold {
		m.log.Warnf("LRUResources: number of entries in pendingResources(%d) exceed the warning threshold of %d", pendingEntriesCount, m.pendingWritesWarnThreshold)
	}
	for ; pendingEntriesCount > 0; pendingEntriesCount-- {
		select {
		case pendingResourceData := <-m.pendingResources:
			m.Write(pendingResourceData.PersistedResourcesData, pendingResourceData.address)
		default:
			return
		}
	}
}

// WritePending Write a single persistedAccountData entry to the pendingResources buffer.
// the function doesn't block, and in case of a buffer overflow the entry would not be added.
// thread locking semantics : no lock is required.
func (m *LRUResources) WritePending(acct PersistedResourcesData, addr basics.Address) {
	select {
	case m.pendingResources <- cachedResourceData{PersistedResourcesData: acct, address: addr}:
	default:
	}
}

// Write a single persistedAccountData to the LRUResources cache.
// when writing the entry, the Round number would be used to determine if it's a newer
// version of what's already on the cache or not. In all cases, the entry is going
// to be promoted to the front of the list.
// thread locking semantics : Write lock
func (m *LRUResources) Write(resData PersistedResourcesData, addr basics.Address) {
	if el := m.resources[ledgercore.AccountCreatable{Address: addr, Index: resData.Aidx}]; el != nil {
		// already exists; is it a newer ?
		if el.Value.before(&resData) {
			// we update with a newer version.
			el.Value = &cachedResourceData{PersistedResourcesData: resData, address: addr}
		}
		m.resourcesList.moveToFront(el)
	} else {
		// new entry.
		m.resources[ledgercore.AccountCreatable{Address: addr, Index: resData.Aidx}] = m.resourcesList.pushFront(&cachedResourceData{PersistedResourcesData: resData, address: addr})
	}
}

// Prune adjust the current size of the LRUResources cache, by dropping the least
// recently used entries.
// thread locking semantics : Write lock
func (m *LRUResources) Prune(newSize int) (removed int) {
	for {
		if len(m.resources) <= newSize {
			break
		}
		back := m.resourcesList.back()
		delete(m.resources, ledgercore.AccountCreatable{Address: back.Value.address, Index: back.Value.Aidx})
		m.resourcesList.remove(back)
		removed++
	}
	return
}
