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
	"github.com/algorand/go-algorand/logging"
)

// LRUAccounts provides a storage class for the most recently used accounts Data.
// It doesn't have any synchronization primitive on it's own and require to be
// syncronized by the caller.
type LRUAccounts struct {
	// accountsList contain the list of persistedAccountData, where the front ones are the most "fresh"
	// and the ones on the back are the oldest.
	accountsList *persistedAccountDataList
	// accounts provides fast access to the various elements in the list by using the account Address
	accounts map[basics.Address]*persistedAccountDataListNode
	// pendingAccounts are used as a way to avoid taking a Write-lock. When the caller needs to "materialize" these,
	// it would call FlushPendingWrites and these would be merged into the accounts/accountsList
	pendingAccounts chan PersistedAccountData
	// log interface; used for logging the threshold event.
	log logging.Logger
	// pendingWritesWarnThreshold is the threshold beyond we would Write a warning for exceeding the number of pendingAccounts entries
	pendingWritesWarnThreshold int
}

// Init initializes the LRUAccounts for use.
// thread locking semantics : Write lock
func (m *LRUAccounts) Init(log logging.Logger, pendingWrites int, pendingWritesWarnThreshold int) {
	m.accountsList = newPersistedAccountList().allocateFreeNodes(pendingWrites)
	m.accounts = make(map[basics.Address]*persistedAccountDataListNode, pendingWrites)
	m.pendingAccounts = make(chan PersistedAccountData, pendingWrites)
	m.log = log
	m.pendingWritesWarnThreshold = pendingWritesWarnThreshold
}

// Read the persistedAccountData object that the LRUAccounts has for the given Address.
// thread locking semantics : Read lock
func (m *LRUAccounts) Read(addr basics.Address) (data PersistedAccountData, has bool) {
	if el := m.accounts[addr]; el != nil {
		return *el.Value, true
	}
	return PersistedAccountData{}, false
}

// FlushPendingWrites flushes the pending writes to the main LRUAccounts cache.
// thread locking semantics : Write lock
func (m *LRUAccounts) FlushPendingWrites() {
	pendingEntriesCount := len(m.pendingAccounts)
	if pendingEntriesCount >= m.pendingWritesWarnThreshold {
		m.log.Warnf("LRUAccounts: number of entries in pendingAccounts(%d) exceed the warning threshold of %d", pendingEntriesCount, m.pendingWritesWarnThreshold)
	}
	for ; pendingEntriesCount > 0; pendingEntriesCount-- {
		select {
		case pendingAccountData := <-m.pendingAccounts:
			m.Write(pendingAccountData)
		default:
			return
		}
	}
}

// WritePending Write a single persistedAccountData entry to the pendingAccounts buffer.
// the function doesn't block, and in case of a buffer overflow the entry would not be added.
// thread locking semantics : no lock is required.
func (m *LRUAccounts) WritePending(acct PersistedAccountData) {
	select {
	case m.pendingAccounts <- acct:
	default:
	}
}

// Write a single persistedAccountData to the LRUAccounts cache.
// when writing the entry, the Round number would be used to determine if it's a newer
// version of what's already on the cache or not. In all cases, the entry is going
// to be promoted to the front of the list.
// thread locking semantics : Write lock
func (m *LRUAccounts) Write(acctData PersistedAccountData) {
	if el := m.accounts[acctData.Addr]; el != nil {
		// already exists; is it a newer ?
		if el.Value.before(&acctData) {
			// we update with a newer version.
			el.Value = &acctData
		}
		m.accountsList.moveToFront(el)
	} else {
		// new entry.
		m.accounts[acctData.Addr] = m.accountsList.pushFront(&acctData)
	}
}

// Prune adjust the current size of the LRUAccounts cache, by dropping the least
// recently used entries.
// thread locking semantics : Write lock
func (m *LRUAccounts) Prune(newSize int) (removed int) {
	for {
		if len(m.accounts) <= newSize {
			break
		}
		back := m.accountsList.back()
		delete(m.accounts, back.Value.Addr)
		m.accountsList.remove(back)
		removed++
	}
	return
}
