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

// lruAccounts provides a storage class for the most recently used accounts data.
// It doesn't have any synchronization primitive on its own and so is required to be
// synchronized by the caller.
type lruOnlineAccounts struct {
	// accountsList contain the list of persistedAccountData, where the front ones are the most "fresh"
	// and the ones on the back are the oldest.
	accountsList *util.List[*trackerdb.PersistedOnlineAccountData]
	// accounts provides fast access to the various elements in the list by using the account address
	// if lruOnlineAccounts is set with pendingWrites 0, then accounts is nil
	accounts map[basics.Address]*util.ListNode[*trackerdb.PersistedOnlineAccountData]
	// pendingAccounts are used as a way to avoid taking a write-lock. When the caller needs to "materialize" these,
	// it would call flushPendingWrites and these would be merged into the accounts/accountsList
	// if lruOnlineAccounts is set with pendingWrites 0, then pendingAccounts is nil
	pendingAccounts chan trackerdb.PersistedOnlineAccountData
	// log interface; used for logging the threshold event.
	log logging.Logger
	// pendingWritesWarnThreshold is the threshold beyond we would write a warning for exceeding the number of pendingAccounts entries
	pendingWritesWarnThreshold int
}

// init initializes the lruAccounts for use.
// thread locking semantics : write lock
func (m *lruOnlineAccounts) init(log logging.Logger, pendingWrites int, pendingWritesWarnThreshold int) {
	if pendingWrites > 0 {
		m.accountsList = util.NewList[*trackerdb.PersistedOnlineAccountData]().AllocateFreeNodes(pendingWrites)
		m.accounts = make(map[basics.Address]*util.ListNode[*trackerdb.PersistedOnlineAccountData], pendingWrites)
		m.pendingAccounts = make(chan trackerdb.PersistedOnlineAccountData, pendingWrites)
	}
	m.log = log
	m.pendingWritesWarnThreshold = pendingWritesWarnThreshold
}

// read the persistedAccountData object that the lruAccounts has for the given address.
// thread locking semantics : read lock
func (m *lruOnlineAccounts) read(addr basics.Address) (data trackerdb.PersistedOnlineAccountData, has bool) {
	if el := m.accounts[addr]; el != nil {
		return *el.Value, true
	}
	return trackerdb.PersistedOnlineAccountData{}, false
}

// flushPendingWrites flushes the pending writes to the main lruAccounts cache.
// thread locking semantics : write lock
func (m *lruOnlineAccounts) flushPendingWrites() {
	pendingEntriesCount := len(m.pendingAccounts)
	if pendingEntriesCount >= m.pendingWritesWarnThreshold {
		m.log.Warnf("lruOnlineAccounts: number of entries in pendingAccounts(%d) exceed the warning threshold of %d", pendingEntriesCount, m.pendingWritesWarnThreshold)
	}
	for ; pendingEntriesCount > 0; pendingEntriesCount-- {
		select {
		case pendingAccountData := <-m.pendingAccounts:
			m.write(pendingAccountData)
		default:
			return
		}
	}
}

// writePending write a single persistedOnlineAccountData entry to the pendingAccounts buffer.
// the function doesn't block, and in case of a buffer overflow the entry would not be added.
// thread locking semantics : no lock is required.
func (m *lruOnlineAccounts) writePending(acct trackerdb.PersistedOnlineAccountData) {
	select {
	case m.pendingAccounts <- acct:
	default:
	}
}

// write a single persistedAccountData to the lruAccounts cache.
// when writing the entry, the round number would be used to determine if it's a newer
// version of what's already on the cache or not. In all cases, the entry is going
// to be promoted to the front of the list.
// thread locking semantics : write lock
func (m *lruOnlineAccounts) write(acctData trackerdb.PersistedOnlineAccountData) {
	if m.accounts == nil {
		return
	}
	if el := m.accounts[acctData.Addr]; el != nil {
		// already exists; is it a newer ?
		if el.Value.Before(&acctData) {
			// we update with a newer version.
			el.Value = &acctData
		}
		m.accountsList.MoveToFront(el)
	} else {
		// new entry.
		m.accounts[acctData.Addr] = m.accountsList.PushFront(&acctData)
	}
}

// prune adjust the current size of the lruAccounts cache, by dropping the least
// recently used entries.
// thread locking semantics : write lock
func (m *lruOnlineAccounts) prune(newSize int) (removed int) {
	if m.accounts == nil {
		return
	}
	for {
		if len(m.accounts) <= newSize {
			break
		}
		back := m.accountsList.Back()
		delete(m.accounts, back.Value.Addr)
		m.accountsList.Remove(back)
		removed++
	}
	return
}
