// Copyright (C) 2019-2021 Algorand, Inc.
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
	"container/list"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

// mruAccounts provides a storage class for the most recently used accounts data.
// It doesn't have any syncronization primitive on it's own and require to be
// syncronized by the caller.
type mruAccounts struct {
	// accountsList contain the list of persistedAccountData, where the front ones are the most "fresh"
	// and the ones on the back are the oldest.
	accountsList *list.List
	// accounts provides fast access to the various elements in the list by using the account address
	accounts map[basics.Address]*list.Element
	// pendingAccounts are used as a way to avoid taking a write-lock. When the caller needs to "materialize" these,
	// it would call flushPendingWrites and these would be merged into the accounts/accountsList
	pendingAccounts chan persistedAccountData
	// log interface
	log logging.Logger
	// pendingWritesWarnThreshold is the threshold beyond we would write a warning for exceeding the number of pendingAccounts entries
	pendingWritesWarnThreshold int
}

func (m *mruAccounts) init(log logging.Logger, pendingWrites int, pendingWritesWarnThreshold int) {
	m.accountsList = list.New()
	m.accounts = make(map[basics.Address]*list.Element)
	m.pendingAccounts = make(chan persistedAccountData, pendingWrites)
	m.log = log
	m.pendingWritesWarnThreshold = pendingWritesWarnThreshold
}

func (m *mruAccounts) read(addr basics.Address) (data persistedAccountData, has bool) {
	if el := m.accounts[addr]; el != nil {
		return el.Value.(persistedAccountData), true
	}
	return persistedAccountData{}, false
}

func (m *mruAccounts) flushPendingWrites() {
	pendingEntriesCount := len(m.pendingAccounts)
	if pendingEntriesCount >= m.pendingWritesWarnThreshold {
		m.log.Warnf("mruAccounts: number of entries in pendingAccounts(%d) exceed the warning threshold of %d", pendingEntriesCount, m.pendingWritesWarnThreshold)
	}
	for ; pendingEntriesCount > 0; pendingEntriesCount-- {
		select {
		case pendingAccountData := <-m.pendingAccounts:
			m.write(pendingAccountData)
		default:
			return
		}
	}
	return
}

func (m *mruAccounts) writePending(acct persistedAccountData) {
	select {
	case m.pendingAccounts <- acct:
	default:
	}
}

func (m *mruAccounts) writeAccounts(updates map[basics.Address]persistedAccountData) {
	for _, update := range updates {
		m.write(update)
	}
	return
}

func (m *mruAccounts) write(acctData persistedAccountData) {
	if el := m.accounts[acctData.addr]; el != nil {
		// already exists; is it a newer ?
		existing := el.Value.(persistedAccountData)
		if existing.round < acctData.round {
			// we update with a newer version.
			el.Value = acctData
		}
		m.accountsList.MoveToFront(el)
	} else {
		// new entry.
		m.accounts[acctData.addr] = m.accountsList.PushFront(acctData)
	}
}

func (m *mruAccounts) resize(newSize int) (removed int) {
	for {
		if len(m.accounts) <= newSize {
			break
		}
		back := m.accountsList.Back()
		delete(m.accounts, back.Value.(persistedAccountData).addr)
		m.accountsList.Remove(back)
		removed++
	}
	return
}
