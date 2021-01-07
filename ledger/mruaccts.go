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
)

// mruAccounts provides a storage class for the most recently used accounts data.
// It doesn't have any syncronization primitive on it's own, but instead desiged so that it's
// methods have a clear designation of the required syncronization model.
type mruAccounts struct {
	accountsList *list.List
	accounts     map[basics.Address]*list.Element

	deferredWrites chan persistedAccountData
}

func (m *mruAccounts) init(deferredWrites int) {
	m.accountsList = list.New()
	m.accounts = make(map[basics.Address]*list.Element)
	m.deferredWrites = make(chan persistedAccountData, deferredWrites)
}

func (m *mruAccounts) read(addr basics.Address) (data persistedAccountData, has bool) {
	if el := m.accounts[addr]; el != nil {
		return el.Value.(persistedAccountData), true
	}
	return persistedAccountData{}, false
}

func (m *mruAccounts) queueDeferredWrite(acct persistedAccountData) {
	select {
	case m.deferredWrites <- acct:
	default:
	}
}

func (m *mruAccounts) getDeferredWrites() (updates map[basics.Address]persistedAccountData) {
	updates = make(map[basics.Address]persistedAccountData)
	for {
		select {
		case br := <-m.deferredWrites:
			updates[br.addr] = br
		default:
			return
		}
	}
	return
}

func (m *mruAccounts) writeAccounts(updates map[basics.Address]persistedAccountData) {
	for _, update := range updates {
		if el := m.accounts[update.addr]; el != nil {
			// already exists, update and promote.
			el.Value = update
			m.accountsList.MoveToFront(el)
		} else {
			// new entry.
			m.accounts[update.addr] = m.accountsList.PushFront(update)
		}
	}
	return
}

func (m *mruAccounts) write(acctData persistedAccountData) {
	if el := m.accounts[acctData.addr]; el != nil {
		// already exists, update and promote.
		el.Value = acctData
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
