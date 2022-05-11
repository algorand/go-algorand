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
	"github.com/algorand/go-algorand/data/basics"
)

// Worst case memory usage = 2500 * 320 * 150B = 120MB
const onlineAccountsCacheMaxSize = 2500

type onlineAccountsCache struct {
	// each persistedOnlineAccountDataList stores online account data with newest
	// at the front, and oldest at the back.
	accounts map[basics.Address]*persistedOnlineAccountDataList
}

// init initializes the onlineAccountsCache for use.
// thread locking semantics : write lock
func (o *onlineAccountsCache) init(accts []persistedOnlineAccountData) {
	o.accounts = make(map[basics.Address]*persistedOnlineAccountDataList)
	for _, acct := range accts {
		// if cache full, stop writing
		if !o.writeFront(acct) {
			break
		}
	}
}

func (o *onlineAccountsCache) full() bool {
	return len(o.accounts) >= onlineAccountsCacheMaxSize
}

// read the persistedAccountData object that the cache has for the given address.
// thread locking semantics : read lock
func (o *onlineAccountsCache) read(addr basics.Address, rnd basics.Round) (persistedOnlineAccountData, bool) {
	if list := o.accounts[addr]; list != nil {
		node := list.back()
		if node.Value.updRound > rnd {
			return persistedOnlineAccountData{}, false
		}
		for node.prev != &list.root {
			node = node.prev
			// only need one entry that is targetRound or older
			if node.Value.updRound > rnd {
				return *node.next.Value, true
			}
		}
		return *node.Value, true
	}
	return persistedOnlineAccountData{}, false
}

// write a single persistedAccountData to the cache
// thread locking semantics : write lock
func (o *onlineAccountsCache) writeFront(acctData persistedOnlineAccountData) bool {
	if _, ok := o.accounts[acctData.addr]; !ok {
		if o.full() {
			return false
		}
		o.accounts[acctData.addr] = newPersistedOnlineAccountList()
	}
	list := o.accounts[acctData.addr]
	if list.root.next != &list.root && acctData.updRound <= list.root.next.Value.updRound {
		return false
	}
	o.accounts[acctData.addr].pushFront(&acctData)
	return true
}

// write a single persistedAccountData to the cache
// thread locking semantics : write lock
func (o *onlineAccountsCache) writeBack(acctData persistedOnlineAccountData) bool {
	if _, ok := o.accounts[acctData.addr]; !ok {
		if o.full() {
			return false
		}
		o.accounts[acctData.addr] = newPersistedOnlineAccountList()
	}
	list := o.accounts[acctData.addr]
	if list.root.prev != &list.root && acctData.updRound >= list.root.prev.Value.updRound {
		return false
	}
	o.accounts[acctData.addr].pushBack(&acctData)
	return true
}

// prune trims the onlineaccountscache by only keeping entries that would give account state
// of rounds targetRound and later
// thread locking semantics : write lock
func (o *onlineAccountsCache) prune(targetRound basics.Round) {
	for addr, list := range o.accounts {
		node := list.back()
		for node.prev != &list.root {
			node = node.prev
			// keep only one entry that is targetRound or older
			// discard all older additional entries older than targetRound
			if node.Value.updRound <= targetRound {
				list.remove(node.next)
			} else {
				break
			}
		}
		// only one item left in cache
		if node.prev == &list.root && node.next == &list.root {
			if node.Value.accountData.IsVotingEmpty() {
				delete(o.accounts, addr)
			}
		}
	}
}

// replace replaces all entries for an account with provided history
// may not insert data if cache full
func (o *onlineAccountsCache) replace(persistedDataHistory []persistedOnlineAccountData, addr basics.Address) {
	delete(o.accounts, addr)
	if !o.full() {
		for _, data := range persistedDataHistory {
			o.writeFront(data)
		}
	}
}
