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

const onlineAccountsCacheMaxSize = 1000

type onlineAccountsCache struct {
	accounts map[basics.Address]*persistedOnlineAccountDataList
}

// init initializes the onlineAccountsCache for use.
// thread locking semantics : write lock
func (o *onlineAccountsCache) init() {
	o.accounts = make(map[basics.Address]*persistedOnlineAccountDataList)
}

// read the persistedAccountData object that the cache has for the given address.
// thread locking semantics : read lock
func (o *onlineAccountsCache) read(addr basics.Address, rnd basics.Round) (data persistedOnlineAccountData, has bool) {
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
func (o *onlineAccountsCache) writeFront(acctData persistedOnlineAccountData) {
	if _, ok := o.accounts[acctData.addr]; !ok {
		if len(o.accounts) >= onlineAccountsCacheMaxSize {
			return
		}
		o.accounts[acctData.addr] = newPersistedOnlineAccountList()
	}
	list := o.accounts[acctData.addr]
	if list.root.next != &list.root && acctData.updRound <= list.root.next.Value.updRound {
		return
	}
	o.accounts[acctData.addr].pushFront(&acctData)
}

// write a single persistedAccountData to the cache
// thread locking semantics : write lock
func (o *onlineAccountsCache) writeBack(acctData persistedOnlineAccountData) {
	if _, ok := o.accounts[acctData.addr]; !ok {
		if len(o.accounts) >= onlineAccountsCacheMaxSize {
			return
		}
		o.accounts[acctData.addr] = newPersistedOnlineAccountList()
	}
	list := o.accounts[acctData.addr]
	if list.root.prev != &list.root && acctData.updRound >= list.root.prev.Value.updRound {
		return
	}
	o.accounts[acctData.addr].pushBack(&acctData)
}

// prune trims the onlineaccountscache by only keeping entries that would give account state
// of rounds past targetRound
// thread locking semantics : write lock
func (o *onlineAccountsCache) prune(targetRound basics.Round) {
	for addr, list := range o.accounts {
		node := list.back()
		for node.prev != &list.root {
			node = node.prev
			// only need one entry that is targetRound or older
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
