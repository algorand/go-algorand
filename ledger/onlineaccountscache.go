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
	"container/list"

	"github.com/algorand/go-algorand/data/basics"
)

// Worst case memory usage = 2500 * 320 * 150B = 120MB
const onlineAccountsCacheMaxSize = 2500

type onlineAccountsCache struct {
	// each List stores online account data with newest
	// at the front, and oldest at the back.
	accounts     map[basics.Address]*list.List
	maxCacheSize int
}

// init initializes the onlineAccountsCache for use.
// thread locking semantics : write lock
func (o *onlineAccountsCache) init(accts []persistedOnlineAccountData, maxCacheSize int) {
	o.accounts = make(map[basics.Address]*list.List)
	o.maxCacheSize = maxCacheSize

	for _, acct := range accts {
		// if cache full, stop writing
		cachedAcct := cachedOnlineAccount{
			baseOnlineAccountData: acct.accountData,
			updRound:              acct.updRound,
		}
		if !o.writeFront(acct.addr, cachedAcct) {
			break
		}
	}
}

func (o *onlineAccountsCache) full() bool {
	return len(o.accounts) >= o.maxCacheSize
}

func (o *onlineAccountsCache) maxSize() int {
	return o.maxCacheSize
}

// read the cachedOnlineAccount object that the cache has for the given address.
// thread locking semantics : read lock
func (o *onlineAccountsCache) read(addr basics.Address, rnd basics.Round) (cachedOnlineAccount, bool) {
	if list := o.accounts[addr]; list != nil {
		node := list.Back()
		prevValue := node.Value.(*cachedOnlineAccount)
		if prevValue.updRound > rnd {
			return cachedOnlineAccount{}, false
		}
		for node.Prev() != nil {
			node = node.Prev()
			// only need one entry that is targetRound or older
			currentValue := node.Value.(*cachedOnlineAccount)
			if currentValue.updRound > rnd {
				return *prevValue, true
			}
			prevValue = currentValue
		}
		return *prevValue, true
	}
	return cachedOnlineAccount{}, false
}

// write a single cachedOnlineAccount to the cache
// thread locking semantics : write lock
func (o *onlineAccountsCache) writeFront(addr basics.Address, acctData cachedOnlineAccount) bool {
	var l *list.List
	var ok bool
	if l, ok = o.accounts[addr]; !ok {
		if o.full() {
			return false
		}
		l = list.New()
	}
	// do not insert if acctData would not be the newest entry in the cache
	if l.Front() != nil && acctData.updRound <= l.Front().Value.(*cachedOnlineAccount).updRound {
		return false
	}
	l.PushFront(&acctData)
	o.accounts[addr] = l
	return true
}

// write a single cachedOnlineAccount to the cache only if there are some history entries
// thread locking semantics : write lock
func (o *onlineAccountsCache) writeFrontIfExist(addr basics.Address, acctData cachedOnlineAccount) {
	var l *list.List
	var ok bool
	if l, ok = o.accounts[addr]; !ok {
		return
	}
	if l.Len() == 0 {
		return
	}
	// do not insert if acctData would not be the newest entry in the cache
	if l.Front() != nil && acctData.updRound <= l.Front().Value.(*cachedOnlineAccount).updRound {
		return
	}
	l.PushFront(&acctData)
	o.accounts[addr] = l
}

// prune trims the onlineAccountsCache by only keeping entries that would give account state
// of rounds targetRound and later, repeating the deletion logic from the history DB
// thread locking semantics : write lock
func (o *onlineAccountsCache) prune(targetRound basics.Round) {
	for addr, list := range o.accounts {
		node := list.Back()
		for node.Prev() != nil {
			node = node.Prev()
			// keep only one entry that is targetRound or older
			// discard all entries older than targetRound other than the current entry
			if node.Value.(*cachedOnlineAccount).updRound < targetRound {
				list.Remove(node.Next())
			} else {
				break
			}
		}
		// only one item left in cache
		if node.Prev() == nil && node.Next() == nil {
			if node.Value.(*cachedOnlineAccount).IsVotingEmpty() {
				delete(o.accounts, addr)
			}
		}
	}
}

// delete cache for a particular address
func (o *onlineAccountsCache) clear(addr basics.Address) {
	delete(o.accounts, addr)
}
