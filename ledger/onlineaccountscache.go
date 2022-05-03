package ledger

import (
	"fmt"
	"github.com/algorand/go-algorand/data/basics"
)

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
		if node.Value.round > rnd {
			return persistedOnlineAccountData{}, false
		}
		for node.prev != &list.root {
			node = node.prev
			// only need one entry that is targetRound or older
			if node.Value.round > rnd {
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
	fmt.Println(acctData.addr, "front", acctData.round)
	if _, ok := o.accounts[acctData.addr]; !ok {
		o.accounts[acctData.addr] = newPersistedOnlineAccountList()
	}
	list := o.accounts[acctData.addr]
	if list.root.next != &list.root && acctData.round <= list.root.next.Value.round {
		fmt.Println(acctData.round, list.root.next.Value.round)
		//panic("VERY BAD")
		return
	}
	o.accounts[acctData.addr].pushFront(&acctData)
	if o.accounts[acctData.addr].root.prev.Value == nil {
		panic("what?")
	}
}

// write a single persistedAccountData to the cache
// thread locking semantics : write lock
func (o *onlineAccountsCache) writeBack(acctData persistedOnlineAccountData) {
	fmt.Println(acctData.addr, "back", acctData.round)
	if _, ok := o.accounts[acctData.addr]; !ok {
		o.accounts[acctData.addr] = newPersistedOnlineAccountList()
	}
	list := o.accounts[acctData.addr]
	if list.root.prev != &list.root && acctData.round >= list.root.prev.Value.round {
		fmt.Println(acctData.round, list.root.prev.Value.round)
		//panic("SUPER BAD")
		return
	}
	o.accounts[acctData.addr].pushBack(&acctData)
	if o.accounts[acctData.addr].root.prev.Value == nil {
		panic("huh?")
	}
}

// prune trims the onlineaccountscache by only keeping entries that would give account state
// of rounds past targetRound
// thread locking semantics : write lock
func (o *onlineAccountsCache) prune(targetRound basics.Round) {
	for _, list := range o.accounts {
		node := list.back()
		for node.prev != &list.root {
			node = node.prev
			// only need one entry that is targetRound or older
			if node.Value.round <= targetRound {
				list.remove(node.next)
			}
		}
	}
	return
}