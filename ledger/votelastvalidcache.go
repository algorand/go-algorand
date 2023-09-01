// Copyright (C) 2019-2023 Algorand, Inc.
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
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

// doubleIndex map uses two keys to store a value
// when adding, it adds the value to both keys.
// The primary data V is stored at [Ka][Kb]
// the index Ka is also stored in a secondary map under [Kb]
// in this way, we can retrieve V by either [Ka][Kb] or [Kb]
// retreiving [Ka] returns a map of Kb->V
type doubleIndexMap[Ka, Kb comparable, V any] interface {
	add(Ka, Kb, V)
	trim(Ka)
	remove(Kb)
	get(Kb) (V, bool)
	getPrimary(Ka) (map[Kb]V, bool)
	getSecondary(Kb) (Ka, bool)
}
type doubleMap[Ka, Kb comparable, V any] struct {
	primary   map[Ka]map[Kb]V
	secondary map[Kb]Ka
	zeroVal   V
}

func newDoubleMap[Ka, Kb comparable, V any](zero V) doubleMap[Ka, Kb, V] {
	return doubleMap[Ka, Kb, V]{
		primary:   make(map[Ka]map[Kb]V),
		secondary: make(map[Kb]Ka),
		zeroVal:   zero,
	}
}
func (d doubleMap[Ka, Kb, V]) add(ka Ka, kb Kb, v V) {
	// f mt.Printrintln("add:", ka, kb, v)
	if _, ok := d.primary[ka]; !ok {
		d.primary[ka] = make(map[Kb]V)
	}
	d.primary[ka][kb] = v
	d.secondary[kb] = ka
}
func (d doubleMap[Ka, Kb, V]) trim(ka Ka) {
	delete(d.primary, ka)
}
func (d doubleMap[Ka, Kb, V]) remove(kb Kb) {
	ka, ok := d.secondary[kb]
	if !ok {
		return
	}
	delete(d.primary[ka], kb)
	delete(d.secondary, kb)
}
func (d doubleMap[Ka, Kb, V]) get(kb Kb) (V, bool) {
	ka, ok := d.secondary[kb]
	if !ok {
		return d.zeroVal, false
	}
	return d.primary[ka][kb], true
}
func (d doubleMap[Ka, Kb, V]) getPrimary(ka Ka) (map[Kb]V, bool) {
	ret, ok := d.primary[ka]
	// f mt.Printrint("getPrimary:", ka)
	// f mt.Printrintln(" ret:", ret)
	return ret, ok
}
func (d doubleMap[Ka, Kb, V]) getSecondary(kb Kb) (Ka, bool) {
	ret, ok := d.secondary[kb]
	return ret, ok
}
func (d doubleMap[Ka, Kb, V]) String() string {
	return fmt.Sprintf("doubleMap: primary: %v\nsecondary: %v", d.primary, d.secondary)
}

// onlineAccountAttributeCache is an interface for a cache that keeps some basic record, given onlineAccounts
// it inittializes from the onlineAccounts persisted data (like from OnlineAccountsAll)
// it commits updates using the onlineAccountDelta
// when querying, it takes into account ledgercore deltas
type onlineAccountAttributeCache[K, V any] interface {
	init([]trackerdb.PersistedOnlineAccountData)
	clear()
	update(onlineAccountDelta)
	getRange(K, K, config.ConsensusParams, uint64) map[basics.Address]*ledgercore.OnlineAccountData
	trim(K)
}

// expiringStakeCache is a cache for the stake of an account at a given round
// it uses a Key of Round, and returns a Value of MicroAlgos expiring on that round
// it internally uses Address as a secondary key so that it can be updated with account data
type expiringStakeCache struct {
	trimBehind basics.Round                                                    // the round that we have trimmed the cache to
	microAlgos doubleIndexMap[basics.Round, basics.Address, basics.MicroAlgos] // round->address->stake
}

func newExpiringStakeCache() expiringStakeCache {
	e := expiringStakeCache{}
	e.microAlgos = newDoubleMap[basics.Round, basics.Address, basics.MicroAlgos](basics.MicroAlgos{})
	e.trimBehind = 0
	return e
}

func (e expiringStakeCache) init(accts []trackerdb.PersistedOnlineAccountData) {
	for _, acct := range accts {
		e.add(acct.AccountData.VoteLastValid, acct.Addr, acct.AccountData.MicroAlgos)
	}
}

func (e expiringStakeCache) add(r basics.Round, addr basics.Address, stake basics.MicroAlgos) {
	// don't do anything if the round is behind the trimBehind
	if r < e.trimBehind {
		return
	}
	e.microAlgos.add(r, addr, stake)
	e.microAlgos.getPrimary(r)
	// f mt.Printrintf("%p\n", &e)
}

// remove takes an address and removes it from the cache
func (e expiringStakeCache) remove(addr basics.Address) {
	e.microAlgos.remove(addr)
}

func (e expiringStakeCache) update(ad onlineAccountDelta) {
	e.microAlgos.remove(ad.oldAcct.Addr)
	// f mt.Printrintln("?????", len(ad.newAcct))
	finalUpdate := ad.newAcct[len(ad.newAcct)-1]
	e.microAlgos.add(finalUpdate.VoteLastValid, ad.oldAcct.Addr, finalUpdate.MicroAlgos)
	// f mt.Printrintf("after update: %v\n", e.microAlgos)
}

func (e expiringStakeCache) getRange(rStart, rEnd basics.Round, proto config.ConsensusParams, rewardsLevel uint64) map[basics.Address]*ledgercore.OnlineAccountData {
	var expiredAccounts map[basics.Address]*ledgercore.OnlineAccountData
	expiredAccounts = make(map[basics.Address]*ledgercore.OnlineAccountData)
	for i := rStart; i < rEnd; i++ {
		acctsStake, ok := e.microAlgos.getPrimary(i)
		if ok {
			for addr, stake := range acctsStake {
				data := trackerdb.BaseOnlineAccountData{
					MicroAlgos: stake,
					BaseVotingData: trackerdb.BaseVotingData{
						VoteLastValid: i,
					},
				}
				x := data.GetOnlineAccountData(proto, rewardsLevel)
				expiredAccounts[addr] = &x
			}

		}
	}
	return expiredAccounts
}

func (e expiringStakeCache) clear() {
	e.microAlgos = newDoubleMap[basics.Round, basics.Address, basics.MicroAlgos](basics.MicroAlgos{})
	e.trimBehind = 0
}

func (e expiringStakeCache) trim(r basics.Round) {
	// if we have already trimmed to this round, do nothing
	if e.trimBehind >= r {
		return
	}
	// otherwise, remove all entries older than vLast
	for i := e.trimBehind; i < r; i++ {
		e.microAlgos.trim(i)
	}
	e.trimBehind = r
}

func (e expiringStakeCache) String() string {
	return fmt.Sprintf("expiringStakeCache: trimBehind: %d, microalgos: %v", e.trimBehind, e.microAlgos)
}
