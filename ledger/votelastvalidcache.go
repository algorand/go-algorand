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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

// onlineAccountAttributeCache is an interface for a cache that keeps some basic record, given onlineAccounts
type onlineAccountAttributeCache[K, V any] interface {
	init([]trackerdb.PersistedOnlineAccountData)
	clear()
	update(onlineAccountDelta)
	get(K) (V, bool)
	trim(K)
}

type expiringStakeCache struct {
	trimBehind basics.Round                       // the round that we have trimmed the cache to
	m          map[basics.Round]basics.MicroAlgos // count of addresses whos voting expires on this round
}

// newExpiringStakeCache is a factory function for the expiringStakeCache
func newExpiringStakeCache() expiringStakeCache {
	e := expiringStakeCache{}
	e.m = make(map[basics.Round]basics.MicroAlgos)
	e.trimBehind = 0
	return e
}

func (e expiringStakeCache) init(accts []trackerdb.PersistedOnlineAccountData) {
	for _, acct := range accts {
		e.add(acct.AccountData.VoteLastValid, acct.AccountData.MicroAlgos)
	}
}

func (e expiringStakeCache) add(r basics.Round, stake basics.MicroAlgos) {
	// don't do anything if the round is behind the trimBehind
	if r < e.trimBehind {
		return
	}
	// if we have not seen this round before, initialize it
	if _, ok := e.m[r]; !ok {
		e.m[r] = stake
	} else {
		e.m[r] = basics.MicroAlgos{Raw: e.m[r].ToUint64() + stake.ToUint64()}
	}
}

// sub subtracts the given stake from the given round
// the caller is expected to have already checked that the update is valid (so underflow is not checked here)
func (e expiringStakeCache) sub(r basics.Round, stake basics.MicroAlgos) {
	// don't do anything if the round is behind the trimBehind
	if r < e.trimBehind {
		return
	}
	// if we have not seen this round before, nothing to subtract from. Should not happen if the caller is managing updates correctly
	if _, ok := e.m[r]; !ok {
		return
	} else {
		e.m[r] = basics.MicroAlgos{Raw: e.m[r].ToUint64() - stake.ToUint64()}
	}
}

func (e expiringStakeCache) update(ad onlineAccountDelta) {
	old, new := ad.oldAcct.AccountData.VoteLastValid, ad.newAcct[0].VoteLastValid
	e.sub(old, ad.oldAcct.AccountData.MicroAlgos)
	e.add(new, ad.newAcct[0].MicroAlgos)
}

func (e expiringStakeCache) clear() {
	e.m = nil
	e.trimBehind = 0
}

func (e expiringStakeCache) get(r basics.Round) (basics.MicroAlgos, bool) {
	ret, ok := e.m[r]
	return ret, ok
}

func (e expiringStakeCache) trim(r basics.Round) {
	// if we have already trimmed to this round, do nothing
	if e.trimBehind >= r {
		return
	}
	// otherwise, remove all entries older than vLast
	for i := e.trimBehind; i < r; i++ {
		delete(e.m, i)
	}
	e.trimBehind = r
}

func (e expiringStakeCache) String() string {
	return fmt.Sprintf("expiringStakeCache: trimBehind: %d, m: %v", e.trimBehind, e.m)
}
