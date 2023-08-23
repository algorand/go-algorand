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
	"sync/atomic"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

// roundCounterCache is a cache that tracks atomic ints used for counting, by-round
// it is abstracted to allow for different types of counters,
// but currently only used for the number of addresses whos voting expires on a given round via newVoteLastValidCache
type roundCounterCache struct {
	trimBehind basics.Round                                            // the round that we have trimmed the cache to
	m          map[basics.Round]*atomic.Uint64                         // count of addresses whos voting expires on this round
	acctFn     func(trackerdb.PersistedOnlineAccountData) basics.Round // function that maps an account to the round information we are tracking (used in init)
	deltaFn    func(accountDelta) (basics.Round, basics.Round)         // function that maps an account delta to the old and new round information we are tracking (used in updateFromAccountDeltas)
}

// newVoteLastValidCache is a factory function for the voteLastValidCache
// which tracks the number of addresses whos voting expires on a given round
func newVoteLastValidCache() roundCounterCache {
	v := roundCounterCache{}
	v.m = make(map[basics.Round]*atomic.Uint64)
	v.trimBehind = 0
	v.acctFn = func(acct trackerdb.PersistedOnlineAccountData) basics.Round {
		return acct.AccountData.VoteLastValid
	}
	v.deltaFn = func(delta accountDelta) (basics.Round, basics.Round) {
		return delta.oldAcct.AccountData.VoteLastValid, delta.newAcct.VoteLastValid
	}
}

// init initializes the cache for use.
// takes a list of persisted online accounts and a function that maps an account to the round we are tracking
func (v *roundCounterCache) init(accts []trackerdb.PersistedOnlineAccountData) {
	for _, acct := range accts {
		v.inc(v.acctFn(acct))
	}
}

func (v *roundCounterCache) inc(r basics.Round) {
	// don't do anything if the round is behind the trimBehind
	if r < v.trimBehind {
		return
	}
	// if we have not seen this round before, initialize it
	if _, ok := v.m[r]; !ok {
		v.m[r] = &atomic.Uint64{}
	}
	v.m[r].Add(1)
}

func (v *roundCounterCache) dec(r basics.Round) {
	// don't do anything if the round is behind the trimBehind
	if r < v.trimBehind {
		return
	}
	// if we have not seen this round before, nothing to decrement
	if _, ok := v.m[r]; !ok {
		return
	}
	v.m[r].Add(^uint64(0))
}

func (v *roundCounterCache) update(rOld, rNew basics.Round) {
	// no actual update
	if rNew == rOld {
		return
	}
	v.dec(rOld)
	v.inc(rNew)
}

// clear clears the cache to pre-init state
func (v *roundCounterCache) clear() {
	v.m = nil
	v.trimBehind = 0
}

// count returns the number of addresses whos voting expire on vLast
func (v roundCounterCache) count(r basics.Round) (*atomic.Uint64, bool) {
	ret, ok := v.m[r]
	return ret, ok
}

// updateFromAccountDeltas updates the cache from the account deltas, given a function mapping a delta to an old and new round
func (v *roundCounterCache) updateFromAccountDeltas(deltas compactAccountDeltas) {
	for _, delta := range deltas.deltas {
		old, new := v.deltaFn(delta)
		v.update(old, new)
	}
}

// trim removes all entries from the cache that are older than vLast
// and advances the trimBehind to vLast
func (v *roundCounterCache) trim(r basics.Round) {
	// if we have already trimmed to this round, do nothing
	if v.trimBehind >= r {
		return
	}
	// otherwise, remove all entries older than vLast
	for i := v.trimBehind; i < r; i++ {
		delete(v.m, i)
	}
	v.trimBehind = r
}

// implements fmt.Stringer
func (v roundCounterCache) String() string {
	return fmt.Sprintf("roundCounterCache: trimBehind: %d, m: %v", v.trimBehind, v.m)
}
