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

type voteLastValidCache struct {
	trimBehind basics.Round                    // the round that we have trimmed the cache to
	m          map[basics.Round]*atomic.Uint64 // count of addresses whos voting expires on this round
}

// init initializes the voteLastValidCache for use.
// thread locking semantics : write lock
func (v *voteLastValidCache) init(accts []trackerdb.PersistedOnlineAccountData) {
	v.trimBehind = 0
	v.m = make(map[basics.Round]*atomic.Uint64)

	for _, acct := range accts {
		v.inc(acct.AccountData.VoteLastValid)
	}
}

func (v *voteLastValidCache) inc(vLast basics.Round) {
	if _, ok := v.m[vLast]; !ok {
		v.m[vLast] = &atomic.Uint64{}
	}
	v.m[vLast].Add(1)
}

// TODO: include thread locking semantic comments once known
func (v *voteLastValidCache) update(vLastOld, vLastNew basics.Round) {
	// no actual update
	if vLastNew == vLastOld {
		return
	}
	// if the old round is still in the cache, decrement the address from it
	if vLastOld >= v.trimBehind {
		v.m[vLastOld].Add(^uint64(0))
	}
	v.inc(vLastNew)
}

// clear clears the cache to pre-init state
func (v *voteLastValidCache) clear() {
	v.m = nil
	v.trimBehind = 0
}

// count returns the number of addresses whos voting expire on vLast
func (v voteLastValidCache) count(vLast basics.Round) (*atomic.Uint64, bool) {
	ret, ok := v.m[vLast]
	return ret, ok
}

// updateFromAccountDeltas updates the cache from the account deltas
func (v *voteLastValidCache) updateFromAccountDeltas(deltas compactAccountDeltas) {
	for _, delta := range deltas.deltas {
		new := delta.newAcct.GetAccountData().VoteLastValid
		old := delta.oldAcct.AccountData.VoteLastValid
		v.update(old, new)
	}
}

// trim removes all entries from the cache that are older than vLast
// and advances the trimBehind to vLast
func (v *voteLastValidCache) trim(vLast basics.Round) {
	// if we have already trimmed to this round, do nothing
	if v.trimBehind >= vLast {
		return
	}
	// otherwise, remove all entries older than vLast
	for i := v.trimBehind; i < vLast; i++ {
		delete(v.m, i)
	}
	v.trimBehind = vLast
}

// implements fmt.Stringer
func (v voteLastValidCache) String() string {
	return fmt.Sprintf("voteLastValidCache: trimBehind: %d, m: %v", v.trimBehind, v.m)
}
