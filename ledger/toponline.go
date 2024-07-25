// Copyright (C) 2019-2024 Algorand, Inc.
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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// topOnlineCache caches a list of top N online accounts, for use in tracking incentive
// participants. The list of addresses may be stale up to topOnlineCacheMaxAge rounds.
type topOnlineCache struct {
	lastQuery basics.Round // the round when the last top N online query was made
	topAccts  []basics.Address
}

const topOnlineCacheMaxAge = 256
const topOnlineCacheSize = 1000

func (t *topOnlineCache) clear() {
	t.lastQuery = 0
	t.topAccts = nil
}

func (t *topOnlineCache) topN(l ledgercore.OnlineAccountsFetcher, rnd basics.Round, currentProto config.ConsensusParams, rewardsLevel uint64) ([]basics.Address, error) {
	if rnd < t.lastQuery {
		// requesting rnd before latest; clear state
		t.clear()
	}
	if rnd.SubSaturate(t.lastQuery) >= topOnlineCacheMaxAge {
		// topOnlineCacheMaxAge has passed, update cache
		data, _, err := l.TopOnlineAccounts(rnd, rnd, topOnlineCacheSize, &currentProto, rewardsLevel)
		if err != nil {
			return nil, err
		}
		t.topAccts = make([]basics.Address, len(data))
		for i := range data {
			t.topAccts[i] = data[i].Address
		}
		t.lastQuery = rnd
	}
	// return cached list of top N accounts
	return t.topAccts, nil
}
