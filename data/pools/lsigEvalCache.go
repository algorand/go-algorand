// Copyright (C) 2019 Algorand, Inc.
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

package pools

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

type cvtx struct {
	cvers protocol.ConsensusVersion
	txid  transactions.Txid
}

type lsigEvalSubcache struct {
	entries      map[protocol.ConsensusVersion]map[transactions.Txid]error
	byFirstValid map[basics.Round]map[int64][]cvtx
}

func (les *lsigEvalSubcache) get(cvers protocol.ConsensusVersion, txid transactions.Txid) (found bool, err error) {
	if les == nil || les.entries == nil {
		found = false
		err = nil
		return
	}
	var byvers map[transactions.Txid]error
	byvers, found = les.entries[cvers]
	if !found {
		return
	}
	err, found = byvers[txid]
	return
}

func (les *lsigEvalSubcache) put(cvers protocol.ConsensusVersion, txid transactions.Txid, firstValid basics.Round, firstValidTimestamp int64, err error, size int) {
	byvers, found := les.entries[cvers]
	if !found {
		byvers = make(map[transactions.Txid]error, size)
		les.entries[cvers] = byvers
	}
	byvers[txid] = err
	if firstValid != 0 && firstValidTimestamp != 0 {
		fvround, ok := les.byFirstValid[firstValid]
		if !ok {
			fvround = make(map[int64][]cvtx)
			les.byFirstValid[firstValid] = fvround
		}
		fvround[firstValidTimestamp] = append(fvround[firstValidTimestamp], cvtx{cvers, txid})
	}
}

func (les *lsigEvalSubcache) size() int {
	if les == nil || len(les.entries) == 0 {
		return 0
	}
	sum := 0
	for _, byvers := range les.entries {
		sum += len(byvers)
	}
	return sum
}

func (les *lsigEvalSubcache) roundCheck(round basics.Round, timestamp int64) {
	if les == nil {
		return
	}
	byTimestamp, ok := les.byFirstValid[round]
	if !ok {
		return
	}
	for ts, they := range byTimestamp {
		if ts == timestamp {
			// okay! the actual round timestamp matches the cached round timestamp
			continue
		}
		// this is a cached timestamp that didn't line up with actual line timestamp, invalidate those txid
		for _, bad := range they {
			bytx, ok := les.entries[bad.cvers]
			if ok {
				delete(bytx, bad.txid)
			}
		}
	}
}

type lsigEvalCache struct {
	cur  *lsigEvalSubcache
	prev *lsigEvalSubcache
	size int
}

func newLsigEvalSubcache() *lsigEvalSubcache {
	return &lsigEvalSubcache{
		entries:      make(map[protocol.ConsensusVersion]map[transactions.Txid]error, 2),
		byFirstValid: make(map[basics.Round]map[int64][]cvtx),
	}
}

func makeLsigEvalCache(poolSize int) *lsigEvalCache {
	out := &lsigEvalCache{
		cur:  newLsigEvalSubcache(),
		prev: nil,
		size: poolSize,
	}
	return out
}

func (lec *lsigEvalCache) get(cvers protocol.ConsensusVersion, txid transactions.Txid) (found bool, err error) {
	found, err = lec.cur.get(cvers, txid)
	if found {
		return
	}
	return lec.prev.get(cvers, txid)
}

func (lec *lsigEvalCache) put(cvers protocol.ConsensusVersion, txid transactions.Txid, firstValid basics.Round, firstValidTimestamp int64, err error) {
	lec.cur.put(cvers, txid, firstValid, firstValidTimestamp, err, lec.size)
	if lec.cur.size() > lec.size {
		lec.prev = lec.cur
		lec.cur = newLsigEvalSubcache()
	}
}

func (lec *lsigEvalCache) roundCheck(round basics.Round, timestamp int64) {
	lec.cur.roundCheck(round, timestamp)
	lec.prev.roundCheck(round, timestamp)
}
