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
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

type lsigEvalSubcache struct {
	they map[protocol.ConsensusVersion]map[transactions.Txid]error
}

func (les *lsigEvalSubcache) get(cvers protocol.ConsensusVersion, txid transactions.Txid) (err error, found bool) {
	if les == nil || les.they == nil {
		found = false
		err = nil
		return
	}
	var byvers map[transactions.Txid]error
	byvers, found = les.they[cvers]
	if !found {
		return
	}
	err, found = byvers[txid]
	return
}

func (les *lsigEvalSubcache) put(cvers protocol.ConsensusVersion, txid transactions.Txid, err error, size int) {
	if les.they == nil {
		les.they = make(map[protocol.ConsensusVersion]map[transactions.Txid]error, 2)
	}
	//var byvers map[transactions.Txid]error
	byvers, found := les.they[cvers]
	if !found {
		byvers = make(map[transactions.Txid]error, size)
		les.they[cvers] = byvers
	}
	byvers[txid] = err
}

func (les *lsigEvalSubcache) size() int {
	sum := 0
	for _, byvers := range les.they {
		sum += len(byvers)
	}
	return sum
}

type lsigEvalCache struct {
	cur  *lsigEvalSubcache
	prev *lsigEvalSubcache
	size int
}

func makeLsigEvalCache(poolSize int) *lsigEvalCache {
	out := &lsigEvalCache{
		cur:  new(lsigEvalSubcache),
		prev: nil,
		size: poolSize,
	}
	return out
}

func (lec *lsigEvalCache) get(cvers protocol.ConsensusVersion, txid transactions.Txid) (err error, found bool) {
	err, found = lec.cur.get(cvers, txid)
	if found {
		return
	}
	return lec.prev.get(cvers, txid)
}

func (lec *lsigEvalCache) put(cvers protocol.ConsensusVersion, txid transactions.Txid, err error) {
	lec.cur.put(cvers, txid, err, lec.size)
	if lec.cur.size() > lec.size {
		lec.prev = lec.cur
		lec.cur = new(lsigEvalSubcache)
	}
}
