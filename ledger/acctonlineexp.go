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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-deadlock"
)

type expiredCirculationCache struct {
	cur  map[expiredCirculationKey]basics.MicroAlgos
	prev map[expiredCirculationKey]basics.MicroAlgos

	maxSize int
	mu      deadlock.RWMutex
}

type expiredCirculationKey struct {
	rnd     basics.Round
	voteRnd basics.Round
}

func makeExpiredCirculationCache(maxSize int) *expiredCirculationCache {
	return &expiredCirculationCache{
		cur:     make(map[expiredCirculationKey]basics.MicroAlgos),
		maxSize: maxSize,
	}
}

func (c *expiredCirculationCache) get(rnd basics.Round, voteRnd basics.Round) (basics.MicroAlgos, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if stake, ok := c.cur[expiredCirculationKey{rnd: rnd, voteRnd: voteRnd}]; ok {
		return stake, true
	}
	if stake, ok := c.prev[expiredCirculationKey{rnd: rnd, voteRnd: voteRnd}]; ok {
		return stake, true
	}

	return basics.MicroAlgos{}, false
}

func (c *expiredCirculationCache) put(rnd basics.Round, voteRnd basics.Round, expiredStake basics.MicroAlgos) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cur) >= c.maxSize {
		c.prev = c.cur
		c.cur = make(map[expiredCirculationKey]basics.MicroAlgos)

	}
	c.cur[expiredCirculationKey{rnd: rnd, voteRnd: voteRnd}] = expiredStake
}
