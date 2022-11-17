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

package data

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-deadlock"
)

type txidCache struct {
	cur  map[crypto.Digest]struct{}
	prev map[crypto.Digest]struct{}

	maxSize int
	mu      deadlock.Mutex
}

func makeTxidCache(size int) *txidCache {
	c := &txidCache{
		cur:     map[crypto.Digest]struct{}{},
		prev:    map[crypto.Digest]struct{}{},
		maxSize: size,
	}
	return c
}

func (c *txidCache) check(d *crypto.Digest) bool {
	_, found := c.cur[*d]
	if !found {
		_, found = c.prev[*d]
	}
	return found
}

func (c *txidCache) put(d *crypto.Digest) {
	if len(c.cur) >= c.maxSize {
		c.prev = c.cur
		c.cur = map[crypto.Digest]struct{}{}
	}

	c.cur[*d] = struct{}{}
}

func (c *txidCache) checkAndPut(d *crypto.Digest) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.check(d) {
		return true
	}
	c.put(d)
	return false
}

func (c *txidCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.cur) + len(c.prev)
}
