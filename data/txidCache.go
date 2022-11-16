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
	"math"
	"sync"
	"sync/atomic"

	"github.com/algorand/go-algorand/crypto"
)

type txidCache struct {
	cur  map[crypto.Digest]struct{}
	prev map[crypto.Digest]struct{}

	maxSize int
	mu      sync.Mutex
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

type txidCacheSyncMap struct {
	// cur and prev are sync.Map
	cur  atomic.Value
	prev atomic.Value

	maxSize int64
	size    int64
}

func makeTxidCacheSyncMap(size int) *txidCacheSyncMap {
	c := &txidCacheSyncMap{
		maxSize: int64(size),
	}
	c.cur.Store(&sync.Map{})
	c.prev.Store(&sync.Map{})
	return c
}

func (c *txidCacheSyncMap) check(d *crypto.Digest) bool {
	cur := c.cur.Load().(*sync.Map)
	_, found := cur.Load(*d)
	if !found {
		prev := c.prev.Load().(*sync.Map)
		_, found = prev.Load(*d)
	}
	return found
}

func (c *txidCacheSyncMap) put(d *crypto.Digest) {
	cur := c.cur.Load().(*sync.Map)
	if atomic.LoadInt64(&c.size) >= atomic.LoadInt64(&c.maxSize) {
		c.prev.Store(cur)
		cur = &sync.Map{}
		c.cur.Store(cur)
		atomic.StoreInt64(&c.size, 0)
	}

	cur.Store(*d, struct{}{})
	atomic.AddInt64(&c.size, 1)
}

func (c *txidCacheSyncMap) checkAndPut(d *crypto.Digest) bool {
	if c.check(d) {
		return true
	}
	c.put(d)
	return false
}

func (c *txidCacheSyncMap) len() int {
	if atomic.LoadInt64(&c.size) >= math.MaxInt32 || atomic.LoadInt64(&c.maxSize) >= math.MaxInt32 {
		return math.MaxInt32
	}
	prev := c.prev.Load().(*sync.Map)
	prevSize := 0
	prev.Range(func(key, value interface{}) bool {
		prevSize++
		return true
	})
	return int(atomic.LoadInt64(&c.size)) + prevSize
}
