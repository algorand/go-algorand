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

package data

import (
	"context"
	"encoding/binary"
	"math"
	"sync"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-deadlock"

	"golang.org/x/crypto/blake2b"
)

// digestCache is a rotating cache of size N accepting crypto.Digest as a key
// and keeping up to 2*N elements in memory
type digestCache struct {
	cur  map[crypto.Digest]struct{}
	prev map[crypto.Digest]struct{}

	maxSize int
	mu      deadlock.RWMutex
}

func makeDigestCache(size int) *digestCache {
	c := &digestCache{
		cur:     map[crypto.Digest]struct{}{},
		maxSize: size,
	}
	return c
}

// check if digest d is in a cache.
// locking semantic: write lock must be taken
func (c *digestCache) check(d *crypto.Digest) bool {
	_, found := c.cur[*d]
	if !found {
		_, found = c.prev[*d]
	}
	return found
}

// swap rotates cache pages.
// locking semantic: write lock must be taken
func (c *digestCache) swap() {
	c.prev = c.cur
	c.cur = map[crypto.Digest]struct{}{}
}

// put adds digest d into a cache.
// locking semantic: write lock must be taken
func (c *digestCache) put(d *crypto.Digest) {
	if len(c.cur) >= c.maxSize {
		c.swap()
	}
	c.cur[*d] = struct{}{}
}

// CheckAndPut adds digest d into a cache if not found
func (c *digestCache) CheckAndPut(d *crypto.Digest) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.check(d) {
		return true
	}
	c.put(d)
	return false
}

// Len returns size of a cache
func (c *digestCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.cur) + len(c.prev)
}

// Delete from the cache
func (c *digestCache) Delete(d *crypto.Digest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cur, *d)
	delete(c.prev, *d)
}

// txSaltedCache is a cache with a rotating salt
// uses blake2b hash function, and stores set of values per each entry
type txSaltedCache struct {
	cur  map[crypto.Digest]*sync.Map
	prev map[crypto.Digest]*sync.Map

	maxSize int
	mu      deadlock.RWMutex

	curSalt  [4]byte
	prevSalt [4]byte
	ctx      context.Context
	wg       sync.WaitGroup
}

func makeSaltedCache(size int) *txSaltedCache {
	return &txSaltedCache{
		cur:     map[crypto.Digest]*sync.Map{},
		maxSize: size,
	}
}

func (c *txSaltedCache) Start(ctx context.Context, refreshInterval time.Duration) {
	c.ctx = ctx
	if refreshInterval != 0 {
		c.wg.Add(1)
		go c.salter(refreshInterval)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.moreSalt()
}

func (c *txSaltedCache) WaitForStop() {
	c.wg.Wait()
}

// salter is a goroutine refreshing the cache by schedule
func (c *txSaltedCache) salter(refreshInterval time.Duration) {
	ticker := time.NewTicker(refreshInterval)
	defer c.wg.Done()
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.Remix()
		case <-c.ctx.Done():
			return
		}
	}
}

// moreSalt updates salt value used for hashing
func (c *txSaltedCache) moreSalt() {
	r := uint32(crypto.RandUint64() % math.MaxUint32)
	binary.LittleEndian.PutUint32(c.curSalt[:], r)
}

// Remix is a locked version of innerSwap, called on schedule
func (c *txSaltedCache) Remix() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.innerSwap()
}

// innerSwap rotates cache pages and update the salt used.
// locking semantic: write lock must be held
func (c *txSaltedCache) innerSwap() {
	c.prevSalt = c.curSalt
	c.prev = c.cur

	// the prev size is a good estimation of a current load
	c.cur = make(map[crypto.Digest]*sync.Map, len(c.prev))
	c.moreSalt()
}

// innerCheck returns true if exists, the salted hash if does not exist
// locking semantic: read lock must be held
func (c *txSaltedCache) innerCheck(msg []byte) (*crypto.Digest, *sync.Map, *map[crypto.Digest]*sync.Map, bool) {
	ptr := saltedPool.Get()
	defer saltedPool.Put(ptr)

	buf := ptr.([]byte)
	toBeHashed := append(buf[:0], msg...)
	toBeHashed = append(toBeHashed, c.curSalt[:]...)
	toBeHashed = toBeHashed[:len(msg)+len(c.curSalt)]

	d := crypto.Digest(blake2b.Sum256(toBeHashed))

	v, found := c.cur[d]
	if found {
		return &d, v, &c.cur, true
	}

	toBeHashed = append(toBeHashed[:len(msg)], c.prevSalt[:]...)
	toBeHashed = toBeHashed[:len(msg)+len(c.prevSalt)]
	pd := crypto.Digest(blake2b.Sum256(toBeHashed))
	v, found = c.prev[pd]
	if found {
		return &pd, v, &c.prev, true
	}
	return &d, nil, nil, false
}

// CheckAndPut adds (msg, sender) pair into a cache. The sender is appended into values if msg is already in the cache.
// Returns a hashing key used for insertion and its associated map of values. The boolean flag `found` is false if the msg not in the cache.
func (c *txSaltedCache) CheckAndPut(msg []byte, sender network.Peer) (d *crypto.Digest, vals *sync.Map, found bool) {
	c.mu.RLock()
	d, vals, _, found = c.innerCheck(msg)
	salt := c.curSalt
	c.mu.RUnlock()
	// fast read-only path: assuming most messages are duplicates, hash msg and check cache
	// keep lock - it is needed for copying vals in defer
	senderFound := false
	if found {
		if _, senderFound = vals.Load(sender); !senderFound {
			vals.Store(sender, struct{}{})
		}
		return d, vals, true
	}

	// not found: acquire write lock to add this msg hash to cache
	c.mu.Lock()
	// salt may have changed between RUnlock() and Lock(), rehash if needed
	if salt != c.curSalt {
		d, vals, _, found = c.innerCheck(msg)
		if found {
			c.mu.Unlock()
			if _, senderFound = vals.Load(sender); !senderFound {
				vals.Store(sender, struct{}{})
			}
			return d, vals, true
		}
	} else { // not found or found in cur page
		// Do another check to see if another copy of the transaction won the race to write it to the cache
		// Only check current to save a lookup since swap is handled in the first branch
		vals, found = c.cur[*d]
		if found {
			c.mu.Unlock()
			if _, senderFound = vals.Load(sender); !senderFound {
				vals.Store(sender, struct{}{})
			}
			return d, vals, true
		}
	}
	defer c.mu.Unlock()

	if len(c.cur) >= c.maxSize {
		c.innerSwap()
		ptr := saltedPool.Get()
		defer saltedPool.Put(ptr)

		buf := ptr.([]byte)
		toBeHashed := append(buf[:0], msg...)
		toBeHashed = append(toBeHashed, c.curSalt[:]...)
		toBeHashed = toBeHashed[:len(msg)+len(c.curSalt)]

		dn := crypto.Digest(blake2b.Sum256(toBeHashed))
		d = &dn
	}

	vals = &sync.Map{}
	vals.Store(sender, struct{}{})
	c.cur[*d] = vals
	return d, vals, false
}

// DeleteByKey from the cache by using a key used for insertion
func (c *txSaltedCache) DeleteByKey(d *crypto.Digest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cur, *d)
	delete(c.prev, *d)
}

// Len returns size of a cache
func (c *txSaltedCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.cur) + len(c.prev)
}

var saltedPool = sync.Pool{
	New: func() interface{} {
		// 2 x MaxAvailableAppProgramLen that covers
		// max approve + clear state programs with max args for app create txn.
		// other transactions are much smaller.
		return make([]byte, 2*config.MaxAvailableAppProgramLen)
	},
}
