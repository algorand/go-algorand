// Copyright (C) 2019-2025 Algorand, Inc.
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

	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-deadlock"

	"golang.org/x/crypto/blake2b"
)

// digestCache is a rotating cache of size N accepting crypto.Digest as a key
// and keeping up to 2*maxSize elements in memory
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
// locking semantic: read lock must be taken
func (c *digestCache) check(d crypto.Digest) bool {
	_, found := c.cur[d]
	if !found {
		_, found = c.prev[d]
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
func (c *digestCache) put(d crypto.Digest) {
	if len(c.cur) >= c.maxSize {
		c.swap()
	}
	c.cur[d] = struct{}{}
}

// CheckAndPut adds digest d into a cache if not found
func (c *digestCache) CheckAndPut(d crypto.Digest) bool {
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
func (c *digestCache) Delete(d crypto.Digest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cur, d)
	delete(c.prev, d)
}

// txSaltedCache is a digest cache with a rotating salt
// uses blake2b hash function
type txSaltedCache struct {
	digestCache

	curSalt  [4]byte
	prevSalt [4]byte
	ctx      context.Context
	wg       sync.WaitGroup
}

func makeSaltedCache(size int) *txSaltedCache {
	return &txSaltedCache{
		digestCache: *makeDigestCache(size),
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
	c.innerSwap(true)
}

// innerSwap rotates cache pages and update the salt used.
// locking semantic: write lock must be held
func (c *txSaltedCache) innerSwap(scheduled bool) {
	c.prevSalt = c.curSalt
	c.prev = c.cur

	if scheduled {
		// updating by timer, the prev size is a good estimation of a current load => preallocate
		c.cur = make(map[crypto.Digest]struct{}, len(c.prev))
	} else {
		// otherwise start empty
		c.cur = map[crypto.Digest]struct{}{}
	}
	c.moreSalt()
}

// innerCheck returns true if exists, and the current salted hash if does not.
// locking semantic: READ lock must be held, cache is not mutated
func (c *txSaltedCache) innerCheck(msg []byte) (crypto.Digest, bool) {
	ptr := saltedPool.Get()
	defer saltedPool.Put(ptr)

	buf := ptr.([]byte)
	toBeHashed := append(buf[:0], msg...)
	toBeHashed = append(toBeHashed, c.curSalt[:]...)
	toBeHashed = toBeHashed[:len(msg)+len(c.curSalt)]

	d := crypto.Digest(blake2b.Sum256(toBeHashed))

	_, found := c.cur[d]
	if found {
		return crypto.Digest{}, true
	}

	toBeHashed = append(toBeHashed[:len(msg)], c.prevSalt[:]...)
	toBeHashed = toBeHashed[:len(msg)+len(c.prevSalt)]
	pd := crypto.Digest(blake2b.Sum256(toBeHashed))
	_, found = c.prev[pd]
	if found {
		return crypto.Digest{}, true
	}
	return d, false
}

// CheckAndPut adds msg into a cache if not found
// returns a hashing key used for insertion if the message not found.
func (c *txSaltedCache) CheckAndPut(msg []byte) (crypto.Digest, bool) {
	c.mu.RLock()
	d, found := c.innerCheck(msg)
	salt := c.curSalt
	c.mu.RUnlock()
	// fast read-only path: assuming most messages are duplicates, hash msg and check cache
	if found {
		return d, found
	}

	// not found: acquire write lock to add this msg hash to cache
	c.mu.Lock()
	defer c.mu.Unlock()
	// salt may have changed between RUnlock() and Lock(), rehash if needed
	if salt != c.curSalt {
		d, found = c.innerCheck(msg)
		if found {
			// already added to cache between RUnlock() and Lock(), return
			return d, found
		}
	} else {
		// Do another check to see if another copy of the transaction won the race to write it to the cache
		// Only check current to save a lookup since swaps are rare and no need to re-hash
		if _, found := c.cur[d]; found {
			return d, found
		}
	}

	if len(c.cur) >= c.maxSize {
		c.innerSwap(false)
		ptr := saltedPool.Get()
		defer saltedPool.Put(ptr)

		buf := ptr.([]byte)
		toBeHashed := append(buf[:0], msg...)
		toBeHashed = append(toBeHashed, c.curSalt[:]...)
		toBeHashed = toBeHashed[:len(msg)+len(c.curSalt)]

		d = crypto.Digest(blake2b.Sum256(toBeHashed))
	}

	c.cur[d] = struct{}{}
	return d, false
}

// DeleteByKey from the cache by using a key used for insertion
func (c *txSaltedCache) DeleteByKey(d crypto.Digest) {
	c.digestCache.Delete(d)
}

var saltedPool = sync.Pool{
	New: func() interface{} {
		// 2 x MaxAvailableAppProgramLen that covers
		// max approve + clear state programs with max args for app create txn.
		// other transactions are much smaller.
		return make([]byte, 2*bounds.MaxAvailableAppProgramLen)
	},
}
