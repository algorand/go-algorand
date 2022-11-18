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
	"context"
	"encoding/binary"
	"math"
	"sync"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-deadlock"

	"golang.org/x/crypto/blake2b"
)

// digestCache is a rotating cache of size N accepting crypto.Digest as a key
// and keeping up to 2*N elements in memory
type digestCache struct {
	cur  map[crypto.Digest]struct{}
	prev map[crypto.Digest]struct{}

	maxSize int
	mu      deadlock.Mutex
}

func makeDigestCache(size int) *digestCache {
	c := &digestCache{
		cur:     map[crypto.Digest]struct{}{},
		maxSize: size,
	}
	return c
}

func (c *digestCache) check(d *crypto.Digest) bool {
	_, found := c.cur[*d]
	if !found {
		_, found = c.prev[*d]
	}
	return found
}

func (c *digestCache) swap() {
	c.prev = c.cur
	c.cur = map[crypto.Digest]struct{}{}
}

func (c *digestCache) put(d *crypto.Digest) {
	if len(c.cur) >= c.maxSize {
		c.swap()
	}
	c.cur[*d] = struct{}{}
}

func (c *digestCache) checkAndPut(d *crypto.Digest) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.check(d) {
		return true
	}
	c.put(d)
	return false
}

func (c *digestCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.cur) + len(c.prev)
}

// txSaltedCache is a digest cache with a rotating salt
// uses blake2b hash function
type txSaltedCache struct {
	digestCache

	curSalt  [4]byte
	prevSalt [4]byte
	ctx      context.Context
}

func makeSaltedCache(ctx context.Context, size int, refreshIntervalSec time.Duration) *txSaltedCache {
	c := &txSaltedCache{
		digestCache: digestCache{
			cur:     map[crypto.Digest]struct{}{},
			maxSize: size,
		},
		ctx: ctx,
	}

	if refreshIntervalSec != 0 {
		go c.salter(refreshIntervalSec)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.moreSalt()

	return c
}

func (c *txSaltedCache) salter(refreshSecs time.Duration) {
	timer := time.NewTimer(refreshSecs)
	for {
		select {
		case <-timer.C:
			c.remix()
		case <-c.ctx.Done():
			timer.Stop()
			return
		}
	}
}

func (c *txSaltedCache) moreSalt() {
	r := uint32(crypto.RandUint64() % math.MaxUint32)
	binary.LittleEndian.PutUint32(c.curSalt[:], r)
}

// remix is a locked version of swap, called on schedule
func (c *txSaltedCache) remix() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.swap()
}

// swap cache maps and update the salt used
func (c *txSaltedCache) swap() {
	c.prevSalt = c.curSalt
	c.prev = c.cur

	c.cur = map[crypto.Digest]struct{}{}
	c.moreSalt()
}

func (c *txSaltedCache) check(msg []byte) bool {
	found, _ := c.innerCheck(msg)
	return found
}

// innerCheck returns true if exists, and the current salted hash if does not
func (c *txSaltedCache) innerCheck(msg []byte) (bool, *crypto.Digest) {
	ptr := saltedPool.Get()
	defer saltedPool.Put(ptr)

	buf := ptr.([]byte)
	toBeHashed := append(buf[:0], msg...)
	toBeHashed = append(toBeHashed, c.curSalt[:]...)
	toBeHashed = toBeHashed[:len(msg)+len(c.curSalt)]

	d := crypto.Digest(blake2b.Sum256(toBeHashed))

	_, found := c.cur[d]
	if found {
		return true, nil
	}

	toBeHashed = append(toBeHashed[:len(msg)], c.prevSalt[:]...)
	toBeHashed = toBeHashed[:len(msg)+len(c.prevSalt)]
	pd := crypto.Digest(blake2b.Sum256(toBeHashed))
	_, found = c.prev[pd]
	if found {
		return true, nil
	}
	return false, &d
}

func (c *txSaltedCache) checkAndPut(msg []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	found, d := c.innerCheck(msg)
	if found {
		return true
	}

	c.put(d)
	return false
}

var saltedPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4*4096) // should be enough for most of transactions
	},
}
