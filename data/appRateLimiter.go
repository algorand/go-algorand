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
	"encoding/binary"
	"math"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"golang.org/x/crypto/blake2b"

	"github.com/algorand/go-deadlock"
)

// appRateLimiter implements a sliding window counter rate limiter for applications
type appRateLimiter struct {
	maxSize              uint64
	serviceRatePerWindow uint64
	serviceRateWindow    time.Duration

	seed uint64

	buckets [128]map[crypto.Digest]*appRateLimiterEntry
	mus     [128]deadlock.RWMutex
}

// makeAppRateLimiter creates a new appRateLimiter from the parameters:
// maxCacheSize is the maximum number of entries to keep in the cache to keep it memory bounded
// maxAppPeerRate is the maximum number of admitted apps per peer per second
// serviceRateWindow is the service window
func makeAppRateLimiter(maxCacheSize uint64, maxAppPeerRate uint64, serviceRateWindow time.Duration) *appRateLimiter {
	// convert target per app rate to per window service rate
	serviceRatePerWindow := maxAppPeerRate * uint64(serviceRateWindow/time.Second)
	r := &appRateLimiter{
		maxSize:              maxCacheSize,
		serviceRatePerWindow: serviceRatePerWindow,
		serviceRateWindow:    serviceRateWindow,
		seed:                 crypto.RandUint64(),
	}
	for i := range r.buckets {
		r.buckets[i] = make(map[crypto.Digest]*appRateLimiterEntry)
	}
	return r
}

type appRateLimiterEntry struct {
	prev     atomic.Uint64
	cur      atomic.Uint64
	interval atomic.Int64 // numeric representation of the current interval value
}

func (r *appRateLimiter) entry(b int, key crypto.Digest, curInt int64) (*appRateLimiterEntry, bool) {
	r.mus[b].Lock()
	defer r.mus[b].Unlock()

	if len(r.buckets[b]) >= int(r.maxSize) {
		// evict the oldest entry
		// TODO: evict 10% oldest entries?
		var oldestKey crypto.Digest
		var oldestInterval int64 = math.MaxInt64
		for k, v := range r.buckets[b] {
			interval := v.interval.Load()
			if interval < oldestInterval {
				oldestKey = k
				oldestInterval = interval
			}
		}
		delete(r.buckets[b], oldestKey)
	}

	entry, ok := r.buckets[b][key]
	if !ok {
		entry = &appRateLimiterEntry{}
		entry.cur.Store(1)
		entry.interval.Store(curInt)
		r.buckets[b][key] = entry
	}
	return entry, ok
}

// interval calculates the interval numeric representation based on the given time
func (r *appRateLimiter) interval(now time.Time) int64 {
	return now.UnixNano() / int64(r.serviceRateWindow)
}

// fraction calculates the fraction of the interval that is elapsed since the given time
func (r *appRateLimiter) fraction(now time.Time) float64 {
	return float64(now.UnixNano()%int64(r.serviceRateWindow)) / float64(r.serviceRateWindow)
}

// shouldDrop returns true if the given transaction group should be dropped based on the
// on the rate for the applications in the group: the entire group is dropped if a single application
// exceeds the rate.
func (r *appRateLimiter) shouldDrop(txgroup []transactions.SignedTxn, origin []byte) bool {
	return r.shouldDropInner(txgroup, origin, time.Now())
}

// shouldDropInner is the same as shouldDrop but accepts the current time as a parameter
// in order to make it testable
func (r *appRateLimiter) shouldDropInner(txgroup []transactions.SignedTxn, origin []byte, now time.Time) bool {
	buckets, keys := txgroupToKeys(txgroup, origin, r.seed, len(r.buckets))
	if len(keys) == 0 {
		return false
	}
	return r.shouldDropKeys(buckets, keys, now)
}

func (r *appRateLimiter) shouldDropKeys(buckets []int, keys []crypto.Digest, now time.Time) bool {
	curInt := r.interval(now)

	for i := range keys {
		key := keys[i]
		bucket := buckets[i]
		entry, has := r.entry(bucket, key, curInt)
		if !has {
			// new entry, defaults are provided by entry() function
			continue
		}

		interval := entry.interval.Load()
		if interval != curInt {
			var val uint64 = 0
			if interval == curInt-1 {
				// there are continuous intervals, use the previous value
				val = entry.cur.Load()
			}
			entry.prev.Store(val)
			entry.cur.Store(1)
			entry.interval.Store(curInt)
		} else {
			entry.cur.Add(1)
		}

		curFraction := r.fraction(now)
		rate := uint64(float64(entry.prev.Load())*(1-curFraction)) + entry.cur.Load()

		if rate > r.serviceRatePerWindow {
			return true
		}
	}

	return false
}

// txgroupToKeys converts txgroup data to keys
func txgroupToKeys(txgroup []transactions.SignedTxn, origin []byte, seed uint64, numBuckets int) ([]int, []crypto.Digest) {
	// there are max 16 * 8 = 128 apps (buckets, keys) per txgroup
	// TODO: consider sync.Pool

	var keys []crypto.Digest
	var buckets []int
	// TODO: since blake2 is a crypto hash function it seems OK to shrink 32 bytes digest to
	// 16 or 12 bytes.
	// Rationale: we expect thousands of apps sent from thousands of peers,
	// so required millions of unique pairs => 12 or 16 bytes should be enough.
	txnToDigest := func(appIdx basics.AppIndex) crypto.Digest {
		var buf [8 + 16]byte // uint64 + up to 16 bytes of address
		binary.LittleEndian.PutUint64(buf[:8], uint64(appIdx))
		copied := copy(buf[8:], origin)
		return crypto.Digest(blake2b.Sum256(buf[:8+copied]))
	}
	for i := range txgroup {
		if txgroup[i].Txn.Type == protocol.ApplicationCallTx {
			appIdx := txgroup[i].Txn.ApplicationID
			// hash appIdx into a bucket, do not use modulo since it could
			// assign two vanilla (and presumable, popular) apps to the same bucket.
			buckets = append(buckets, int(memhash64(uint64(appIdx), seed)%uint64(numBuckets)))
			keys = append(keys, txnToDigest(appIdx))
			if len(txgroup[i].Txn.ForeignApps) > 0 {
				for _, appIdx := range txgroup[i].Txn.ForeignApps {
					buckets = append(buckets, int(memhash64(uint64(appIdx), seed)%uint64(numBuckets)))
					keys = append(keys, txnToDigest(appIdx))
				}
			}
		}
	}
	return buckets, keys
}

const (
	// Constants for multiplication: four random odd 64-bit numbers.
	m1 = 16877499708836156737
	m2 = 2820277070424839065
	m3 = 9497967016996688599
	m4 = 15839092249703872147
)

// memhash64 is uint64 hash function from go runtime
// https://go-review.googlesource.com/c/go/+/59352/4/src/runtime/hash64.go#96
func memhash64(val uint64, seed uint64) uint64 {
	h := seed
	h ^= val
	h = rotl31(h*m1) * m2
	h ^= h >> 29
	h *= m3
	h ^= h >> 32
	return h
}

func rotl31(x uint64) uint64 {
	return (x << 31) | (x >> (64 - 31))
}
