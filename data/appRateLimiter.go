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
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"golang.org/x/crypto/blake2b"

	"github.com/algorand/go-deadlock"
)

const numBuckets = 128

type keyType [8]byte

// appRateLimiter implements a sliding window counter rate limiter for applications.
// It is a shared map with numBuckets of maps each protected by its own mutex.
// Bucket is selected by hashing the application index with a seed (see memhash64).
type appRateLimiter struct {
	maxBucketSize        uint64
	serviceRatePerWindow uint64
	serviceRateWindow    time.Duration

	// seed for hashing application index to bucket
	seed uint64
	// salt for hashing application index + origin address
	salt [16]byte

	buckets [numBuckets]map[keyType]*appRateLimiterEntry
	mus     [numBuckets]deadlock.RWMutex
	lrus    [numBuckets]*util.List[keyType]

	// evictions
	// TODO: delete
	evictions    uint64
	evictionTime uint64
}

type appRateLimiterEntry struct {
	prev       atomic.Uint64
	cur        atomic.Uint64
	interval   atomic.Int64 // numeric representation of the current interval value
	lruElement *util.ListNode[keyType]
}

// makeAppRateLimiter creates a new appRateLimiter from the parameters:
// maxCacheSize is the maximum number of entries to keep in the cache to keep it memory bounded
// maxAppPeerRate is the maximum number of admitted apps per peer per second
// serviceRateWindow is the service window
func makeAppRateLimiter(maxCacheSize uint64, maxAppPeerRate uint64, serviceRateWindow time.Duration) *appRateLimiter {
	// convert target per app rate to per window service rate
	serviceRatePerWindow := maxAppPeerRate * uint64(serviceRateWindow/time.Second)
	maxBucketSize := maxCacheSize / numBuckets
	if maxBucketSize == 0 {
		// got the max size less then buckets, use maps of 1
		maxBucketSize = 1
	}
	r := &appRateLimiter{
		maxBucketSize:        maxBucketSize,
		serviceRatePerWindow: serviceRatePerWindow,
		serviceRateWindow:    serviceRateWindow,
		seed:                 crypto.RandUint64(),
	}
	crypto.RandBytes(r.salt[:])

	for i := 0; i < numBuckets; i++ {
		r.buckets[i] = make(map[keyType]*appRateLimiterEntry)
		r.lrus[i] = util.NewList[keyType]().AllocateFreeNodes(int(maxBucketSize))
	}
	return r
}

func (r *appRateLimiter) entry(b int, key keyType, curInt int64) (*appRateLimiterEntry, bool) {
	r.mus[b].Lock()
	defer r.mus[b].Unlock()

	if len(r.buckets[b]) >= int(r.maxBucketSize) {
		// evict the oldest entry
		start := time.Now()
		atomic.AddUint64(&r.evictions, 1)

		el := r.lrus[b].Back()
		delete(r.buckets[b], el.Value)
		r.lrus[b].Remove(el)

		atomic.AddUint64(&r.evictionTime, uint64(time.Since(start)))
	}

	entry, ok := r.buckets[b][key]
	if ok {
		el := entry.lruElement
		r.lrus[b].MoveToFront(el)
	} else {
		el := r.lrus[b].PushFront(key)
		entry = &appRateLimiterEntry{lruElement: el}
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
	buckets, keys := txgroupToKeys(txgroup, origin, r.seed, r.salt, numBuckets)
	if len(keys) == 0 {
		return false
	}
	return r.shouldDropKeys(buckets, keys, now)
}

func (r *appRateLimiter) shouldDropKeys(buckets []int, keys []keyType, now time.Time) bool {
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
func txgroupToKeys(txgroup []transactions.SignedTxn, origin []byte, seed uint64, salt [16]byte, numBuckets int) ([]int, []keyType) {
	// there are max 16 * 8 = 128 apps (buckets, keys) per txgroup
	// TODO: consider sync.Pool

	var keys []keyType
	var buckets []int
	// since blake2 is a crypto hash function it seems OK to shrink 32 bytes digest down to 8.
	// Rationale: we expect thousands of apps sent from thousands of peers,
	// so required millions of unique pairs => 8 bytes should be enough.
	// The 16 bytes salt makes it harder to find collisions if an adversary attempts to censor
	// some app by finding a collision with some app and flood a network with such transactions:
	// h(app + relay_ip) = h(app2 + relay_ip).
	var buf [8 + 16 + 16]byte // uint64 + 16 bytes of salt + up to 16 bytes of address
	txnToDigest := func(appIdx basics.AppIndex) keyType {
		binary.LittleEndian.PutUint64(buf[:8], uint64(appIdx))
		copy(buf[8:], salt[:])
		copied := copy(buf[8+16:], origin)

		h := blake2b.Sum256(buf[:8+16+copied])
		var key keyType
		copy(key[:], h[:len(key)])
		return key
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
