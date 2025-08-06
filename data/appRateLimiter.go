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
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-deadlock"
	"golang.org/x/crypto/blake2b"
)

const numBuckets = 128

type keyType [8]byte

// appRateLimiter implements a sliding window counter rate limiter for applications.
// It is a sharded map with numBuckets of maps each protected by its own mutex.
// Bucket is selected by hashing the application index with a seed (see memhash64).
// LRU is used to evict entries from each bucket, and "last use" is updated on each attempt, not admission.
// This is mostly done to simplify the implementation and does not look affecting the correctness.
type appRateLimiter struct {
	maxBucketSize        int
	serviceRatePerWindow uint64
	serviceRateWindow    time.Duration

	// seed for hashing application index to bucket
	seed uint64
	// salt for hashing application index + origin address
	salt [16]byte

	buckets [numBuckets]appRateLimiterBucket

	// evictions
	// TODO: delete?
	evictions    uint64
	evictionTime uint64
}

type appRateLimiterBucket struct {
	entries map[keyType]*appRateLimiterEntry
	lru     *util.List[keyType]
	mu      deadlock.RWMutex // mutex protects both map and the list access
}

type appRateLimiterEntry struct {
	prev       atomic.Int64
	cur        atomic.Int64
	interval   int64 // numeric representation of the current interval value
	lruElement *util.ListNode[keyType]
}

// makeAppRateLimiter creates a new appRateLimiter from the parameters:
// maxCacheSize is the maximum number of entries to keep in the cache to keep it memory bounded
// maxAppPeerRate is the maximum number of admitted apps per peer per second
// serviceRateWindow is the service window
func makeAppRateLimiter(maxCacheSize int, maxAppPeerRate uint64, serviceRateWindow time.Duration) *appRateLimiter {
	// convert target per app rate to per window service rate
	serviceRatePerWindow := maxAppPeerRate * uint64(serviceRateWindow/time.Second)
	maxBucketSize := maxCacheSize / numBuckets
	if maxBucketSize == 0 {
		// got the max size less then buckets, use maps of 2 to avoid eviction on each insert
		maxBucketSize = 2
	}
	r := &appRateLimiter{
		maxBucketSize:        maxBucketSize,
		serviceRatePerWindow: serviceRatePerWindow,
		serviceRateWindow:    serviceRateWindow,
		seed:                 crypto.RandUint64(),
	}
	crypto.RandBytes(r.salt[:])

	for i := 0; i < numBuckets; i++ {
		r.buckets[i] = appRateLimiterBucket{entries: make(map[keyType]*appRateLimiterEntry), lru: util.NewList[keyType]()}
	}
	return r
}

func (r *appRateLimiter) entry(b *appRateLimiterBucket, key keyType, curInt int64) (*appRateLimiterEntry, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.entries) >= r.maxBucketSize {
		// evict the oldest entry
		start := time.Now()

		el := b.lru.Back()
		delete(b.entries, el.Value)
		b.lru.Remove(el)

		atomic.AddUint64(&r.evictions, 1)
		atomic.AddUint64(&r.evictionTime, uint64(time.Since(start)))
	}

	entry, ok := b.entries[key]
	if ok {
		el := entry.lruElement
		// note, the entry is marked as recently used even before the rate limiting decision
		// since it does not make sense to evict keys that are actively attempted
		b.lru.MoveToFront(el)

		// the same logic is applicable to the intervals: if a new interval is started, update the entry
		// by moving the current value to the previous and resetting the current.
		// this is done under a lock so that the interval is not updated concurrently.
		// The rationale is even this requests is going to be dropped the new interval already started
		// and it is OK to start a new interval and have it prepared for upcoming requests
		var newPrev int64 = 0
		switch entry.interval {
		case curInt:
			// the interval is the same, do nothing
		case curInt - 1:
			// these are continuous intervals, use current value as a new previous
			newPrev = entry.cur.Load()
			fallthrough
		default:
			// non-contiguous intervals, reset the entry
			entry.prev.Store(newPrev)
			entry.cur.Store(0)
			entry.interval = curInt
		}
	} else {
		el := b.lru.PushFront(key)
		entry = &appRateLimiterEntry{interval: curInt, lruElement: el}
		b.entries[key] = entry
	}
	return entry, ok
}

// interval calculates the interval numeric representation based on the given time
func (r *appRateLimiter) interval(nowNano int64) int64 {
	return nowNano / int64(r.serviceRateWindow)
}

// fraction calculates the fraction of the interval that is elapsed since the given time
func (r *appRateLimiter) fraction(nowNano int64) float64 {
	return float64(nowNano%int64(r.serviceRateWindow)) / float64(r.serviceRateWindow)
}

// shouldDrop returns true if the given transaction group should be dropped based on the
// on the rate for the applications in the group: the entire group is dropped if a single application
// exceeds the rate.
func (r *appRateLimiter) shouldDrop(txgroup []transactions.SignedTxn, origin []byte) bool {
	return r.shouldDropAt(txgroup, origin, time.Now().UnixNano())
}

// shouldDropAt is the same as shouldDrop but accepts the current time as a parameter
// in order to make it testable
func (r *appRateLimiter) shouldDropAt(txgroup []transactions.SignedTxn, origin []byte, nowNano int64) bool {
	keysBuckets := txgroupToKeys(txgroup, origin, r.seed, r.salt, numBuckets)
	defer putAppKeyBuf(keysBuckets)
	if len(keysBuckets.keys) == 0 {
		return false
	}
	return r.shouldDropKeys(keysBuckets.buckets, keysBuckets.keys, nowNano)
}

func (r *appRateLimiter) shouldDropKeys(buckets []int, keys []keyType, nowNano int64) bool {
	curInt := r.interval(nowNano)
	curFraction := r.fraction(nowNano)

	for i, key := range keys {
		// TODO: reuse last entry for matched keys and buckets?
		b := buckets[i]
		entry, has := r.entry(&r.buckets[b], key, curInt)
		if !has {
			// new entry, defaults are provided by entry() function
			// admit and increment
			entry.cur.Add(1)
			continue
		}

		rate := int64(float64(entry.prev.Load())*(1-curFraction)) + entry.cur.Load() + 1
		if rate > int64(r.serviceRatePerWindow) {
			return true
		}
		entry.cur.Add(1)
	}

	return false
}

func (r *appRateLimiter) len() int {
	var count int
	for i := 0; i < numBuckets; i++ {
		r.buckets[i].mu.RLock()
		count += len(r.buckets[i].entries)
		r.buckets[i].mu.RUnlock()
	}
	return count
}

var appKeyPool = sync.Pool{
	New: func() interface{} {
		return &appKeyBuf{
			// max bounds.MaxTxGroupSize apps per txgroup, each app has up to MaxAppTxnForeignApps extra foreign apps
			// at moment of writing bounds.MaxTxGroupSize = 16, bounds.MaxAppTxnForeignApps = 8
			keys:    make([]keyType, 0, bounds.MaxTxGroupSize*(1+bounds.MaxAppTxnForeignApps)),
			buckets: make([]int, 0, bounds.MaxTxGroupSize*(1+bounds.MaxAppTxnForeignApps)),
		}
	},
}

// appKeyBuf is a reusable storage for key and bucket slices
type appKeyBuf struct {
	keys    []keyType
	buckets []int
}

func getAppKeyBuf() *appKeyBuf {
	buf := appKeyPool.Get().(*appKeyBuf)
	buf.buckets = buf.buckets[:0]
	buf.keys = buf.keys[:0]
	return buf
}

func putAppKeyBuf(buf *appKeyBuf) {
	appKeyPool.Put(buf)
}

// txgroupToKeys converts txgroup data to keys
func txgroupToKeys(txgroup []transactions.SignedTxn, origin []byte, seed uint64, salt [16]byte, numBuckets int) *appKeyBuf {
	keysBuckets := getAppKeyBuf()
	// since blake2 is a crypto hash function it seems OK to shrink 32 bytes digest down to 8.
	// Rationale: we expect thousands of apps sent from thousands of peers,
	// so required millions of unique pairs => 8 bytes should be enough.
	// The 16 bytes salt makes it harder to find collisions if an adversary attempts to censor
	// some app by finding a collision with some app and flood a network with such transactions:
	// h(app + relay_ip) = h(app2 + relay_ip).

	// uint64 + 16 bytes of salt + up to 16 bytes of address
	// salt and origin are fixed so pre-copy them into the buf
	var buf [8 + 16 + 16]byte
	copy(buf[8:], salt[:])
	copied := copy(buf[8+16:], origin)
	bufLen := 8 + 16 + copied

	txnToDigest := func(appIdx basics.AppIndex) (key keyType) {
		binary.LittleEndian.PutUint64(buf[:8], uint64(appIdx))
		h := blake2b.Sum256(buf[:bufLen])
		copy(key[:], h[:len(keyType{})])
		return
	}
	txnToBucket := func(appIdx basics.AppIndex) int {
		return int(memhash64(uint64(appIdx), seed) % uint64(numBuckets))
	}
	seen := make(map[basics.AppIndex]struct{}, len(txgroup)*(1+bounds.MaxAppTxnForeignApps))
	valid := func(appIdx basics.AppIndex) bool {
		if appIdx != 0 {
			_, ok := seen[appIdx]
			return !ok
		}
		return false
	}
	for i := range txgroup {
		if txgroup[i].Txn.Type == protocol.ApplicationCallTx {
			appIdx := txgroup[i].Txn.ApplicationID
			if valid(appIdx) {
				keysBuckets.buckets = append(keysBuckets.buckets, txnToBucket(appIdx))
				keysBuckets.keys = append(keysBuckets.keys, txnToDigest(appIdx))
				seen[appIdx] = struct{}{}
			}
			// hash appIdx into a bucket, do not use modulo without hashing first since it could
			// assign two vanilla (and presumable, popular) apps to the same bucket.
			if len(txgroup[i].Txn.ForeignApps) > 0 {
				for _, appIdx := range txgroup[i].Txn.ForeignApps {
					if valid(appIdx) {
						keysBuckets.buckets = append(keysBuckets.buckets, txnToBucket(appIdx))
						keysBuckets.keys = append(keysBuckets.keys, txnToDigest(appIdx))
						seen[appIdx] = struct{}{}
					}
				}
			}
		}
	}
	return keysBuckets
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
