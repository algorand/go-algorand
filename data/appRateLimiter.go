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
	maxSize           uint64
	serviceRate       uint64
	serviceRateWindow time.Duration

	// TODO: consider some kind of concurrent map
	// TODO: add expiration strategy
	mu   deadlock.RWMutex
	apps map[crypto.Digest]*appRateLimiterEntry
}

func makeAppRateLimiter(maxSize uint64, serviceRate uint64, serviceRateWindow time.Duration) *appRateLimiter {
	return &appRateLimiter{
		maxSize:           maxSize,
		serviceRate:       serviceRate,
		serviceRateWindow: serviceRateWindow,
		apps:              map[crypto.Digest]*appRateLimiterEntry{},
	}
}

type appRateLimiterEntry struct {
	prev     atomic.Uint64
	cur      atomic.Uint64
	interval int64 // numeric representation of the current interval value
}

func (r *appRateLimiter) entry(key crypto.Digest, curInt int64) (*appRateLimiterEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.apps) >= int(r.maxSize) {
		// evict the oldest entry
		// TODO: evict 10% oldest entries?
		var oldestKey crypto.Digest
		var oldestInterval int64 = math.MaxInt64
		for k, v := range r.apps {
			if v.interval < oldestInterval {
				oldestKey = k
				oldestInterval = v.interval
			}
		}
		delete(r.apps, oldestKey)
	}

	entry, ok := r.apps[key]
	if !ok {
		entry = &appRateLimiterEntry{interval: curInt}
		entry.cur.Store(1)
		r.apps[key] = entry
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
	keys := txgroupToKeys(txgroup, origin)
	if len(keys) == 0 {
		return false
	}
	return r.shouldDropKeys(keys, now)
}

func (r *appRateLimiter) shouldDropKeys(keys []crypto.Digest, now time.Time) bool {
	curInt := r.interval(now)

	for _, key := range keys {
		entry, has := r.entry(key, curInt)
		if !has {
			// new entry, fill defaults and continue
			// entry.interval = curInt
			// entry.cur.Store(1)
			continue
		}

		if entry.interval != curInt {
			var val uint64 = 0
			if entry.interval == curInt-1 {
				// there are continuous intervals, use the previous value
				val = entry.cur.Load()
			}
			entry.prev.Store(val)
			entry.interval = curInt
			entry.cur.Store(1)
		} else {
			entry.cur.Add(1)
		}

		curFraction := r.fraction(now)
		rate := uint64(float64(entry.prev.Load())*(1-curFraction)) + entry.cur.Load()

		if rate > r.serviceRate {
			return true
		}
	}

	return false
}

// txgroupToKeys converts txgroup data to keys
func txgroupToKeys(txgroup []transactions.SignedTxn, origin []byte) []crypto.Digest {
	var keys []crypto.Digest
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
			keys = append(keys, txnToDigest(txgroup[i].Txn.ApplicationID))
			if len(txgroup[i].Txn.ForeignApps) > 0 {
				for _, appIdx := range txgroup[i].Txn.ForeignApps {
					keys = append(keys, txnToDigest(appIdx))
				}
			}
		}
	}
	return keys
}