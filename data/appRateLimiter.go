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
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"

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
	apps map[basics.AppIndex]*appRateLimiterEntry
}

func MakeAppRateLimiter(maxSize uint64, serviceRate uint64, serviceRateWindow time.Duration) *appRateLimiter {
	return &appRateLimiter{
		maxSize:           maxSize,
		serviceRate:       serviceRate,
		serviceRateWindow: serviceRateWindow,
		apps:              map[basics.AppIndex]*appRateLimiterEntry{},
	}
}

type appRateLimiterEntry struct {
	prev     atomic.Uint64
	cur      atomic.Uint64
	interval int64 // numeric representation of the current interval value
}

func (r *appRateLimiter) entry(appIdx basics.AppIndex) (*appRateLimiterEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.apps[appIdx]
	if !ok {
		entry = &appRateLimiterEntry{}
		r.apps[appIdx] = entry
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
func (r *appRateLimiter) shouldDrop(txgroup []transactions.SignedTxn) bool {
	return r.shouldDropInner(txgroup, time.Now())
}

func (r *appRateLimiter) shouldDropInner(txgroup []transactions.SignedTxn, now time.Time) bool {
	var apps []basics.AppIndex
	for i := range txgroup {
		if txgroup[i].Txn.Type == protocol.ApplicationCallTx {
			apps = append(apps, txgroup[i].Txn.ApplicationID)
			// TODO: enable? this could allow apps censoring
			// if len(txgroup[i].Txn.ForeignApps) > 0 {
			// 	apps = append(apps, txgroup[i].Txn.ForeignApps...)
			// }
		}
	}
	if len(apps) == 0 {
		return false
	}

	curInt := r.interval(now)

	for _, appIdx := range apps {
		entry, has := r.entry(appIdx)
		if !has {
			// new entry, fill defaults and continue
			entry.interval = curInt
			entry.cur.Store(1)
			continue
		}

		if entry.interval != curInt {
			var val uint64 = 0
			if entry.interval == curInt-1 {
				// there are continuous intervals, use the previous value
				val = entry.cur.Load()
			} else {
				// no data for the previous interval, reset
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
