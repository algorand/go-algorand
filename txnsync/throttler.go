// Copyright (C) 2019-2021 Algorand, Inc.
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

package txnsync

import (
	"time"

	"github.com/algorand/go-algorand/util/timers"
)

// throttler provide a simplistic mechanism for dynamically adjusting the scheduler
// percision granularity by monitoring the moving avarage of the recent n-samples.
type throttler struct {
	clock               timers.WallClock
	startDuration       time.Duration
	history             []time.Duration
	oldestEntryIndex    int
	accumulatedDuration time.Duration
	minWindow           time.Duration
	maxWindow           time.Duration
	currentWindow       time.Duration
}

func makeThrottler(clock timers.WallClock, sampleCount int, minWindow, maxWindow time.Duration) *throttler {
	return &throttler{
		clock:         clock.Zero().(timers.WallClock),
		history:       make([]time.Duration, 0, sampleCount),
		minWindow:     minWindow,
		maxWindow:     maxWindow,
		currentWindow: (minWindow + maxWindow) / 2,
	}
}

func (t *throttler) workStarts() {
	t.startDuration = t.clock.Since()
}

func (t *throttler) workEnds() {
	elapsedWorkTime := t.clock.Since() - t.startDuration

	if len(t.history) < cap(t.history) {
		// if it's not full yet.
		t.history = append(t.history, elapsedWorkTime)
		t.accumulatedDuration += elapsedWorkTime
		return // we don't have enough samples yet, so keep the currentWindow
	}
	// it's already full.
	t.accumulatedDuration += elapsedWorkTime - t.history[t.oldestEntryIndex]
	t.history[t.oldestEntryIndex] = elapsedWorkTime
	t.oldestEntryIndex = (t.oldestEntryIndex + 1) % cap(t.history)

	avgWindow := t.accumulatedDuration / time.Duration(len(t.history))

	// adjust the current window so that it would be half of the effective average work time.
	t.currentWindow = avgWindow / 2
	if t.currentWindow < t.minWindow {
		t.currentWindow = t.minWindow
	} else if t.currentWindow > t.minWindow {
		t.currentWindow = t.maxWindow
	}
}

func (t *throttler) getWindow() time.Duration {
	return t.currentWindow
}

func (t *throttler) getWindowDeadlineMonitor() timers.DeadlineMonitor {
	return t.clock.DeadlineMonitorAt(t.clock.Since() + t.currentWindow)
}
