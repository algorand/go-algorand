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
	"sort"
	"time"

	//"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/util/timers"
)

// guidedClock implements the WallClock interface
type guidedClock struct {
	zero     time.Time
	adv      time.Duration
	timers   map[time.Duration]chan time.Time
	children []*guidedClock
	lockCh   chan struct{}
}

func makeGuidedClock() *guidedClock {
	return &guidedClock{
		zero:   time.Now(),
		lockCh: make(chan struct{}, 1),
	}
}
func (g *guidedClock) Zero() timers.Clock {
	// the real monotonic clock doesn't return the same clock object, which is fine.. but for our testing
	// we want to keep the same clock object so that we can tweak with it.
	child := &guidedClock{
		zero:   g.zero.Add(g.adv),
		lockCh: make(chan struct{}, 1),
	}
	g.lock()
	defer g.unlock()
	g.children = append(g.children, child)
	return child
}

func (g *guidedClock) TimeoutAt(delta time.Duration) <-chan time.Time {
	if delta <= g.adv {
		c := make(chan time.Time, 1)
		close(c)
		return c
	}
	g.lock()
	defer g.unlock()
	if g.timers == nil {
		g.timers = make(map[time.Duration]chan time.Time)
	}
	c, has := g.timers[delta]
	if has {
		return c
	}
	c = make(chan time.Time, 1)
	g.timers[delta] = c
	return c
}

func (g *guidedClock) Encode() []byte {
	return []byte{}
}
func (g *guidedClock) Decode([]byte) (timers.Clock, error) {
	return &guidedClock{}, nil
}

func (g *guidedClock) Since() time.Duration {
	return g.adv
}

func (g *guidedClock) DeadlineMonitorAt(at time.Duration) timers.DeadlineMonitor {
	return timers.MakeMonotonicDeadlineMonitor(g, at)
}

func (g *guidedClock) Advance(adv time.Duration) {
	g.adv += adv

	type entryStruct struct {
		duration time.Duration
		ch       chan time.Time
	}
	expiredClocks := []entryStruct{}
	g.lock()
	// find all the expired clocks.
	for delta, ch := range g.timers {
		if delta < g.adv {
			expiredClocks = append(expiredClocks, entryStruct{delta, ch})
		}
	}
	sort.SliceStable(expiredClocks, func(i, j int) bool {
		return expiredClocks[i].duration < expiredClocks[j].duration
	})

	// remove from map
	for _, entry := range expiredClocks {
		delete(g.timers, entry.duration)
	}
	g.unlock()
	// fire expired clocks
	for _, entry := range expiredClocks {
		entry.ch <- g.zero.Add(g.adv)
	}
	g.lock()
	defer g.unlock()
	for _, child := range g.children {
		child.Advance(adv)
	}
}

func (g *guidedClock) lock() {
	g.lockCh <- struct{}{}
}

func (g *guidedClock) unlock() {
	<-g.lockCh
}
