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
	"fmt"
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/timers"
)

// The profiler struct provides profiling information regarding the main loop performance
// characteristics. Using it provides statistics information about the recent duty cycle utilization,
// that could be used when trying to throlle the accuracy and performance of the transaction sync.
type profiler struct {
	clock    timers.WallClock
	elements []*element
	log      logging.Logger

	profile        []int
	profileSum     time.Duration
	profileSpan    time.Duration
	spanReached    bool
	lastProfileLog time.Duration
}

// element represent a single tracked element that would be profiled.
type element struct {
	name      string
	id        int
	lastStart time.Duration
	profiler  *profiler
	times     []time.Duration
	total     time.Duration
	detached  bool
}

func makeProfiler(span time.Duration, clock timers.WallClock, log logging.Logger) *profiler {
	return &profiler{
		profileSpan: span,
		clock:       clock,
		log:         log,
	}
}

func (p *profiler) createElement(name string, detached bool) *element {
	i := len(p.elements)
	e := &element{
		name:     name,
		id:       i,
		profiler: p,
		detached: detached,
	}
	p.elements = append(p.elements, e)
	return e
}

func (p *profiler) prune() {
	for p.profileSum > p.profileSpan {
		// remove the first elements from the profile.
		i := p.profile[0]
		e := p.elements[i]
		dt := e.times[0]

		e.total -= dt
		if !e.detached {
			p.profileSum -= dt
		}

		p.profile = p.profile[1:]
		e.times = e.times[1:]
		p.spanReached = true
	}
	p.logProfile()
}

func (p *profiler) logProfile() {
	if !p.spanReached {
		return
	}
	curTime := p.clock.Since()
	if curTime-p.lastProfileLog <= p.profileSpan {
		return
	}
	p.lastProfileLog = curTime
	// TODO : this logging need to be re-implemented as a telemetry event.
	s := ""
	for _, element := range p.elements {
		elPart := float64(element.total) * 100.0 / float64(p.profileSum)
		elCount := len(element.times)
		s += fmt.Sprintf(", %s %3.1f%% / %d", element.name, elPart, elCount)
	}
	s = s[2:]
	p.log.Infof("txnsync.logProfile: %d ops, %s", len(p.profile), s)
}

func (e *element) start() {
	e.lastStart = e.profiler.clock.Since()
}

func (e *element) end() {
	diff := e.profiler.clock.Since() - e.lastStart
	e.total += diff
	e.times = append(e.times, diff)
	e.profiler.profile = append(e.profiler.profile, e.id)

	if !e.detached {
		e.profiler.profileSum += diff
		e.profiler.prune()
	}
}
