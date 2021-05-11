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

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/util/timers"
)

//msgp:ignore profElements
type profElements int

const (
	profElementIdle = iota
	profElementTxChange
	profElementNewRound
	profElementPeerState
	profElementIncomingMsg
	profElementOutgoingMsg
	profElementNextOffset

	// detached elements
	profElementGetTxnsGroups
	profElementAssembleMessage
	profElementSendMessage
	profElementMakeBloomFilter
	profElementTxnsSelection

	profElementLast
	profFirstDetachedElement = profElementGetTxnsGroups
)

// The profiler struct provides profiling information regarding the main loop performance
// characteristics. Using it provides statistics information about the recent duty cycle utilization,
// that could be used when trying to throttle the accuracy and performance of the transaction sync.
type profiler struct {
	// clock used as the source clock for measurements.
	clock timers.WallClock
	// elements contains the elements we want to measure. The user of this struct would not interact
	// with this variable directly. Instead, he/she would use getElement to get the element for a specific
	// profElements and use the start()/end() methods on that element.
	elements []*element
	// log is used to report the outcome of the measuring.
	log logging.Logger

	// profile contains all the elements indices, in order of arrival. It allows us to maintain a moving window.
	profile []int
	// profileSum is the total amount of time tracked by the profile array.
	profileSum time.Duration
	// profileSpan is the max span of the array ( or - the window ) that we would like to maintain.
	profileSpan time.Duration
	// lastProfileLog is the last time we've logged to the telemetry.
	lastProfileLog time.Duration
	// logInterval defines what is the frequency at which we send an event to the telemetry. Zero to disable.
	logInterval time.Duration
}

// element represent a single tracked element that would be profiled.
type element struct {
	// id is the index of the element in the profiler's elements array.
	id int
	// lastStart is the timestamp of the last time we called "start"
	lastStart time.Duration
	// profiler points to the parent profiler.
	profiler *profiler
	// times contains the times we've monitored for this element.
	times []time.Duration
	// total is the total accumulated time for this element ( i.e. sum(times) )
	total time.Duration
	// detached indicate whether this is a detached elements or not. Detached elements don't add to the total amount of time
	// counted by the profiler, allowing them to overlap with other elements.
	detached bool
}

func makeProfiler(span time.Duration, clock timers.WallClock, log logging.Logger, logInterval time.Duration) *profiler {
	prof := &profiler{
		profileSpan: span,
		clock:       clock,
		log:         log,
		logInterval: logInterval,
	}
	prof.createElements()
	return prof
}

func (p *profiler) createElements() {
	for element := 0; element < profElementLast; element++ {
		p.createElement(element >= profFirstDetachedElement)
	}
}

func (p *profiler) createElement(detached bool) *element {
	i := len(p.elements)
	e := &element{
		id:       i,
		profiler: p,
		detached: detached,
	}
	p.elements = append(p.elements, e)
	return e
}

func (p *profiler) getElement(el profElements) *element {
	return p.elements[el]
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
	}
}

func (p *profiler) maybeLogProfile() {
	// do we have the log profile enabled ?
	if p.logInterval == 0 {
		return
	}
	// do we have enough samples ? ( i.e. at least 50% sample time )
	if p.profileSum < p.profileSpan/2 {
		return
	}
	// have we send metrics recently ?
	curTime := p.clock.Since()
	if curTime-p.lastProfileLog <= p.logInterval {
		return
	}
	p.lastProfileLog = curTime
	p.logProfile()
}

func (p *profiler) logProfile() {
	metrics := telemetryspec.TransactionSyncProfilingMetrics{
		TotalOps:                     uint64(len(p.profile)),
		IdleOps:                      uint64(len(p.elements[profElementIdle].times)),
		TransactionPoolChangedOps:    uint64(len(p.elements[profElementTxChange].times)),
		NewRoundOps:                  uint64(len(p.elements[profElementNewRound].times)),
		PeerStateOps:                 uint64(len(p.elements[profElementPeerState].times)),
		IncomingMsgOps:               uint64(len(p.elements[profElementIncomingMsg].times)),
		OutgoingMsgOps:               uint64(len(p.elements[profElementOutgoingMsg].times)),
		NextOffsetOps:                uint64(len(p.elements[profElementNextOffset].times)),
		GetTxnGroupsOps:              uint64(len(p.elements[profElementGetTxnsGroups].times)),
		AssembleMessageOps:           uint64(len(p.elements[profElementAssembleMessage].times)),
		SendMessageOps:               uint64(len(p.elements[profElementSendMessage].times)),
		MakeBloomFilterOps:           uint64(len(p.elements[profElementMakeBloomFilter].times)),
		SelectPendingTransactionsOps: uint64(len(p.elements[profElementTxnsSelection].times)),

		TotalDuration:                    time.Duration(p.profileSum),
		IdlePercent:                      float64(p.elements[profElementIdle].total) * 100.0 / float64(p.profileSum),
		TransactionPoolChangedPercent:    float64(p.elements[profElementTxChange].total) * 100.0 / float64(p.profileSum),
		NewRoundPercent:                  float64(p.elements[profElementNewRound].total) * 100.0 / float64(p.profileSum),
		PeerStatePercent:                 float64(p.elements[profElementPeerState].total) * 100.0 / float64(p.profileSum),
		IncomingMsgPercent:               float64(p.elements[profElementIncomingMsg].total) * 100.0 / float64(p.profileSum),
		OutgoingMsgPercent:               float64(p.elements[profElementOutgoingMsg].total) * 100.0 / float64(p.profileSum),
		NextOffsetPercent:                float64(p.elements[profElementNextOffset].total) * 100.0 / float64(p.profileSum),
		GetTxnGroupsPercent:              float64(p.elements[profElementGetTxnsGroups].total) * 100.0 / float64(p.profileSum),
		AssembleMessagePercent:           float64(p.elements[profElementAssembleMessage].total) * 100.0 / float64(p.profileSum),
		SendMessagePercent:               float64(p.elements[profElementSendMessage].total) * 100.0 / float64(p.profileSum),
		MakeBloomFilterPercent:           float64(p.elements[profElementMakeBloomFilter].total) * 100.0 / float64(p.profileSum),
		SelectPendingTransactionsPercent: float64(p.elements[profElementTxnsSelection].total) * 100.0 / float64(p.profileSum),
	}

	p.log.Metrics(telemetryspec.Transaction, metrics, struct{}{})
}

func (e *element) start() {
	if e.profiler.logInterval > 0 {
		e.lastStart = e.profiler.clock.Since()
	}
}

func (e *element) end() {
	if e.profiler.logInterval == 0 {
		return
	}
	diff := e.profiler.clock.Since() - e.lastStart
	e.total += diff
	e.times = append(e.times, diff)
	e.profiler.profile = append(e.profiler.profile, e.id)

	if !e.detached {
		e.profiler.profileSum += diff
		e.profiler.prune()
		e.profiler.maybeLogProfile()
	}
}
