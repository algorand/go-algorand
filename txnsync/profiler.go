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

type profElements int

const (
	profElementIdle = iota
	profElementTxChange
	profElementNewRounnd
	profElementPeerState
	profElementIncomingMsg
	profElementOutgoingMsg
	profElementNextOffset

	profElementGetTxnsGroups
	profElementAssembleMessage
	profElementSendMessage
	profElementMakeBloomFilter
	profElementTxnsSelection

	profElementLast
)

var profElementNames = []string{
	"idle",
	"transactionPoolChangedEvent",
	"newRound",
	"peerState",
	"incomingMsg",
	"outgoingMsg",
	"nextOffset",
	"getTxnGroups",
	"assembleMessage",
	"sendMessage",
	"makeBloomFilter",
	"selectPendingTransactions",
}

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
	logInterval    time.Duration // what is the frequency at which we send an event to the telemetry. Zero to disable.
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
		p.createElement(profElementNames[element], element > profElementNextOffset)
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
		p.spanReached = true
	}
	p.logProfile()
}

func (p *profiler) logProfile() {
	if !p.spanReached || p.logInterval == 0 {
		return
	}
	curTime := p.clock.Since()
	if curTime-p.lastProfileLog <= p.logInterval {
		return
	}
	p.lastProfileLog = curTime

	metrics := telemetryspec.TransactionSyncProfilingMetrics{
		TotalOps:                     uint64(len(p.profile)),
		IdleOps:                      uint64(len(p.elements[profElementIdle].times)),
		TransactionPoolChangedOps:    uint64(len(p.elements[profElementTxChange].times)),
		NewRoundOps:                  uint64(len(p.elements[profElementNewRounnd].times)),
		PeerStateOps:                 uint64(len(p.elements[profElementPeerState].times)),
		IncomingMsgOps:               uint64(len(p.elements[profElementIncomingMsg].times)),
		OutgoingMsgOps:               uint64(len(p.elements[profElementOutgoingMsg].times)),
		NextOffsetOps:                uint64(len(p.elements[profElementNextOffset].times)),
		GetTxnGroupsOps:              uint64(len(p.elements[profElementGetTxnsGroups].times)),
		AssembleMessageOps:           uint64(len(p.elements[profElementAssembleMessage].times)),
		SendMessageOps:               uint64(len(p.elements[profElementSendMessage].times)),
		MakeBloomFilterOps:           uint64(len(p.elements[profElementMakeBloomFilter].times)),
		SelectPendingTransactionsOps: uint64(len(p.elements[profElementTxnsSelection].times)),

		TotalDuration:                    uint64(p.profileSum),
		IdlePercent:                      float64(p.elements[profElementIdle].total) * 100.0 / float64(p.profileSum),
		TransactionPoolChangedPercent:    float64(p.elements[profElementTxChange].total) * 100.0 / float64(p.profileSum),
		NewRoundPercent:                  float64(p.elements[profElementNewRounnd].total) * 100.0 / float64(p.profileSum),
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
	}
}
