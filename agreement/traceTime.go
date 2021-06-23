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

package agreement

import (
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

// We call all of the following messages post-filtering, such that
// any event we log is relevant to the current agreement state.
type timingInfoGenerator struct {
	enabled          bool
	i                stagedRndTimingMetrics
	iForPV           map[proposalValue]*stagedTimeSender // track winner
	iForPP           map[proposalValue]*stagedTimeSender // track payload for winner
	iForPPValidation map[proposalValue]*stagedTimeSender // track payload for winner
	winner           proposalValue
	log              serviceLogger
}

func makeTimingInfoGen(enabled bool, log serviceLogger) *timingInfoGenerator {
	t := new(timingInfoGenerator)
	t.enabled = enabled
	t.log = log
	if enabled {
		t.iForPP = make(map[proposalValue]*stagedTimeSender)
		t.iForPPValidation = make(map[proposalValue]*stagedTimeSender)
		t.iForPV = make(map[proposalValue]*stagedTimeSender)
		t.i.LVotes = make(map[uint64]stagedLclMsgTiming)
	}
	return t
}

// StartRound should be called before logging other relevant items.
func (tG *timingInfoGenerator) StartRound(r round) {
	if !tG.enabled {
		return
	}
	tG.i.Round = uint64(r.number) // XXX timing doesn't know about branches
	tG.i.LRoundStart = time.Now()
}

// RecStep records the "beginning" of a step, corresponding to the time when
// we send the corresponding vote for that step.
func (tG *timingInfoGenerator) RecStep(p period, s step, winner proposalValue) {
	if !tG.enabled || s > next || p > 0 {
		return
	}
	if tG.i.LVotes == nil {
		// if this happens, then .enabled is somehow inconsistent.
		// This should never happen, but for now make it fail less badly.
		tG.log.Warn("agreement: trace time metrics not initialized properly; tried to write nil map")
		return
	}
	t := time.Now()
	localInfo := tG.i.LVotes[uint64(s)]
	localInfo.LStart = &t

	switch s {
	case soft:
		// write timing for winning proposal
		proposeInfo := tG.i.LVotes[0]
		proposeInfo.LRWin = tG.iForPV[winner] // winner should always be non bottom for soft
		tG.i.LVotes[0] = proposeInfo
		// write timing for winning payload (or, if not yet seen, cache the winner)
		tG.i.LPayload.LRWin = tG.iForPP[winner]
		tG.i.LPayloadValidation.LRWin = tG.iForPPValidation[winner]
		tG.winner = winner
	}
	tG.i.LVotes[uint64(s)] = localInfo
}

// note: we currently *do* log proposal votes received after the freeze timer (2\lambda) (but before cert)
func (tG *timingInfoGenerator) RecVoteReceived(v vote) {
	if !tG.enabled || v.R.Step > next || v.R.Period > 0 {
		return
	}
	if tG.iForPV == nil || tG.i.LVotes == nil {
		tG.log.Warn("agreement: trace time metrics not initialized properly; tried to write nil map")
		return
	}
	x := &stagedTimeSender{
		T:      time.Now(),
		Sender: truncate(v.R.Sender),
	}

	localInfo := tG.i.LVotes[uint64(v.R.Step)]
	if localInfo.LRFirst == nil {
		localInfo.LRFirst = x
	}
	localInfo.LRLast = x
	tG.i.LVotes[uint64(v.R.Step)] = localInfo

	switch v.R.Step {
	case propose:
		// cache timing so we can pull it out for winning proposal
		tG.iForPV[v.R.Proposal] = x
	}
}

func (tG *timingInfoGenerator) RecThreshold(e thresholdEvent) {
	if !tG.enabled || e.Step > next || e.Period > 0 {
		return
	}
	if tG.i.LVotes == nil {
		tG.log.Warn("agreement: trace time metrics not initialized properly; tried to write nil map")
		return
	}
	t := time.Now()
	localInfo := tG.i.LVotes[uint64(e.Step)]
	localInfo.LRThresh = &t
	tG.i.LVotes[uint64(e.Step)] = localInfo
}

func (tG *timingInfoGenerator) RecPayload(p period, s step, pV proposalValue) {
	if !tG.enabled || s > next || p > 0 {
		return
	}
	if tG.iForPP == nil {
		tG.log.Warn("agreement: trace time metrics not initialized properly; tried to write nil payload map")
		return
	}
	x := &stagedTimeSender{
		T:      time.Now(),
		Sender: truncate(pV.OriginalProposer),
	}
	tG.iForPP[pV] = x // cache timing so we can pull it out for winning proposal
	if tG.i.LPayload.LRFirst == nil {
		tG.i.LPayload.LRFirst = x
	}
	if pV == tG.winner { // pV should never be bottom
		tG.i.LPayload.LRWin = x
	}
	tG.i.LPayload.LRLast = x
}

func (tG *timingInfoGenerator) RecPayloadValidation(p period, s step, pV proposalValue) {
	if !tG.enabled || s > next || p > 0 {
		return
	}
	if tG.iForPPValidation == nil {
		tG.log.Warn("agreement: trace time metrics not initialized properly; tried to write nil payload map")
		return
	}
	x := &stagedTimeSender{
		T:      time.Now(),
		Sender: truncate(pV.OriginalProposer),
	}
	tG.iForPPValidation[pV] = x // cache timing so we can pull it out for winning proposal
	if tG.i.LPayloadValidation.LRFirst == nil {
		tG.i.LPayloadValidation.LRFirst = x
	}
	if pV == tG.winner { // pV should never be bottom
		tG.i.LPayloadValidation.LRWin = x
	}
	tG.i.LPayloadValidation.LRLast = x
}

func (tG *timingInfoGenerator) RecBlockAssembled() {
	// This raw timing is only available in the pseudonode, but we don't want
	// to cause a race. So this method is currently unused. [GOAL2-541]
	tG.i.BlockAssembleTime = time.Now()
}

func (tG *timingInfoGenerator) Build(concludingStep step) telemetryspec.RoundTimingMetrics {
	tG.i.ConcludingStep = uint64(concludingStep)
	return tG.i.build()
}

// truncate crypto addr to five chars in logs
func truncate(a basics.Address) string {
	g := a.String()
	x := len(g)
	switch {
	case x <= 5:
		return g
	case x < 10:
		return g[5:x]
	default:
		return g[5:10]
	}
}

/* Utility types */

// Local helpers for converting absolute time to offset time (which can be negative)
// See telemetry equivalents: these utility structs are intended to mirror the telemetry
// output, with identical documentation, with the exception that here we store absolute times
// and later populate telemetry with relevative offsets from the round start (since votes
// can be received before rounds start.)
type stagedRndTimingMetrics struct {
	Round              uint64
	ConcludingStep     uint64
	LRoundStart        time.Time
	LVotes             map[uint64]stagedLclMsgTiming
	LPayload           stagedLclMsgTiming
	LPayloadValidation stagedLclMsgTiming
	BlockAssembleTime  time.Time
}

func (m stagedRndTimingMetrics) build() (t telemetryspec.RoundTimingMetrics) {
	t.Round = m.Round
	t.ConcludingStep = m.ConcludingStep
	t.LRoundStart = m.LRoundStart
	t.LVotes = make(map[uint64]telemetryspec.LocalMsgTiming, len(m.LVotes))
	for k, v := range m.LVotes {
		t.LVotes[k] = v.build(t.LRoundStart)
	}
	t.LPayload = m.LPayload.build(t.LRoundStart)
	t.PayloadValidation = m.LPayloadValidation.build(t.LRoundStart)
	t.BlockAssemble = m.BlockAssembleTime.Sub(t.LRoundStart)
	return
}

type stagedLclMsgTiming struct {
	LRFirst  *stagedTimeSender
	LRLast   *stagedTimeSender
	LStart   *time.Time
	LRWin    *stagedTimeSender
	LRThresh *time.Time
}

// build converts time.Time fields into time.Durations from the relative time.
func (m stagedLclMsgTiming) build(relative time.Time) (t telemetryspec.LocalMsgTiming) {
	if m.LRFirst != nil {
		t.LRFirst = m.LRFirst.build(relative)
	}
	if m.LRLast != nil {
		t.LRLast = m.LRLast.build(relative)
	}
	if m.LStart != nil {
		d := m.LStart.Sub(relative)
		t.LStart = &d
	}
	if m.LRWin != nil {
		t.LRWin = m.LRWin.build(relative)
	}
	if m.LRThresh != nil {
		d := m.LRThresh.Sub(relative)
		t.LRThresh = &d
	}
	return
}

type stagedTimeSender struct {
	T      time.Time `json:"t"`
	Sender string    `json:"sender"`
}

func (m *stagedTimeSender) build(relative time.Time) (t *telemetryspec.TimeWithSender) {
	t = &telemetryspec.TimeWithSender{}
	t.Sender = m.Sender
	t.T = m.T.Sub(relative)
	return
}
