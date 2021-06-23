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
	"github.com/algorand/go-algorand/logging"
)

// A voteTrackerPeriod is a voteMachinePeriod which indicates whether a
// next-threshold of votes was observed for a some value in a period.
type voteTrackerPeriod struct {
	// Make it explicit that we are serializing player fields for crash recovery;
	// we should probably adopt this convention over the rest of player at some point.
	Cached nextThresholdStatusEvent
}

func (t *voteTrackerPeriod) T() stateMachineTag {
	return voteMachinePeriod
}

func (t *voteTrackerPeriod) underlying() listener {
	return t
}

// A voteTrackerPeriod handles:
//   - voteAcceptedEvent, which it forwards to the vote tracker. This generates either
//     a threshold event or an empty event (forwarded to the sender)
//   - nextThresholds: It updates its next threshold cache if this
//     is a new next vote bundle for this period. Emits empty event. (We split this out
//     so that we can unit test the voteTrackerPeriod trace without depending on the
//     voteTrackerStep.)
//   - nextThresholdStatusRequest, which enables a nextThresholdStatusEvent reply
//
// In a given period, a threshold for the bottom value may or may not be seen.
// In addition, a threshold for some non-bottom proposal-value may or may not be
// seen.  (If thresholds for both a non-bottom proposal-value and bottom value are
// ever seen, any threshold for any non-bottom proposal-value has a step greater than
// any threshold for any bottom value.)
//
// One question you might have is why we cache both the next threshold in the period
// machine and the freshest bundle in the round machine, when they seem to expose
// redundant functionality. However, the functionality is not actually redundant.
// In particular, when soft-voting, player needs to know if it saw a next-vote
// value bundle (regardless of if it saw a next-vote bottom bundle). This is because
// of a protocol optimization to prevent "reproposers" from setting the seed Q_r.
func (t *voteTrackerPeriod) handle(r routerHandle, p player, e event) event {
	switch e.t() {
	case voteAccepted:
		// forward voteAccepted event
		round := e.(voteAcceptedEvent).Vote.R.roundBranch()
		period := e.(voteAcceptedEvent).Vote.R.Period
		step := e.(voteAcceptedEvent).Vote.R.Step
		e = r.dispatch(p, e, voteMachineStep, round, period, step)
		if e.t() != none && e.(thresholdEvent).Step >= next {
			// dispatch to self, so that we can unit test threshold caching
			r.dispatch(p, e, voteMachinePeriod, round, period, 0)
		}
		// send any threshold event (or none) back to the round
		return e
	case nextThreshold:
		// cache next thresholds in response
		if e.(thresholdEvent).Proposal == bottom {
			t.Cached.Bottom = true
		} else {
			t.Cached.Proposal = e.(thresholdEvent).Proposal
		}
		return emptyEvent{}
	case nextThresholdStatusRequest:
		return t.Cached
	default:
		logging.Base().Panicf("voteTrackerPeriod: bad event type: observed an event of type %v", e.t())
		panic("not reached")
	}
}

// A voteTrackerRound is a voteMachineRound which forwards voteAcceptedEvents
// and maintains the "freshest" bundle seen for a round.
//
// Bundle "freshness" is an ordering relation defined on thresholdEvents.  The
// relation is defined as follows:
//  - certThresholds are fresher than other kinds of thresholdEvent.
//  - other thresholdEvents are fresher than thresholdEvents from older periods.
//  - nextThresholds are fresher than softThreshold in the same period.
//  - nextThresholds for the bottom proposal-value are fresher than
//    nextThresholds for another proposal-value.
// (Note that the step of a nextThreshold does not affect its freshness.)
//
// It handles the following type(s) of event: voteAcceptedEvent, freshestBundleRequest, nextThreshold
// It returns the following type(s) of event: none and
// {soft,cert,next}Threshold, and freshestBundle
type voteTrackerRound struct {
	// Freshest holds the freshest thresholdEvent seen this round.
	Freshest thresholdEvent
	// Ok is set if any thresholdEvent has been seen.
	Ok bool
}

func (t *voteTrackerRound) T() stateMachineTag {
	return voteMachineRound
}

func (t *voteTrackerRound) underlying() listener {
	return t
}

// A voteTrackerRound handles:
//   - voteAcceptedEvent.  The voteTrackerRound forwards voteAcceptedEvents to the
//     correct children, and propagates threshold events back up if they are the freshest seen.
//   - freshestBundleRequest: this event enables a freshestBundle reply
//   - soft/cert/nextThreshold: updates freshest threshold cache, returns the same event if freshest,
//     else, emits emptyEvent.
//
// The voteTrackerRound returns thresholdEvents in freshness order.
// thresholdEvents which are emitted from voteMachineSteps after a fresher event
// was emitted are dropped by the voteTrackerRound and do not propagate up to
// the parent.
//
// A thresholdEvent which is emitted is saved for later freshestEvent queries.
func (t *voteTrackerRound) handle(r routerHandle, p player, e event) event {
	switch e.t() {
	case voteAccepted:
		round := e.(voteAcceptedEvent).Vote.R.roundBranch()
		period := e.(voteAcceptedEvent).Vote.R.Period
		e = r.dispatch(p, e, voteMachinePeriod, round, period, 0)
		// dispatch to self to handle freshest bundle
		if e.t() != none {
			e2 := r.dispatch(p, e, voteMachineRound, round, 0, 0)
			return e2
		}
		return emptyEvent{}
	case softThreshold, certThreshold, nextThreshold:
		if e.(thresholdEvent).fresherThan(t.Freshest) {
			t.Freshest = e.(thresholdEvent)
			t.Ok = true
			return e
		}
		return emptyEvent{}
	case freshestBundleRequest:
		return freshestBundleEvent{Ok: t.Ok, Event: t.Freshest}
	default:
		logging.Base().Panicf("voteTrackerRound: bad event type: observed an event of type %v", e.t())
		panic("not reached")
	}
}
