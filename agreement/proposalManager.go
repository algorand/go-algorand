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
	"fmt"

	"github.com/algorand/go-algorand/logging"
)

// A proposalManager is a proposalMachine which applies relay rules to incoming
// proposal-votes and proposal payloads, absorbs threshold events, and emits
// proposalCommittable events as proposals become committable.
//
// It handles the following type(s) of event: vote{Present,Verified},
// payload{Present,Verified}, roundInterruption, {soft,cert,next}Threshold.
// It returns the following type(s) of event: none, vote{Filtered,Malformed},
// payload{Pipelined,Rejected,Accepted}, and proposal{Accepted,Committable}.
type proposalManager struct{}

func (m *proposalManager) T() stateMachineTag {
	return proposalMachine
}

func (m *proposalManager) underlying() listener {
	return m
}

// A proposalManager handles eight types of events:
//
// - It applies message relay rules to votePresent, voteVerified,
//   payloadPresent, and payloadVerified events.
//
// - It enters a new round given a roundInterruption.
//
// - It enters a new period given a nextThreshold event.  It also enters a new
//   period given a softThreshold/certThreshold event, if necessary.
//    - On entering a new period due to a softThreshold/certThreshold, it
//      dispatches this event to the proposalMachineRound.
//
// For more details, see each method's respective documentation below.
func (m *proposalManager) handle(r routerHandle, p player, e event) event {
	switch e.t() {
	case votePresent, voteVerified, payloadPresent, payloadVerified:
		return m.handleMessageEvent(r, p, e.(filterableMessageEvent))
	case roundInterruption:
		return m.handleNewRound(r, p, e.(roundInterruptionEvent).Round)
	case softThreshold, certThreshold:
		e := e.(thresholdEvent)
		if p.Period < e.Period {
			r = m.handleNewPeriod(r, p, e)
		}

		ec := r.dispatch(p, e, proposalMachineRound, e.Round, e.Period, 0)
		return ec
	case nextThreshold:
		r = m.handleNewPeriod(r, p, e.(thresholdEvent))
		return emptyEvent{}
	}
	logging.Base().Panicf("proposalManager: bad event type: observed an event of type %v", e.t())
	panic("not reached")
}

// handleNewRound is called for roundInterruption and certThreshold events.  The
// proposalManager dispatches a newRound event to the proposalMachineRound and
// returns a payloadPipelined event or an empty event.
func (m *proposalManager) handleNewRound(r routerHandle, p player, round round) event {
	e := r.dispatch(p, newRoundEvent{}, proposalMachineRound, round, 0, 0)
	return e
}

// handleNewPeriod is called for threshold events that move the state machine into a new period.
// These events are dispatched to the proposalMachineRound, and an empty event is returned.
func (m *proposalManager) handleNewPeriod(r routerHandle, p player, e thresholdEvent) routerHandle {
	target := e.Period
	if e.t() == nextThreshold {
		target = e.Period + 1
	}

	en := newPeriodEvent{Period: target, Proposal: e.Proposal}
	r.dispatch(p, en, proposalMachineRound, e.Round, 0, 0)
	return r
}

// handleMessageEvent is called for {vote,payload}{Present,Verified} events.
//
// - A votePresent event is delivered when the state machine receives a new
//   proposal-vote.  A voteFiltered event is returned if the proposal-vote is
//   not fresh or is a duplicate.  Otherwise, an empty event is returned.
//
// - A voteVerified event is delievered after verification was attempted on a
//   proposal-vote.  A voteMalformed event is returned if the proposal-vote is
//   ill-formed and resulted from a corrupt process.  A voteFiltered event is
//   emitted if the vote is not fresh or is a duplicate.  Otherwise the
//   proposal-vote is dispatched to the proposalMachineRound, and a voteFiltered
//   or a proposalAccepted event is returned.
//
// - A payloadPresent event is delivered when the state machine receives a new
//   proposal payload.  The payload is dispatched to both the
//   proposalMachineRound for the current round and the proposalMachineRound for
//   the next round.  If both state machines return payloadRejected,
//   proposalManager also returns payloadRejected.  Otherwise, one state machine
//   returned payloadPipelined, and the proposalManager propagates this event to
//   the parent, setting the event's round properly.
//
// - A payloadVerified event is delivered after validation was attempted on a
//   proposal payload.  If the proposal payload was invalid, a payloadMalformed
//   event is returned.  Otherwise, the event is dispatched to the
//   proposalMachineRound, and then the resulting payload{Rejected,Accepted} or
//   proposalCommittable event is returned.
func (m *proposalManager) handleMessageEvent(r routerHandle, p player, e filterableMessageEvent) (res event) {
	var pipelinedRound round
	var pipelinedPeriod period
	defer func() {
		r.t.logProposalManagerResult(p, e.messageEvent, res, pipelinedRound, pipelinedPeriod)
	}()

	switch e.t() {
	case votePresent:
		err := m.filterProposalVote(p, r, e.Input.UnauthenticatedVote, e.FreshnessData)
		if err != nil {
			return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		}
		return emptyEvent{}

	case voteVerified: // Precondition: e.Round = p.Round
		if e.Cancelled {
			return filteredEvent{T: voteFiltered, Err: e.Err}
		}

		if e.Err != nil {
			return filteredEvent{T: voteMalformed, Err: e.Err}
		}

		v := e.Input.Vote

		err := proposalFresh(e.FreshnessData, v.u())
		if err != nil {
			err := makeSerErrf("proposalManager: ignoring proposal-vote due to age: %v", err)
			return filteredEvent{T: voteFiltered, Err: err}
		}

		if v.R.Round == p.Round {
			r.t.timeR().RecVoteReceived(v)
		} else if v.R.Round == p.Round+1 {
			r.t.timeRPlus1().RecVoteReceived(v)
		}

		return r.dispatch(p, e.messageEvent, proposalMachineRound, v.R.Round, v.R.Period, 0)

	case payloadPresent:
		propRound := e.Input.UnauthenticatedProposal.Round()
		in := e.messageEvent

		if p.Round == propRound {
			pipelinedRound = p.Round
			pipelinedPeriod = p.Period
			e1 := r.dispatch(p, in, proposalMachineRound, p.Round, p.Period, 0)
			if e1.t() == payloadRejected {
				return e1
			}

			ep := e1.(payloadProcessedEvent) // e1.t() == payloadPipelined
			ep.Round = p.Round

			// we log timing info on payloadPresent because we delay verification
			// (this is in contrast to logging timing on voteVerified...)
			r.t.timeR().RecPayload(ep.Proposal.OriginalPeriod, propose, ep.Proposal)
			return ep
		}

		// pipeline for next round
		e2 := r.dispatch(p, in, proposalMachineRound, p.Round+1, 0, 0)
		if e2.t() == payloadRejected {
			return e2
		}
		ep := e2.(payloadProcessedEvent) // e2.t() == payloadPipelined
		ep.Round = p.Round + 1

		pipelinedRound = p.Round + 1
		pipelinedPeriod = 0

		r.t.timeRPlus1().RecPayload(ep.Proposal.OriginalPeriod, propose, ep.Proposal)

		return ep

	default: // case payloadVerified:
		if e.Cancelled {
			return payloadProcessedEvent{T: payloadRejected, Err: e.Err}
		}

		if e.Err != nil {
			return filteredEvent{T: payloadMalformed, Err: e.Err}
		}

		up := e.Input.UnauthenticatedProposal
		r.t.timeR().RecPayloadValidation(up.OriginalPeriod, propose, up.value())

		return r.dispatch(p, e.messageEvent, proposalMachineRound, p.Round, p.Period, 0)
	}
}

// filterVote filters a vote, checking if it is both fresh and not a duplicate.
func (m *proposalManager) filterProposalVote(p player, r routerHandle, uv unauthenticatedVote, freshData freshnessData) error {
	err := proposalFresh(freshData, uv)
	if err != nil {
		return fmt.Errorf("proposalManager: filtered proposal-vote due to age: %v", err)
	}

	qe := voteFilterRequestEvent{RawVote: uv.R}
	sawVote := r.dispatch(p, qe, proposalMachinePeriod, uv.R.Round, uv.R.Period, 0)
	if sawVote.t() == voteFiltered {
		return fmt.Errorf("proposalManager: filtered proposal-vote: sender %v had already sent a vote in round %d period %d", uv.R.Sender, uv.R.Round, uv.R.Period)
	}
	return nil
}

// voteFresh determines whether a proposal satisfies freshness rules.
func proposalFresh(freshData freshnessData, vote unauthenticatedVote) error {
	switch vote.R.Round {
	case freshData.PlayerRound:
		if freshData.PlayerPeriod != 0 && freshData.PlayerPeriod-1 > vote.R.Period {
			return fmt.Errorf("filtered stale proposal: period %d - 1 > %d", freshData.PlayerPeriod, vote.R.Period)
		}
		if freshData.PlayerPeriod+1 < vote.R.Period {
			return fmt.Errorf("filtered premature proposal: period %d + 1 < %d", freshData.PlayerPeriod, vote.R.Period)
		}
	case freshData.PlayerRound + 1:
		if vote.R.Period != 0 {
			return fmt.Errorf("filtered premature proposal from next round: period %d > 0", vote.R.Period)
		}
	default:
		return fmt.Errorf("filtered proposal from bad round: p.Round=%d, vote.Round=%d", freshData.PlayerRound, vote.R.Round)
	}
	return nil
}
