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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
)

// A proposalSeeker finds the vote with the lowest credential until freeze() is
// called.
type proposalSeeker struct {
	// Lowest contains the vote with the lowest credential seen so far.
	Lowest vote
	// Filled is set if any vote has been seen.
	Filled bool
	// Frozen is set once freeze is called.  When Frozen is set, Lowest and
	// Filled will no longer be modified.
	Frozen bool
}

// accept compares a given vote with the current lowest-credentialled vote and
// sets it if freeze has not been called.
func (s proposalSeeker) accept(v vote) (proposalSeeker, error) {
	if s.Frozen {
		return s, errProposalSeekerFrozen{}
	}

	if s.Filled && !v.Cred.Less(s.Lowest.Cred) {
		return s, errProposalSeekerNotLess{NewSender: v.R.Sender, LowestSender: s.Lowest.R.Sender}
	}

	s.Lowest = v
	s.Filled = true
	return s, nil
}

// freeze freezes the state of the proposalSeeker so that future calls no longer
// change its state.
func (s proposalSeeker) freeze() proposalSeeker {
	s.Frozen = true
	return s
}

// A proposalTracker is a proposalMachinePeriod which de-duplicates
// proposal-votes seen in a given period and records the lowest credential seen
// and the period's staging proposal-value.
//
// It handles the following type(s) of event: voteVerified, voteFilterRequest, proposalFrozen, readStaging, and
// softThreshold.
// It returns the following type(s) of event: voteFiltered, proposalAccepted, readStaging,
// and proposalFrozen.
type proposalTracker struct {
	// Duplicate holds the set of senders which has been seen by the
	// proposalTracker.  A duplicate proposal-vote or an equivocating
	// proposal-vote is dropped by a proposalTracker.
	Duplicate map[basics.Address]bool
	// Freezer holds a proposalSeeker, which seeks the proposal-vote with
	// the lowest credential seen by the proposalTracker.
	Freezer proposalSeeker
	// Staging holds the proposalValue of the softThreshold delivered to
	// this proposalTracker (if any).
	Staging proposalValue
}

func (t *proposalTracker) T() stateMachineTag {
	return proposalMachinePeriod
}

func (t *proposalTracker) underlying() listener {
	return t
}

// A proposalTracker handles five types of events.
//
// - voteFilterRequest returns a voteFiltered event if a given proposal-vote
//   from a given sender has already been seen.  Otherwise it returns an empty
//   event.
//
// - voteVerified is issued when a relevant proposal-vote has passed
//   cryptographic verification.  If the proposalTracker has already seen a
//   proposal-vote from the same sender, a voteFiltered event is returned.  If
//   the proposal-vote's credential is not lowest than the current lowest
//   credential, or if a proposalFrozen or softThreshold event has already been delivered,
//   voteFiltered is also returned.  Otherwise, a proposalAccepted event is
//   returned.  The returned event contains the proposal-value relevant to the
//   current period.
//
// - proposalFrozen is issued after the state machine has timed out waiting for
//   the vote with the lowest credential value and has settled on a value to
//   soft-vote.  A proposalFrozen event tells this state machine to stop
//   accepting new proposal-votes.  The proposalFrozen is returned and the best
//   vote proposal-value is returned.  If none exists, bottom is returned.
//
// - softThreshold is issued after the state machine has received a threshold of
//   soft votes for some value in the proposalTracker's period.  The
//   softThreshold event sets the proposalTracker's staging value.  A
//   proposalAccepted event is returned, which contains the proposal-value
//   relevant to the current period.
//
// - readStaging returns the a stagingValueEvent with the proposal-value
//   believed to be the staging value (i.e., sigma(S, r, p)) by the
//   proposalTracker in period p.
func (t *proposalTracker) handle(r routerHandle, p player, e event) event {
	switch e.t() {
	case voteFilterRequest:
		v := e.(voteFilterRequestEvent).RawVote
		if t.Duplicate[v.Sender] {
			err := errProposalTrackerSenderDup{Sender: v.Sender, Round: v.roundBranch(), Period: v.Period}
			return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		}
		return emptyEvent{}

	case voteVerified:
		if t.Duplicate == nil {
			t.Duplicate = make(map[basics.Address]bool)
		}

		e := e.(messageEvent)
		v := e.Input.Vote
		if t.Duplicate[v.R.Sender] {
			err := errProposalTrackerSenderDup{Sender: v.R.Sender, Round: v.R.roundBranch(), Period: v.R.Period}
			return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		}
		t.Duplicate[v.R.Sender] = true

		if t.Staging != bottom {
			err := errProposalTrackerStaged{}
			return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		}

		var err error
		t.Freezer, err = t.Freezer.accept(v)
		if err != nil {
			err := errProposalTrackerPS{Sub: err}
			return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		}

		return proposalAcceptedEvent{
			Round:    v.R.roundBranch(),
			Period:   v.R.Period,
			Proposal: v.R.Proposal,
		}

	case proposalFrozen:
		e := e.(proposalFrozenEvent)
		e.Proposal = t.Freezer.Lowest.R.Proposal
		t.Freezer = t.Freezer.freeze()
		return e

	case softThreshold, certThreshold:
		e := e.(thresholdEvent)
		t.Staging = e.Proposal

		return proposalAcceptedEvent{
			Round:    e.Round,
			Period:   e.Period,
			Proposal: e.Proposal,
		}

	case readStaging:
		se := e.(stagingValueEvent)
		se.Proposal = t.Staging
		return se
	}

	logging.Base().Panicf("proposalTracker: bad event type: observed an event of type %v", e.t())
	panic("not reached")
}

// errors

type errProposalSeekerFrozen struct{}

func (err errProposalSeekerFrozen) Error() string {
	return "proposalSeeker.accept: seeker is already frozen"
}

type errProposalSeekerNotLess struct {
	NewSender    basics.Address
	LowestSender basics.Address
}

func (err errProposalSeekerNotLess) Error() string {
	return fmt.Sprintf("proposalSeeker.accept: credential from %v is not less than credential from %v", err.NewSender, err.LowestSender)
}

type errProposalTrackerSenderDup struct {
	Sender basics.Address
	Round  round
	Period period
}

func (err errProposalTrackerSenderDup) Error() string {
	return fmt.Sprintf("proposalTracker: filtered vote: sender %v had already sent a vote in round %d period %d", err.Sender, err.Round, err.Period)

}

type errProposalTrackerStaged struct{}

func (err errProposalTrackerStaged) Error() string {
	return "proposalTracker: value already staged"
}

type errProposalTrackerPS struct {
	Sub error
}

func (err errProposalTrackerPS) Error() string {
	return fmt.Sprintf("proposalTracker: filtered vote: %v", err.Sub)
}
