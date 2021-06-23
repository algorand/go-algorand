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
	"bytes"
	"sort"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

type proposalVoteCounter struct {
	Count uint64
	Votes map[basics.Address]vote
}

// A voteTracker is a voteMachineStep which handles duplication and
// equivocation, counts votes, and emits threshold events.
//
// It handles the following type(s) of queries: sawObject and sawNextThrehsold.
//
// It handles the following type(s) of event: voteAcceptedEvent.
// It returns the following type(s) of event: none and
// {soft,cert,next}Threshold.
type voteTracker struct {
	// Voters holds the set of voters which have voted in the current step.
	// It is used to track whether a voter has equivocated.
	Voters map[basics.Address]vote

	// Counts holds the weighted sum of the votes for a given proposal.
	// it also hold the individual votes.
	// preconditions :
	// Any proposalValue in Counts is gurenteed to contain at least one vote
	Counts map[proposalValue]proposalVoteCounter

	// Equivocators holds the set of voters which have already equivocated
	// once.  Future votes from these voters are dropped and not
	// propagated.
	Equivocators map[basics.Address]equivocationVote

	// EquivocatorsCount holds the number of equivocating votes which count
	// for any proposal-value.
	EquivocatorsCount uint64
}

func (tracker *voteTracker) T() stateMachineTag {
	return voteMachineStep
}

func (tracker *voteTracker) underlying() listener {
	return tracker
}

// count counts the number of votes which vouch for a proposal. This includes
// the number of votes which directly vote for a proposal and also the number of
// equivocating votes, which are interpreted to vote for any proposal.
func (tracker *voteTracker) count(proposal proposalValue) uint64 {
	return tracker.Counts[proposal].Count + tracker.EquivocatorsCount
}

// A voteTracker handles the voteAcceptedEvent and voteFilterRequestEvents.  It returns either an event
// of type none, or it returns an event of type {soft,cert,next}Threshold, or it
// returns a FilteredEvent saying that the event was not processed (if it were a
// duplicate); if not a duplicate, returns a none type.
//
// For a voteTracker observing votes from the soft step, an event of type
// softThreshold is emitted if the vote causes the state machine to observe a
// threshold of soft votes.  Since this can happen at most once, the voteTracker
// will emit an event of type none before and after it observes this threshold.
//
// The behavior of the voteTracker for different steps is analogous to the
// behavior of the voteTracker observing votes from the soft step, except they
// emit certThreshold or nextThreshold events.
//
// When a thresholdEvent is emitted, it will include a bundle of votes which
// proves the validity of the event to any other player.
func (tracker *voteTracker) handle(r routerHandle, p player, e0 event) event {
	voteCausesStateChange := true

	switch e0.t() {
	case voteAccepted:
		e := e0.(voteAcceptedEvent)
		proto := config.Consensus[e.Proto]
		var res thresholdEvent
		defer func() {
			if voteCausesStateChange {
				r.t.logVoteTrackerResult(p, e, res, e.Vote.Cred.Weight, tracker.count(e.Vote.R.Proposal), tracker.count(res.Proposal), proto)
			}
		}()

		if tracker.Counts == nil {
			tracker.Counts = make(map[proposalValue]proposalVoteCounter)
		}
		if tracker.Voters == nil {
			tracker.Voters = make(map[basics.Address]vote)
		}
		if tracker.Equivocators == nil {
			tracker.Equivocators = make(map[basics.Address]equivocationVote)
		}

		sender := e.Vote.R.Sender
		eqVote, equivocator := tracker.Equivocators[sender]
		if equivocator {
			equivocationDetails := telemetryspec.EquivocatedVoteEventDetails{
				VoterAddress:          sender.String(),
				ProposalHash:          e.Vote.R.Proposal.BlockDigest.String(),
				Round:                 uint64(e.Vote.R.Round),
				Period:                uint64(e.Vote.R.Period),
				Step:                  uint64(e.Vote.R.Step),
				Weight:                e.Vote.Cred.Weight,
				PreviousProposalHash1: eqVote.Proposals[0].BlockDigest.String(),
				PreviousProposalHash2: eqVote.Proposals[1].BlockDigest.String(),
			}
			logging.Base().EventWithDetails(telemetryspec.ApplicationState, telemetryspec.EquivocatedVoteEvent, equivocationDetails)

			return thresholdEvent{}
		}

		_, overBefore := tracker.overThreshold(proto, e.Vote.R.Step)

		oldVote, voted := tracker.Voters[sender]

		if !voted {
			// not an equivocator, and there's no earlier vote
			tracker.Voters[sender] = e.Vote

			// if we never seen this proposal before, the following would return the default proposalVote
			proposalVote := tracker.Counts[e.Vote.R.Proposal]
			// if we received the default proposalVote, we need to initialize the Votes map.
			if proposalVote.Votes == nil {
				proposalVote.Votes = make(map[basics.Address]vote)
			}
			// add the count for the given vote
			proposalVote.Count += e.Vote.Cred.Weight
			// store the vote by the sender
			proposalVote.Votes[sender] = e.Vote
			tracker.Counts[e.Vote.R.Proposal] = proposalVote
		} else {

			if oldVote.R.Proposal == e.Vote.R.Proposal {
				// don't log - otherwise bundles with votes we've seen before will dump thousands of lines into logs
				voteCausesStateChange = false
				return thresholdEvent{}
			}

			equivocationDetails := telemetryspec.EquivocatedVoteEventDetails{
				VoterAddress:          sender.String(),
				ProposalHash:          e.Vote.R.Proposal.BlockDigest.String(),
				Round:                 uint64(e.Vote.R.Round),
				Period:                uint64(e.Vote.R.Period),
				Step:                  uint64(e.Vote.R.Step),
				Weight:                e.Vote.Cred.Weight,
				PreviousProposalHash1: oldVote.R.Proposal.BlockDigest.String(),
			}
			logging.Base().EventWithDetails(telemetryspec.ApplicationState, telemetryspec.EquivocatedVoteEvent, equivocationDetails)

			logging.Base().Warnf("voteTracker: observed an equivocator: %v (vote was %v)", sender, e.Vote)

			// sender was not already marked as an equivocator so track
			// their weight
			tracker.EquivocatorsCount += e.Vote.Cred.Weight

			if e.Vote.R.Step.reachesQuorum(proto, tracker.EquivocatorsCount) {
				// when does this triggers ?
				// In order for this to be triggered, more than 75% of the vote for the given step need to vote for more than
				// a single proposal. In that state, all the proposals become "above threshold". That's a serious issue, since
				// it would compromise the honest node core assumption.
				logging.Base().Panicf("too many equivocators for step %d: %d", e.Vote.R.Step, tracker.EquivocatorsCount)
			}

			// decrease their weight from any block proposal they already
			// voted for (there can be only one such value)

			// it's the equivocator's other vote, don't add twice
			if tracker.Counts[oldVote.R.Proposal].Count <= oldVote.Cred.Weight {
				// this is the only vote for this proposal.
				delete(tracker.Counts, oldVote.R.Proposal)
			} else {
				proposalVote := tracker.Counts[oldVote.R.Proposal]
				proposalVote.Count -= oldVote.Cred.Weight
				delete(proposalVote.Votes, sender)
				tracker.Counts[oldVote.R.Proposal] = proposalVote
			}

			// mark the sender as an equivocator, so we never track its
			// votes again
			tracker.Equivocators[sender] = equivocationVote{
				Sender:    oldVote.R.Sender,
				Round:     oldVote.R.Round,
				Period:    oldVote.R.Period,
				Step:      oldVote.R.Step,
				Cred:      oldVote.Cred,
				Proposals: [2]proposalValue{oldVote.R.Proposal, e.Vote.R.Proposal},
				Sigs:      [2]crypto.OneTimeSignature{oldVote.Sig, e.Vote.Sig},
			}
			// delete the equivocator from the set of voters
			delete(tracker.Voters, sender)

			// We've just moved the vote around ( regular vote -> equivocator vote ) but that did not
			// change the total weight. Since the total weight for the proposal in the vote wasn't altered,
			// we know for sure that we haven't reached a threshold for that proposal. ( but maybe for a diffrent one )

			// at this point, we need to check if this is the very last vote or not.
			// if we have no regular votes, we won't be generating a bundle so we can abort right here.
			// note that it might be a legit thing; if we received two votes from X followed by 100 regular votes,
			// we would end up here for the second vote.
			if len(tracker.Voters) == 0 {
				return res
			}
		}

		prop, overAfter := tracker.overThreshold(proto, e.Vote.R.Step)

		if overBefore || !overAfter {
			return res
		}

		// overThreshold is gurentee to return a valid proposal when overAfter is true
		proposalVote := tracker.Counts[prop]

		round := e.Vote.R.roundBranch()
		period := e.Vote.R.Period
		step := e.Vote.R.Step
		switch {
		case step == soft:
			res = thresholdEvent{T: softThreshold, Round: round, Period: period, Step: step, Proposal: prop, Proto: e.Proto}
		case step == cert:
			res = thresholdEvent{T: certThreshold, Round: round, Period: period, Step: step, Proposal: prop, Proto: e.Proto}
		default: // next vote
			res = thresholdEvent{T: nextThreshold, Round: round, Period: period, Step: step, Proposal: prop, Proto: e.Proto}
		}

		res.Bundle = tracker.genBundle(proto, proposalVote)

		return res
	case voteFilterRequest:
		e := e0.(voteFilterRequestEvent)
		eqVote, equivocated := tracker.Equivocators[e.RawVote.Sender]
		if equivocated {
			equivocationDetails := telemetryspec.EquivocatedVoteEventDetails{
				VoterAddress:          e.RawVote.Sender.String(),
				ProposalHash:          e.RawVote.Proposal.BlockDigest.String(),
				Round:                 uint64(e.RawVote.Round),
				Period:                uint64(e.RawVote.Period),
				Step:                  uint64(e.RawVote.Step),
				Weight:                eqVote.Cred.Weight,
				PreviousProposalHash1: eqVote.Proposals[0].BlockDigest.String(),
				PreviousProposalHash2: eqVote.Proposals[1].BlockDigest.String(),
			}
			logging.Base().EventWithDetails(telemetryspec.ApplicationState, telemetryspec.EquivocatedVoteEvent, equivocationDetails)

			return filteredStepEvent{T: voteFilteredStep}
		}

		v, ok := tracker.Voters[e.RawVote.Sender]
		if ok {
			if e.RawVote.Proposal == v.R.Proposal {
				return filteredStepEvent{T: voteFilteredStep}
			}
		}
		return emptyEvent{}
	case dumpVotesRequest:
		votes := make([]unauthenticatedVote, 0, len(tracker.Voters)+2*len(tracker.Equivocators))
		for _, v := range tracker.Voters {
			votes = append(votes, v.u())
		}
		for _, ev := range tracker.Equivocators {
			votes = append(votes, ev.v0().u(), ev.v1().u())
		}

		return dumpVotesEvent{Votes: votes}

	default:
		logging.Base().Panicf("voteTracker: bad event type: observed an event of type %v", e0.t())
		panic("not reached")
	}
}

// overThreshold returns an arbitrary proposal over the step threshold or
// (_, false) if none exists.
func (tracker *voteTracker) overThreshold(proto config.ConsensusParams, step step) (res proposalValue, ok bool) {
	for proposal := range tracker.Counts {
		if step.reachesQuorum(proto, tracker.count(proposal)) {
			if ok {
				logging.Base().Panicf("voteTracker: more than value reached a threhsold in a given step: %v; %v", res, proposal)
			}
			res = proposal
			ok = true
		}
	}
	return
}

// genBundle generates a bundle which proves that a quorum of votes exists for
// the given proposal-value.
func (tracker *voteTracker) genBundle(proto config.ConsensusParams, proposalVotes proposalVoteCounter) (b unauthenticatedBundle) {
	// allocate votes array, with the same size as the proposal votes length.
	votes := make([]vote, len(proposalVotes.Votes))

	// pack the votes into the bundle
	// we pack votes in descending order and stop after packing enough votes to reach a quorum
	i := 0
	for _, v := range proposalVotes.Votes {
		votes[i] = v
		i++
	}
	sort.SliceStable(votes, func(i, j int) bool {
		return votes[i].Cred.Weight > votes[j].Cred.Weight || (votes[i].Cred.Weight == votes[j].Cred.Weight && bytes.Compare(votes[i].R.Sender[:], votes[j].R.Sender[:]) > 0)
	})
	cutoff := 0
	weight := uint64(0)
	for ; !votes[0].R.Step.reachesQuorum(proto, weight) && cutoff < len(votes); cutoff++ {
		weight += votes[cutoff].Cred.Weight
	}
	votes = votes[:cutoff]

	// pack equivocation votes into the bundle
	// similarly to regular votes, we pack them in descending order and stop if we reach a quorum.
	equiPairs := make([]equivocationVote, len(tracker.Equivocators))
	i = 0
	for _, vPair := range tracker.Equivocators {
		equiPairs[i] = vPair
		i++
	}
	sort.SliceStable(equiPairs, func(i, j int) bool {
		return equiPairs[i].Cred.Weight > equiPairs[j].Cred.Weight || (equiPairs[i].Cred.Weight == equiPairs[j].Cred.Weight && bytes.Compare(equiPairs[i].Sender[:], equiPairs[j].Sender[:]) > 0)
	})
	for cutoff = 0; !votes[0].R.Step.reachesQuorum(proto, weight) && cutoff < len(equiPairs); cutoff++ {
		weight += equiPairs[cutoff].Cred.Weight
	}
	equiPairs = equiPairs[:cutoff]

	return makeBundle(proto, votes[0].R.Proposal, votes, equiPairs)
}
