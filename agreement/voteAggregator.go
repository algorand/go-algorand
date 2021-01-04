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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// A voteAggregator is a voteMachine which applies relay rules to incoming votes
// and converts accepted votes into thresholdEvents.
//
// It handles the following type(s) of event: votePresent, voteVerified,
// bundlePresent, and bundleVerified.
// It returns the following type(s) of event: none, vote{Filtered,Malformed},
// bundle{Filtered,Malformed}, and {soft,cert,next}Threshold.
type voteAggregator struct{}

func (agg *voteAggregator) T() stateMachineTag {
	return voteMachine
}

func (agg *voteAggregator) underlying() listener {
	return agg
}

// A voteAggregator handles four types of events:
//
//  - votePresent is issued when a new vote arrives at the state machine.  A
//    voteFiltered event is emitted in response if the vote is either stale or
//    an equivocating duplicate.  Otherwise an empty event is returned.
//
//  - voteVerified is issued after the agreement service has attempted
//    cryptographic verification on a given vote.
//     - A voteMalformed event is emitted if the ill-formed vote was the result
//       of some corrupt process.
//     - A voteFiltered event is emitted if the vote is either stale or an
//       equivocating duplicate.
//     - Otherwise, the vote is observed. thresholdEvents occur in the current
//       round are propagated up to the parent, while thresholdEvents that occur
//       the next round are pipelined for the next round.
//
//  - bundlePresent is issued when a new bundle arrives at the state machine.  A
//    bundleFiltered event is emitted in response if the bundle is stale.
//    Otherwise an empty event is returned.
//
//  - bundleVerified is issued after agreement service has attempted
//    cryptographic verification on a given bundle.
//     - A bundleMalformed event is emitted if the ill-formed bundle was the
//       result of some corrupt process.
//     - A bundleFiltered event is emitted if the bundle is stale.
//     - Otherwise, the bundle is observed.  If observing the bundle causes a
//       thresholdEvent to occur, the thresholdEvent is propagated to the
//       parent.  Otherwise, a bundleFiltered event is propagated to the parent.
func (agg *voteAggregator) handle(r routerHandle, pr player, em event) (res event) {
	e := em.(filterableMessageEvent)
	defer func() {
		r.t.logVoteAggregatorResult(e, res)
	}()

	switch e.t() {
	case votePresent:
		if e.Proto.Err != nil {
			return filteredEvent{T: voteFiltered, Err: e.Proto.Err}
		}

		uv := e.Input.UnauthenticatedVote
		err := agg.filterVote(e.Proto.Version, pr, r, uv, e.FreshnessData)
		if err != nil {
			return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		}
		return emptyEvent{}

	case voteVerified:
		if e.Cancelled {
			return filteredEvent{T: voteFiltered, Err: e.Err}
		}
		if e.Proto.Err != nil {
			return filteredEvent{T: voteFiltered, Err: e.Err}
		}
		if e.Err != nil {
			return filteredEvent{T: voteMalformed, Err: e.Err}
		}
		v := e.Input.Vote
		err := agg.filterVote(e.Proto.Version, pr, r, v.u(), e.FreshnessData)
		if err != nil {
			return filteredEvent{T: voteFiltered, Err: makeSerErr(err)}
		}
		if v.R.Round == pr.Round {
			r.t.timeR().RecVoteReceived(v)
		} else if v.R.Round == pr.Round+1 {
			r.t.timeRPlus1().RecVoteReceived(v)
		}

		deliver := voteAcceptedEvent{Vote: v, Proto: e.Proto.Version}
		tE := r.dispatch(pr, deliver, voteMachineRound, v.R.Round, v.R.Period, v.R.Step)
		if tE.t() == none {
			return tE
		}
		if tE.(thresholdEvent).Round == e.FreshnessData.PlayerRound {
			return tE
		} else if tE.(thresholdEvent).Round == e.FreshnessData.PlayerRound+1 {
			return emptyEvent{}
		}
		logging.Base().Panicf("bad round (%v, %v)", tE.(thresholdEvent).Round, e.FreshnessData.PlayerRound) // TODO this should be a postcondition check; move it

	case bundlePresent:
		ub := e.Input.UnauthenticatedBundle
		err := agg.filterBundle(ub, e.FreshnessData)
		if err != nil {
			return filteredEvent{T: bundleFiltered, Err: makeSerErr(err)}
		}
		return emptyEvent{}

	case bundleVerified:
		if e.Cancelled {
			return filteredEvent{T: bundleFiltered, Err: e.Err}
		}
		if e.Proto.Err != nil {
			return filteredEvent{T: bundleFiltered, Err: e.Err}
		}
		if e.Err != nil {
			return filteredEvent{T: bundleMalformed, Err: e.Err}
		}

		b := e.Input.Bundle
		err := agg.filterBundle(b.u(), e.FreshnessData)
		if err != nil {
			return filteredEvent{T: bundleFiltered, Err: makeSerErr(err)}
		}

		// Constuct a single votes list by combining the validated votes and equivocated votes into a single votes list.
		// TODO : is that really the best thing to do ? once we have validated that these are valid equivocated votes
		// we don't want to add them one by one to the voteTracker. Instead, we want to add the pair and let the
		// voteTracker do the special equivocated votes handling. ( otherwise, we're forcing adding a vote followed by
		// an "upgrade" from a regular vote into an equivocated vote )
		votes := make([]vote, len(b.Votes)+2*len(b.EquivocationVotes))
		copy(votes, b.Votes) // i.e., make a copy of b.Votes
		votesIdx := len(b.Votes)
		for _, pair := range b.EquivocationVotes {
			votes[votesIdx+0] = pair.v0()
			votes[votesIdx+1] = pair.v1()
			votesIdx += 2
		}

		// Send each of the votes in this bundle to the vote tracker, and keep track
		// of any threshold events. Play all votes so that we don't accidentally stop
		// partway through an equivocation vote
		var threshEvent event
		for _, vote := range votes {
			deliver := voteAcceptedEvent{Vote: vote, Proto: e.Proto.Version}
			e := r.dispatch(pr, deliver, voteMachineRound, vote.R.Round, vote.R.Period, vote.R.Step)
			switch e.t() {
			case softThreshold, certThreshold, nextThreshold:
				threshEvent = e
			}
		}

		// If we reached a threshold, return
		if threshEvent != nil {
			return threshEvent
		}

		smErr := makeSerErrf("bundle for (%v, %v, %v: %v) failed to cause a significant state change", b.U.Round, b.U.Period, b.U.Step, b.U.Proposal)
		return filteredEvent{T: bundleFiltered, Err: smErr}
	}
	logging.Base().Panicf("voteAggregator: bad event type: observed an event of type %v", e.t())
	panic("not reached")
}

// filterVote filters a vote, checking if it is fresh, and also asks the voteMachineStep for its input,
// to ensure we don't relay duplicate or redundant votes.
func (agg *voteAggregator) filterVote(proto protocol.ConsensusVersion, p player, r routerHandle, uv unauthenticatedVote, freshData freshnessData) error {
	err := voteFresh(proto, freshData, uv)
	if err != nil {
		return fmt.Errorf("voteAggregator: rejected vote due to age: %v", err)
	}
	filterReq := voteFilterRequestEvent{RawVote: uv.R}
	filterRes := r.dispatch(p, filterReq, voteMachineStep, uv.R.Round, uv.R.Period, uv.R.Step)
	switch filterRes.t() {
	case voteFilteredStep:
		// we'll rebuild the filtered event later
		return fmt.Errorf("voteAggregator: rejected vote: sender %v had already sent a vote in round %d period %d step %d", uv.R.Sender, uv.R.Round, uv.R.Period, uv.R.Step)
	case none:
		return nil
	}
	logging.Base().Panicf("voteAggregator: bad event type: while filtering, observed an event of type %v", filterRes.t())
	panic("not reached")
}

// filterBundle filters a bundle, checking if it is fresh.
// TODO consider optimizing recovery by filtering bundles for some value if we
// have already seen the threshold met for that value.  This will filter
// repeated bundles sent by honest peers.
func (agg *voteAggregator) filterBundle(ub unauthenticatedBundle, freshData freshnessData) error {
	err := bundleFresh(freshData, ub)
	if err != nil {
		return fmt.Errorf("voteAggregator: rejected bundle due to age: %v", err)
	}

	return nil
}

// voteStepFresh is a helper function for vote relay rules.  Votes from steps
// [soft, next] are always propagated, as are votes from [s-1, s+1] where s is
// the current/last concluding step. Set mine to 0 to effectively disable allowing
// votes adjacent to the current/last concluding step.
func voteStepFresh(descr string, proto protocol.ConsensusVersion, mine, vote step) error {
	if vote <= next {
		// always propagate first recovery vote to ensure synchronous block of periods after partition
		return nil
	}
	if config.Consensus[proto].FastPartitionRecovery && vote >= late {
		// always propagate fast partition recovery votes
		return nil
	}

	if mine != 0 && mine-1 > vote {
		return fmt.Errorf("filtered stale vote %s: step %d - 1 > %d", descr, mine, vote)
	}
	if mine+1 < vote {
		return fmt.Errorf("filtered premature vote %s: step %d + 1 < %d", descr, mine, vote)
	}

	return nil
}

// voteFresh determines whether a vote satisfies freshness rules.
func voteFresh(proto protocol.ConsensusVersion, freshData freshnessData, vote unauthenticatedVote) error {
	if freshData.PlayerRound != vote.R.Round && freshData.PlayerRound+1 != vote.R.Round {
		return fmt.Errorf("filtered vote from bad round: player.Round=%v; vote.Round=%v", freshData.PlayerRound, vote.R.Round)
	}

	if freshData.PlayerRound+1 == vote.R.Round {
		if vote.R.Period > 0 {
			return fmt.Errorf("filtered future vote from bad period: player.Round=%v; vote.(Round,Period,Step)=(%v,%v,%v)", freshData.PlayerRound, vote.R.Round, vote.R.Period, vote.R.Step)
		}
		// pipeline votes from next round period 0
		return voteStepFresh("from next round", proto, 0, vote.R.Step)
	}

	switch vote.R.Period {
	case freshData.PlayerPeriod - 1:
		if freshData.PlayerPeriod != 0 {
			return voteStepFresh("from previous period", proto, freshData.PlayerLastConcluding, vote.R.Step)
		}
	case freshData.PlayerPeriod:
		return voteStepFresh("from period", proto, freshData.PlayerStep, vote.R.Step)
	case freshData.PlayerPeriod + 1:
		// has the effect of rejecting all votes except for the ones from steps which are always propagated
		return voteStepFresh("from next period", proto, soft, vote.R.Step)
	}

	return fmt.Errorf("filtered vote from bad period: p.Period=%v, vote.Period=%v", freshData.PlayerPeriod, vote.R.Period)

}

// bundleFresh determines whether a bundle satisfies freshness rules.
func bundleFresh(freshData freshnessData, b unauthenticatedBundle) error {
	if freshData.PlayerRound != b.Round {
		return fmt.Errorf("filtered bundle from different round: round %d != %d", freshData.PlayerRound, b.Round)
	}

	if b.Step == cert {
		return nil
	}

	if freshData.PlayerPeriod != 0 && freshData.PlayerPeriod-1 > b.Period {
		return fmt.Errorf("filtered stale bundle: period %d >= %d", freshData.PlayerPeriod, b.Period)
	}

	return nil
}
