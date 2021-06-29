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
	"math/rand"
	"sort"
	"testing"

	"github.com/algorand/go-algorand/testpartitioning"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sortedVoteGen(t *testing.T) (votes []vote) {
	ledger, addresses, vrfs, ots := readOnlyFixture100()

	for i, addr := range addresses {
		pv := proposalValue{
			OriginalProposer: addr,
			BlockDigest:      randomBlockHash(),
			EncodingDigest:   randomBlockHash(),
		}
		rv := rawVote{Round: ledger.NextRound(), Sender: addr, Proposal: pv}
		uv, err := makeVote(rv, ots[i], vrfs[i], ledger)
		require.NoError(t, err)
		v, err := uv.verify(ledger)
		if err == nil {
			votes = append(votes, v)
		}
	}

	sort.Slice(votes, func(i, j int) bool {
		return votes[i].Cred.Less(votes[j].Cred)
	})

	return
}

func TestProposalTrackerProposalSeeker(t *testing.T) {
	testpartitioning.PartitionTest(t)

	votes := sortedVoteGen(t)
	for len(votes) < 4 {
		votes = sortedVoteGen(t)
	}

	var s proposalSeeker
	var err error
	assert.False(t, s.Frozen)
	assert.False(t, s.Filled)

	// issue events in the following order: 2, 3, 1, (freeze), 0
	s, err = s.accept(votes[2])
	assert.NoError(t, err)
	assert.False(t, s.Frozen)
	assert.True(t, s.Filled)
	assert.True(t, s.Lowest.equals(votes[2]))

	s, err = s.accept(votes[3])
	assert.Error(t, err)
	assert.False(t, s.Frozen)
	assert.True(t, s.Filled)
	assert.True(t, s.Lowest.equals(votes[2]))

	s, err = s.accept(votes[1])
	assert.NoError(t, err)
	assert.False(t, s.Frozen)
	assert.True(t, s.Filled)
	assert.True(t, s.Lowest.equals(votes[1]))

	s = s.freeze()
	assert.True(t, s.Frozen)
	assert.True(t, s.Filled)
	assert.True(t, s.Lowest.equals(votes[1]))

	s, err = s.accept(votes[0])
	assert.Error(t, err)
	assert.True(t, s.Frozen)
	assert.True(t, s.Filled)
	assert.True(t, s.Lowest.equals(votes[1]))
}

// mimics a proposalTracker, producing a trace of events
type proposalTrackerTestShadow struct {
	// trace
	inputs  []event
	outputs []event

	// all votes seen
	seen map[vote]bool

	// running lowest
	lowest vote

	// frozen?
	frozen bool

	// frozen value
	leader proposalValue

	// staged?
	staged bool

	// staging value
	staging proposalValue

	// round and period (set on init)
	round  round
	period period
}

func makeProposalTrackerTestShadow(r round, p period) *proposalTrackerTestShadow {
	s := new(proposalTrackerTestShadow)
	s.seen = make(map[vote]bool)
	s.round = r
	s.period = p
	return s
}

func makeProposalTrackerZero() listener {
	return checkedListener{listener: new(proposalTracker), listenerContract: new(proposalTrackerContract)}
}

func (s *proposalTrackerTestShadow) execute(t *testing.T, errstr string) {
	testCase := determisticTraceTestCase{
		inputs:          s.inputs,
		expectedOutputs: s.outputs,
	}
	proposalTrackerAutomata := &ioAutomataConcrete{
		listener: makeProposalTrackerZero(),
	}
	res, err := testCase.Validate(proposalTrackerAutomata)
	require.NoError(t, err)

	if res == nil {
		return
	}
	div, ok := res.(errIOTraceDiverge)
	if ok {
		require.Equal(t, div.expected, div.actual, errstr)
	} else {
		require.NoErrorf(t, res, errstr)
	}
}

// assumes sender has not been seen yet
func (s *proposalTrackerTestShadow) addVote(v vote) {
	defer func() {
		// state updates
		s.seen[v] = true
		if s.lowest.R.Proposal == bottom || v.Cred.Less(s.lowest.Cred) {
			s.lowest = v
		}
	}()

	var req, res event
	round := v.R.Round
	period := v.R.Period
	sender := v.R.Sender

	// check seen before
	req = voteFilterRequestEvent{RawVote: v.R}
	res = filteredEvent{T: voteFiltered, Err: makeSerErr(errProposalTrackerSenderDup{Round: round, Period: period})}
	if !s.seen[v] {
		res = emptyEvent{}
	}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)

	// check staging
	req = stagingValueEvent{}
	res = stagingValueEvent{Proposal: s.staging}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)

	// deliver
	req = messageEvent{T: voteVerified, Input: message{Vote: v, UnauthenticatedVote: v.u()}}
	if s.seen[v] {
		res = filteredEvent{T: voteFiltered, Err: makeSerErr(errProposalTrackerSenderDup{Sender: sender, Round: round, Period: period})}
	} else if s.staged {
		res = filteredEvent{T: voteFiltered, Err: makeSerErr(errProposalTrackerStaged{})}
	} else if s.frozen {
		res = filteredEvent{T: voteFiltered, Err: makeSerErr(errProposalTrackerPS{Sub: errProposalSeekerFrozen{}})}
	} else if s.lowest.R.Proposal != bottom && !v.Cred.Less(s.lowest.Cred) {
		sub := errProposalSeekerNotLess{
			NewSender:    v.R.Sender,
			LowestSender: s.lowest.R.Sender,
		}
		res = filteredEvent{T: voteFiltered, Err: makeSerErr(errProposalTrackerPS{Sub: sub})}
	} else {
		res = proposalAcceptedEvent{Round: round, Period: period, Proposal: v.R.Proposal}
	}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)

	// check staging
	req = stagingValueEvent{}
	res = stagingValueEvent{Proposal: s.staging}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)

	// check seen after
	req = voteFilterRequestEvent{RawVote: v.R}
	res = filteredEvent{T: voteFiltered, Err: makeSerErr(errProposalTrackerSenderDup{Sender: sender, Round: round, Period: period})}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)
}

func (s *proposalTrackerTestShadow) freeze() {
	var req, res event

	// check staging
	req = stagingValueEvent{}
	res = stagingValueEvent{Proposal: s.staging}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)

	// freeze
	req = proposalFrozenEvent{}
	res = proposalFrozenEvent{Proposal: s.lowest.R.Proposal}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)
	s.frozen = true
	s.leader = s.lowest.R.Proposal

	// check staging
	req = stagingValueEvent{}
	res = stagingValueEvent{Proposal: s.staging}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)
}

func (s *proposalTrackerTestShadow) stage(pv proposalValue) {
	var req, res event

	// check staging
	req = stagingValueEvent{}
	res = stagingValueEvent{}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)

	// deliver soft threshold
	req = thresholdEvent{T: softThreshold, Proposal: pv}
	res = proposalAcceptedEvent{Round: s.round, Period: s.period, Proposal: pv}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)
	s.staged = true
	s.staging = pv

	// check staging
	req = stagingValueEvent{}
	res = stagingValueEvent{Proposal: pv}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)
}

func (s *proposalTrackerTestShadow) stageWithCert(pv proposalValue) {
	var req, res event

	// check staging
	req = stagingValueEvent{}
	res = stagingValueEvent{}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)

	// deliver cert threshold
	req = thresholdEvent{T: certThreshold, Proposal: pv}
	res = proposalAcceptedEvent{Round: s.round, Period: s.period, Proposal: pv}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)
	s.staged = true
	s.staging = pv

	// check staging
	req = stagingValueEvent{}
	res = stagingValueEvent{Proposal: pv}
	s.inputs = append(s.inputs, req)
	s.outputs = append(s.outputs, res)
}

// create many proposal-votes, sorted in increasing credential-order.
func setupProposalTrackerTests(t *testing.T) (votes []vote) {
	ledger, addrs, vrfs, ots := readOnlyFixture100()
	for i := range addrs {
		prop := proposalValue{
			OriginalPeriod:   0,
			OriginalProposer: addrs[i],
			BlockDigest:      randomBlockHash(),
			EncodingDigest:   randomBlockHash(),
		}

		rv := rawVote{
			Round:    ledger.NextRound(),
			Sender:   addrs[i],
			Proposal: prop,
		}

		uv, err := makeVote(rv, ots[i], vrfs[i], ledger)
		require.NoError(t, err)

		v, err := uv.verify(ledger)
		if err == nil {
			votes = append(votes, v)
		}
	}

	sort.Slice(votes, func(i, j int) bool {
		return votes[i].Cred.Less(votes[j].Cred)
	})

	return
}

func TestProposalTrackerBasic(t *testing.T) {
	testpartitioning.PartitionTest(t)

	votes := setupProposalTrackerTests(t)
	for len(votes) <= 3 {
		votes = setupProposalTrackerTests(t)
	}

	divlow := len(votes) / 3
	divhigh := 2 * divlow

	highvotes := votes[divhigh:]
	rand.Shuffle(len(highvotes), func(i, j int) {
		highvotes[i], highvotes[j] = highvotes[j], highvotes[i]
	})
	midvotes := votes[divlow:divhigh]
	rand.Shuffle(len(midvotes), func(i, j int) {
		midvotes[i], midvotes[j] = midvotes[j], midvotes[i]
	})
	lowvotes := votes[:divlow]
	rand.Shuffle(len(lowvotes), func(i, j int) {
		lowvotes[i], lowvotes[j] = lowvotes[j], lowvotes[i]
	})

	highDelivery := func(shadow *proposalTrackerTestShadow, msg string) {
		for _, v := range highvotes {
			shadow.addVote(v)
		}
		shadow.execute(t, msg)
	}
	midDelivery := func(shadow *proposalTrackerTestShadow, msg string) {
		for _, v := range midvotes {
			shadow.addVote(v)
		}
		shadow.execute(t, msg)
	}
	lowDelivery := func(shadow *proposalTrackerTestShadow, msg string) {
		for _, v := range lowvotes {
			shadow.addVote(v)
		}
		shadow.execute(t, msg)
	}

	// TODO assert more things about the state outside of using the shadow
	t.Run("Synchronous", func(t *testing.T) {
		targetCert := lowvotes[0]
		shadow := makeProposalTrackerTestShadow(votes[0].R.Round, votes[0].R.Period)

		midDelivery(shadow, "failed to track votes properly at zero state")
		highDelivery(shadow, "failed to track votes properly at zero state")
		lowDelivery(shadow, "failed to track votes properly at zero state")

		shadow.freeze()
		shadow.execute(t, "failed to freeze machine properly")

		shadow.stage(targetCert.R.Proposal)
		shadow.execute(t, "failed to deliver soft threshold properly")

	})

	t.Run("MissedLeader", func(t *testing.T) {
		targetCert := midvotes[0]
		shadow := makeProposalTrackerTestShadow(votes[0].R.Round, votes[0].R.Period)

		highDelivery(shadow, "failed to track votes properly at zero state")

		shadow.freeze()
		shadow.execute(t, "failed to freeze machine properly")

		midDelivery(shadow, "failed to track votes properly at zero state after frozen (but not staged)")

		shadow.stage(targetCert.R.Proposal)
		shadow.execute(t, "failed to deliver soft threshold properly")

		lowDelivery(shadow, "failed to track votes properly after staged")
	})

	t.Run("LateStaging", func(t *testing.T) {
		targetCert := midvotes[0]
		shadow := makeProposalTrackerTestShadow(votes[0].R.Round, votes[0].R.Period)

		highDelivery(shadow, "failed to track votes properly at zero state")

		shadow.freeze()
		shadow.execute(t, "failed to freeze machine properly")

		midDelivery(shadow, "failed to track votes properly after frozen (but not staged)")

		shadow.stage(targetCert.R.Proposal)
		shadow.execute(t, "failed to deliver soft threshold properly")

		lowDelivery(shadow, "failed to track votes properly after staged")
	})

	t.Run("EarlyStaging", func(t *testing.T) {
		targetCert := midvotes[0]
		shadow := makeProposalTrackerTestShadow(votes[0].R.Round, votes[0].R.Period)

		shadow.stage(targetCert.R.Proposal)
		shadow.execute(t, "failed to deliver soft threshold properly")

		highDelivery(shadow, "failed to track votes after staged")

		shadow.freeze()
		shadow.execute(t, "failed to freeze machine properly")

		lowDelivery(shadow, "failed to track votes properly after staged")
		midDelivery(shadow, "failed to track votes properly after staged")
	})

	t.Run("EarlyStagingCert", func(t *testing.T) {
		targetCert := midvotes[0]
		shadow := makeProposalTrackerTestShadow(votes[0].R.Round, votes[0].R.Period)

		shadow.stageWithCert(targetCert.R.Proposal)
		shadow.execute(t, "failed to deliver cert threshold properly")

		highDelivery(shadow, "failed to track votes after staged")

		shadow.freeze()
		shadow.execute(t, "failed to freeze machine properly")

		lowDelivery(shadow, "failed to track votes properly after staged")
		midDelivery(shadow, "failed to track votes properly after staged")
	})

	t.Run("LateStagingCert", func(t *testing.T) {
		targetCert := midvotes[0]
		shadow := makeProposalTrackerTestShadow(votes[0].R.Round, votes[0].R.Period)

		highDelivery(shadow, "failed to track votes properly at zero state")

		shadow.freeze()
		shadow.execute(t, "failed to freeze machine properly")

		midDelivery(shadow, "failed to track votes properly after frozen (but not staged)")

		shadow.stageWithCert(targetCert.R.Proposal)
		shadow.execute(t, "failed to deliver soft threshold properly")

		lowDelivery(shadow, "failed to track votes properly after staged")
	})

	t.Run("SynchronousCert", func(t *testing.T) {
		targetCert := lowvotes[0]
		shadow := makeProposalTrackerTestShadow(votes[0].R.Round, votes[0].R.Period)

		midDelivery(shadow, "failed to track votes properly at zero state")
		highDelivery(shadow, "failed to track votes properly at zero state")
		lowDelivery(shadow, "failed to track votes properly at zero state")

		shadow.freeze()
		shadow.execute(t, "failed to freeze machine properly")

		shadow.stageWithCert(targetCert.R.Proposal)
		shadow.execute(t, "failed to deliver cert threshold properly")

	})

}

//   func TestProposalTrackerSenderSpam(t *testing.T) {
//   	votes := setupProposalTrackerTests(t)
//   }
