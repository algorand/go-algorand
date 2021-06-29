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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testPartitioning"
)

// this helper object creates threshold events
type nextThresholdHelper struct {
}

func (v *nextThresholdHelper) MakeValidNextThresholdVal(t *testing.T, r round, p period, s step, value proposalValue) thresholdEvent {
	h := voteMakerHelper{}
	h.Setup()
	votes := make([]vote, 0)
	NumNext := next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	for i := 0; i < int(NumNext); i++ {
		// todo: combine all of these helpers into a common test helper location
		vote := h.MakeValidVoteAcceptedVal(t, i, s, value).Vote
		votes = append(votes, vote)
	}
	// don't bother with equipairs for now
	equiPairs := make([]equivocationVote, 0)
	bun := makeBundle(config.Consensus[protocol.ConsensusCurrentVersion], value, votes, equiPairs)
	eType := none
	switch {
	case s == soft:
		eType = softThreshold
	case s == cert:
		eType = certThreshold
	case s >= next:
		eType = nextThreshold
	default:
		t.Fatalf("Unsupported threshold type")
	}
	return thresholdEvent{T: eType, Round: r, Period: p, Step: s, Proposal: value, Bundle: bun}
}

// make a voteTracker at zero state
func makeVoteTrackerPeriodZero() listener {
	return checkedListener{listener: new(voteTrackerPeriod), listenerContract: new(voteTrackerPeriodContract)}
}
func makeVoteTrackerRoundZero() listener {
	return checkedListener{listener: new(voteTrackerRound), listenerContract: new(voteTrackerRoundContract)}
}

func TestVoteTrackerPeriodStepCachedThresholdPrivate(t *testing.T) {
	testPartitioning.PartitionTest(t)

	// goal: generate a next vote bottom quorum for the given period
	// check that Cached is set properly. This is a private
	// state test, this file also ensures that the matching event is generated appropriately.
	helper := voteMakerHelper{}
	helper.Setup()

	NumThreshold := next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	require.Falsef(t, next.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold-1), "Test case malformed; generates too many votes")
	require.Truef(t, next.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold), "Test case malformed; generates too few votes")
	inputVotes := make([]event, NumThreshold)
	expectedOutputs := make([]event, NumThreshold)
	for i := 0; i < len(inputVotes); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, next, bottom)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	// this is just piped up from the vote tracker... (for now)
	expectedOutputs[len(expectedOutputs)-1] = thresholdEvent{T: nextThreshold, Proposal: bottom}
	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	// We need to construct a composition of voteTrackerPeriod (voteMachinePeriod) and
	// a whole set of voteTrackerStep machines... enter the router! (for now)
	perRouter := new(periodRouter)
	perRouter.update(next)

	votePeriodM := &ioAutomataConcrete{
		listener:  perRouter.voteRoot, // start at zero state
		routerCtx: perRouter,
	}
	res, err := testCase.Validate(votePeriodM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Expected threshold event not relayed")

	// now, given that a bottom threshold was emitted, make sure private state was set (so we can appropriately respond to queries)
	vt := perRouter.voteRoot.underlying().(*voteTrackerPeriod)
	require.Truef(t, vt.Cached.Bottom, "VoteTrackerPeriod didn't set bottom to true")

	// now, add votes for next + 1...
	NumThreshold = (next + 1).threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	inputVotes = make([]event, NumThreshold)
	expectedOutputs = make([]event, NumThreshold)
	v := randomBlockHash()
	fixedPVal := proposalValue{BlockDigest: v}
	for i := 0; i < len(inputVotes); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, next+1, fixedPVal)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	expectedOutputs[len(expectedOutputs)-1] = thresholdEvent{T: nextThreshold, Proposal: fixedPVal}
	extensionTestCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	res, err = extensionTestCase.ValidateAsExtension(votePeriodM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Expected threshold event not relayed")

	// make sure private state was updated
	require.Truef(t, vt.Cached.Bottom, "VoteTrackerPeriod should cache fact that it saw bottom")
	require.EqualValuesf(t, fixedPVal, vt.Cached.Proposal, "VoteTrackerPeriod emits wrong proposal value")

}

// add value threshold only, make sure its returned in status
func TestVoteTrackerPeriodValueStatus(t *testing.T) {
	testPartitioning.PartitionTest(t)

	h := nextThresholdHelper{}
	b := testCaseBuilder{}
	v1 := randomBlockHash()
	V1 := proposalValue{BlockDigest: v1}
	in := h.MakeValidNextThresholdVal(t, 1, 1, next, V1)
	b.AddInOutPair(in, emptyEvent{}) // adding a threshold event does not generate meaningful output
	expectedStatus := nextThresholdStatusEvent{Bottom: false, Proposal: V1}
	b.AddInOutPair(nextThresholdStatusRequestEvent{}, expectedStatus)

	votePeriodM := &ioAutomataConcrete{
		listener: makeVoteTrackerPeriodZero(), // start at zero state
	}
	res, err := b.Build().ValidateAsExtension(votePeriodM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Status Message Invalid")
}

// check seen no thresholds
func TestVoteTrackerPeriodNoneSeen(t *testing.T) {
	testPartitioning.PartitionTest(t)

	b := testCaseBuilder{}
	expectedStatus := nextThresholdStatusEvent{Bottom: false, Proposal: bottom}
	b.AddInOutPair(nextThresholdStatusRequestEvent{}, expectedStatus)

	votePeriodM := &ioAutomataConcrete{
		listener: makeVoteTrackerPeriodZero(), // start at zero state
	}
	res, err := b.Build().ValidateAsExtension(votePeriodM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Status Message Invalid")
}

// check seen bottom threshold only
func TestVoteTrackerPeriodBottomOnly(t *testing.T) {
	testPartitioning.PartitionTest(t)

	h := nextThresholdHelper{}
	b := testCaseBuilder{}
	in := h.MakeValidNextThresholdVal(t, 1, 1, next, bottom)
	b.AddInOutPair(in, emptyEvent{}) // adding a threshold event does not generate meaningful output
	expectedStatus := nextThresholdStatusEvent{Bottom: true, Proposal: bottom}
	b.AddInOutPair(nextThresholdStatusRequestEvent{}, expectedStatus)

	votePeriodM := &ioAutomataConcrete{
		listener: makeVoteTrackerPeriodZero(), // start at zero state
	}
	res, err := b.Build().ValidateAsExtension(votePeriodM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Status Message Invalid")
}

// check seen both bottom and value threshodl
func TestVoteTrackerPeriodValueAndBottom(t *testing.T) {
	testPartitioning.PartitionTest(t)

	h := nextThresholdHelper{}
	b := testCaseBuilder{}
	in := h.MakeValidNextThresholdVal(t, 1, 1, next, bottom)
	b.AddInOutPair(in, emptyEvent{})
	v1 := randomBlockHash()
	V1 := proposalValue{BlockDigest: v1}
	in = h.MakeValidNextThresholdVal(t, 1, 1, next, V1)
	b.AddInOutPair(in, emptyEvent{})
	expectedStatus := nextThresholdStatusEvent{Bottom: true, Proposal: V1}
	b.AddInOutPair(nextThresholdStatusRequestEvent{}, expectedStatus)

	votePeriodM := &ioAutomataConcrete{
		listener: makeVoteTrackerPeriodZero(), // start at zero state
	}
	res, err := b.Build().ValidateAsExtension(votePeriodM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Status Message Invalid")
}

/* VoteTrackerRound Tests */

func TestVoteTrackerRoundUpdatesFreshest(t *testing.T) {
	testPartitioning.PartitionTest(t)

	h := nextThresholdHelper{}
	b := testCaseBuilder{}
	v1 := randomBlockHash()
	V1 := proposalValue{BlockDigest: v1}
	in := h.MakeValidNextThresholdVal(t, 1, 1, soft, V1)
	b.AddInOutPair(in, in) // should ack same event back if freshest
	expectedStatus := freshestBundleEvent{Ok: true, Event: in}
	b.AddInOutPair(freshestBundleRequestEvent{}, expectedStatus)

	voteRoundM := &ioAutomataConcrete{
		listener: makeVoteTrackerRoundZero(),
	}
	res, err := b.Build().ValidateAsExtension(voteRoundM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Fresh Message Invalid")
}

func TestVoteTrackerRoundUpdatesFreshestNextOverSoft(t *testing.T) {
	testPartitioning.PartitionTest(t)

	h := nextThresholdHelper{}
	b := testCaseBuilder{}
	v1 := randomBlockHash()
	V1 := proposalValue{BlockDigest: v1}
	// add soft bundle V1 for period 1
	in := h.MakeValidNextThresholdVal(t, 1, 1, soft, V1)
	b.AddInOutPair(in, in) // should ack same event back if freshest
	expectedStatus := freshestBundleEvent{Ok: true, Event: in}
	b.AddInOutPair(freshestBundleRequestEvent{}, expectedStatus)
	// add a next bundle V1 for period 1
	in = h.MakeValidNextThresholdVal(t, 1, 1, next, V1)
	b.AddInOutPair(in, in)
	expectedStatus = freshestBundleEvent{Ok: true, Event: in}
	b.AddInOutPair(freshestBundleRequestEvent{}, expectedStatus)

	voteRoundM := &ioAutomataConcrete{
		listener: makeVoteTrackerRoundZero(),
	}
	res, err := b.Build().ValidateAsExtension(voteRoundM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Fresh Message Invalid")
}

func TestVoteTrackerRoundUpdatesFreshestPeriod(t *testing.T) {
	testPartitioning.PartitionTest(t)

	h := nextThresholdHelper{}
	b := testCaseBuilder{}
	v1 := randomBlockHash()
	V1 := proposalValue{BlockDigest: v1}
	// add a next bundle V1 for period 1
	in := h.MakeValidNextThresholdVal(t, 1, 1, next, V1)
	b.AddInOutPair(in, in)
	expectedStatus := freshestBundleEvent{Ok: true, Event: in}
	b.AddInOutPair(freshestBundleRequestEvent{}, expectedStatus)
	// add a soft bundle V1 for period 2
	in = h.MakeValidNextThresholdVal(t, 1, 2, soft, V1)
	b.AddInOutPair(in, in)
	expectedStatus = freshestBundleEvent{Ok: true, Event: in}
	b.AddInOutPair(freshestBundleRequestEvent{}, expectedStatus)

	voteRoundM := &ioAutomataConcrete{
		listener: makeVoteTrackerRoundZero(),
	}
	res, err := b.Build().ValidateAsExtension(voteRoundM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Period freshness ordering missed")
}

func TestVoteTrackerRoundUpdatesFreshestBot(t *testing.T) {
	testPartitioning.PartitionTest(t)

	h := nextThresholdHelper{}
	b := testCaseBuilder{}
	v1 := randomBlockHash()
	V1 := proposalValue{BlockDigest: v1}
	// add a next bundle V1 for period 1
	in := h.MakeValidNextThresholdVal(t, 1, 1, next, V1)
	b.AddInOutPair(in, in)
	expectedStatus := freshestBundleEvent{Ok: true, Event: in}
	b.AddInOutPair(freshestBundleRequestEvent{}, expectedStatus)
	// add a next bundle bottom for period 2
	botT := h.MakeValidNextThresholdVal(t, 1, 2, next, bottom)
	b.AddInOutPair(botT, botT)
	expectedStatus = freshestBundleEvent{Ok: true, Event: botT}
	b.AddInOutPair(freshestBundleRequestEvent{}, expectedStatus)
	// add a next bundle V1 for period 2
	in = h.MakeValidNextThresholdVal(t, 1, 2, next, V1)
	b.AddInOutPair(in, emptyEvent{}) // not freshest, should refuse
	expectedStatus = freshestBundleEvent{Ok: true, Event: botT}
	b.AddInOutPair(freshestBundleRequestEvent{}, expectedStatus)

	voteRoundM := &ioAutomataConcrete{
		listener: makeVoteTrackerRoundZero(),
	}
	res, err := b.Build().ValidateAsExtension(voteRoundM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Next Value Bottom bundle not fresh enough")
}

func TestVoteTrackerRoundForwardsVoteAccepted(t *testing.T) {
	testPartitioning.PartitionTest(t)

	// check forwards vote accepted, and returns only a fresh bundle
	// this is really a test on the composition of machines. We should build
	// a framework for composing tests instead of writing these e2e's in the future.
	b := testCaseBuilder{}
	helper := voteMakerHelper{}
	helper.Setup()
	v1 := randomBlockHash()
	V1 := proposalValue{BlockDigest: v1}

	NumThreshold := next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	require.Falsef(t, next.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold-1), "Test case malformed; generates too many votes")
	require.Truef(t, next.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold), "Test case malformed; generates too few votes")
	for i := 0; i < int(NumThreshold)-1; i++ {
		b.AddInOutPair(helper.MakeValidVoteAcceptedVal(t, i, next, V1), emptyEvent{})
	}
	b.AddInOutPair(helper.MakeValidVoteAcceptedVal(t, int(NumThreshold)-1, next, V1), thresholdEvent{T: nextThreshold, Proposal: V1})

	// now, add a soft bundle for the same thing; nothing should be emitted since it is less fresh
	NumThreshold = soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	require.Falsef(t, soft.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold-1), "Test case malformed; generates too many votes")
	require.Truef(t, soft.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold), "Test case malformed; generates too few votes")
	for i := 0; i < int(NumThreshold); i++ {
		b.AddInOutPair(helper.MakeValidVoteAcceptedVal(t, i, soft, V1), emptyEvent{})
	}

	// We need to construct a composition of voteTrackerRound, Period and
	// a whole set of voteTrackerStep machines... enter the router! (for now)

	perRouter := new(roundRouter)
	perRouter.update(player{}, 0, false)

	voteRoundM := &ioAutomataConcrete{
		listener:  perRouter.voteRoot,
		routerCtx: perRouter,
	}

	res, err := b.Build().ValidateAsExtension(voteRoundM)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Next Value Bottom bundle not fresh enough")
}
