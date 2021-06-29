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

// todo: test validity of threshold events (incl. bundles)
// todo: test vote weights (and not just number of votes)

// make a voteTracker at zero state
func makeVoteTrackerZero() listener {
	return checkedListener{listener: new(voteTracker), listenerContract: new(voteTrackerContract)}
}

// actual tests

func TestVoteTrackerNoOp(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	voteAcceptEvent := helper.MakeValidVoteAccepted(t, 0, soft)
	testCase := determisticTraceTestCase{
		inputs: []event{
			voteAcceptEvent,
		},
		expectedOutputs: []event{
			thresholdEvent{T: none},
		},
	}

	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Test case 1 did not validate")
}

func TestVoteTrackerSoftQuorum(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	NumThreshold := soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	require.Falsef(t, soft.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold-1), "Test case malformed; generates too many votes")
	require.Truef(t, soft.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold), "Test case malformed; generates too few votes")
	inputVotes := make([]event, NumThreshold)
	expectedOutputs := make([]event, NumThreshold)
	for i := 0; i < len(inputVotes); i++ {
		inputVotes[i] = helper.MakeValidVoteAccepted(t, i, soft)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	// given quorum of soft votes, we expect to see soft threshold
	expectedOutputs[len(expectedOutputs)-1] = thresholdEvent{T: softThreshold, Proposal: *helper.proposal}
	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Threshold event not generated")

	// now, do the same thing, but have one less vote, so expect no threshold
	inputVotes = inputVotes[:len(inputVotes)-1]
	expectedOutputs = expectedOutputs[:len(expectedOutputs)-1]
	testCaseNoThreshold := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata = &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err = testCaseNoThreshold.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Threshold event should not have been generated")
}

// sanity check for cert quorums
func TestVoteTrackerCertQuorum(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	NumThreshold := cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	require.Falsef(t, cert.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold-1), "Test case malformed; generates too many votes")
	require.Truef(t, cert.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold), "Test case malformed; generates too few votes")
	inputVotes := make([]event, NumThreshold)
	expectedOutputs := make([]event, NumThreshold)
	for i := 0; i < len(inputVotes); i++ {
		inputVotes[i] = helper.MakeValidVoteAccepted(t, i, cert)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	expectedOutputs[len(expectedOutputs)-1] = thresholdEvent{T: certThreshold, Proposal: *helper.proposal}
	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Threshold event not generated")

	// now, do the same thing, but have one less vote
	inputVotes = inputVotes[:len(inputVotes)-1]
	expectedOutputs = expectedOutputs[:len(expectedOutputs)-1]
	testCaseNoThreshold := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata = &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err = testCaseNoThreshold.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Threshold event should not have been generated")
}

// sanity check for next quorums
func TestVoteTrackerNextQuorum(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	NumThreshold := next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	require.Falsef(t, next.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold-1), "Test case malformed; generates too many votes")
	require.Truef(t, next.reachesQuorum(config.Consensus[protocol.ConsensusCurrentVersion], NumThreshold), "Test case malformed; generates too few votes")
	inputVotes := make([]event, NumThreshold)
	expectedOutputs := make([]event, NumThreshold)
	for i := 0; i < len(inputVotes); i++ {
		inputVotes[i] = helper.MakeValidVoteAccepted(t, i, next)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	expectedOutputs[len(expectedOutputs)-1] = thresholdEvent{T: nextThreshold, Proposal: *helper.proposal}
	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Threshold event not generated")

	// now, do the same thing, but have one less vote
	inputVotes = inputVotes[:len(inputVotes)-1]
	expectedOutputs = expectedOutputs[:len(expectedOutputs)-1]
	testCaseNoThreshold := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata = &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err = testCaseNoThreshold.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Threshold event should not have been generated")
}

// sanity check propose votes don't trigger anything
func TestVoteTrackerProposeNoOp(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	const NumUpperBound = 2000
	inputVotes := make([]event, NumUpperBound)
	for i := 0; i < len(inputVotes); i++ {
		inputVotes[i] = helper.MakeValidVoteAccepted(t, i, propose)
	}

	// here, each input is a separate test-case
	for i := 0; i < NumUpperBound; i++ {
		testCase := determisticTraceTestCase{
			inputs:          inputVotes[i : i+1],
			expectedOutputs: nil, // we expect the input to panic
		}
		voteTrackerAutomata := &ioAutomataConcrete{
			listener: makeVoteTrackerZero(),
		}

		res, err := testCase.Validate(voteTrackerAutomata)
		require.NoError(t, err, "A vote with step propose did not result in a precondition violation")
		require.NoError(t, res, "A vote with step propose did not result in a precondition violation")
	}
}

func TestVoteTrackerEquivocatorWeightCountedOnce(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	NumThreshold := soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	inputVotes := make([]event, NumThreshold)
	expectedOutputs := make([]event, NumThreshold)
	for i := 0; i < int(NumThreshold-1); i++ {
		inputVotes[i] = helper.MakeValidVoteAccepted(t, i, soft)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	// generate an equivocation
	inputVotes[NumThreshold-1] = helper.MakeValidVoteAccepted(t, 0, soft)
	expectedOutputs[NumThreshold-1] = thresholdEvent{T: none}

	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Threshold event generated due to equivocation double counting")

}

func TestVoteTrackerEquivDoesntReemitThreshold(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	NumThreshold := soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	inputVotes := make([]event, NumThreshold+2)
	expectedOutputs := make([]event, NumThreshold+2)
	for i := 0; i < int(NumThreshold); i++ {
		inputVotes[i] = helper.MakeValidVoteAccepted(t, i, soft)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	expectedOutputs[NumThreshold-1] = thresholdEvent{T: softThreshold, Proposal: *helper.proposal}

	// generate an equivocation
	v := randomBlockHash()
	equivVal := proposalValue{BlockDigest: v}
	require.NotEqualf(t, *helper.proposal, equivVal, "Test does not generate equivocating values...")
	inputVotes[NumThreshold] = helper.MakeValidVoteAcceptedVal(t, 0, soft, equivVal)
	expectedOutputs[NumThreshold] = thresholdEvent{T: none}

	// generate one more valid vote
	inputVotes[NumThreshold+1] = helper.MakeValidVoteAccepted(t, int(NumThreshold+1), soft)
	expectedOutputs[NumThreshold+1] = thresholdEvent{T: none}

	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Extra threshold events generated")
}

func TestVoteTrackerEquivocationsCount(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	// generate an equivocation value pair
	v1 := randomBlockHash()
	equivVal1 := proposalValue{BlockDigest: v1}
	v2 := randomBlockHash()
	equivVal2 := proposalValue{BlockDigest: v2}
	require.NotEqualf(t, equivVal1, equivVal2, "Test does not generate equivocating values...")

	// lets use cert this time...
	NumThreshold := cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	TotalThreshold := NumThreshold + NumThreshold - NumThreshold/2
	inputVotes := make([]event, NumThreshold+NumThreshold/2)
	expectedOutputs := make([]event, NumThreshold+NumThreshold/2)
	// generate threshold/2 non equivocating votes
	for i := 0; i < int(NumThreshold/2); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, cert, equivVal1)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	// generate threshold/2 votes for v2. This shouldn't trigger a threshold event
	for i := int(NumThreshold / 2); i < int(NumThreshold); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, cert, equivVal2)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	// now, for the last threshold/2 votes, have them equivocate for v1. This should generate a threshold event.
	// we may need to update our test case once we implement early next-vote bottom detection.
	for i := int(NumThreshold / 2); i < int(NumThreshold); i++ {
		inputVotes[int(NumThreshold)+i-int(NumThreshold/2)] = helper.MakeValidVoteAcceptedVal(t, i, cert, equivVal1)
		expectedOutputs[int(NumThreshold)+i-int(NumThreshold/2)] = thresholdEvent{T: none}
	}
	expectedOutputs[TotalThreshold-1] = thresholdEvent{T: certThreshold, Proposal: equivVal1}

	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Equivocation adversely affected threshold generation")
}

// same test as before, except equivocations voting v2, v3 should also count towards quorum for v1
func TestVoteTrackerSuperEquivocationsCount(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	// generate an equivocation value triplet
	v1 := randomBlockHash()
	equivVal1 := proposalValue{BlockDigest: v1}
	v2 := randomBlockHash()
	equivVal2 := proposalValue{BlockDigest: v2}
	v3 := randomBlockHash()
	equivVal3 := proposalValue{BlockDigest: v3}
	require.NotEqualf(t, equivVal1, equivVal2, "Test does not generate equivocating values...")
	require.NotEqualf(t, equivVal2, equivVal3, "Test does not generate equivocating values...")
	require.NotEqualf(t, equivVal1, equivVal3, "Test does not generate equivocating values...")

	// lets use cert this time...
	NumThreshold := cert.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	TotalThreshold := NumThreshold + NumThreshold - NumThreshold/2
	inputVotes := make([]event, NumThreshold+NumThreshold/2)
	expectedOutputs := make([]event, NumThreshold+NumThreshold/2)
	// generate threshold/2 non equivocating votes
	for i := 0; i < int(NumThreshold/2); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, cert, equivVal1)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	// generate threshold/2 votes for v2. This shouldn't trigger a threshold event
	for i := int(NumThreshold / 2); i < int(NumThreshold); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, cert, equivVal2)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	// now, for the last threshold/2 votes, have them equivocate for v1. This should generate a threshold event.
	// we may need to update our test case once we implement early next-vote bottom detection.
	for i := int(NumThreshold / 2); i < int(NumThreshold); i++ {
		inputVotes[int(NumThreshold)+i-int(NumThreshold/2)] = helper.MakeValidVoteAcceptedVal(t, i, cert, equivVal3)
		expectedOutputs[int(NumThreshold)+i-int(NumThreshold/2)] = thresholdEvent{T: none}
	}
	expectedOutputs[TotalThreshold-1] = thresholdEvent{T: certThreshold, Proposal: equivVal1}

	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "Equivocation adversely affected threshold generation")
}

// check that SM panics on seeing two quorums
func TestVoteTrackerPanicsOnTwoSoftQuorums(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	// generate an equivocation value pair
	v1 := randomBlockHash()
	equivVal1 := proposalValue{BlockDigest: v1}
	v2 := randomBlockHash()
	equivVal2 := proposalValue{BlockDigest: v2}
	require.NotEqualf(t, equivVal1, equivVal2, "Test does not generate equivocating values...")

	NumThreshold := soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	inputVotes := make([]event, 2*NumThreshold)
	expectedOutputs := make([]event, 2*NumThreshold)
	// generate quorum for v1
	for i := 0; i < int(NumThreshold); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, soft, equivVal1)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	expectedOutputs[NumThreshold-1] = thresholdEvent{T: softThreshold, Proposal: equivVal1}
	// generate quorum for v2
	for i := int(NumThreshold); i < int(2*NumThreshold); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, soft, equivVal2)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	// the last output should be a panic. Express this by shortening expected outputs
	expectedOutputs = expectedOutputs[:2*NumThreshold-1]

	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VoteTracker did not panic on seeing two quorums for v1 != v2")
}

// check that SM panics on seeing soft quorum for bot (currently enforced by contract)
func TestVoteTrackerPanicsOnSoftBotQuorum(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	// generate an equivocation value pair

	NumThreshold := soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	inputVotes := make([]event, NumThreshold)
	expectedOutputs := make([]event, NumThreshold)
	// generate quorum for bot
	for i := 0; i < int(NumThreshold); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, soft, bottom)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	expectedOutputs[NumThreshold-1] = thresholdEvent{T: softThreshold, Proposal: bottom}
	// the last output should be a panic. Express this by shortening expected outputs
	expectedOutputs = expectedOutputs[:NumThreshold-1]

	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VoteTracker did not panic on seeing soft vote bot quorum")
}

// check that SM panics on seeing two next quorums, in particular bot, val in same step.
func TestVoteTrackerPanicsOnTwoNextQuorums(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()

	// generate an equivocation value pair
	v2 := randomBlockHash()
	val2 := proposalValue{BlockDigest: v2}
	require.NotEqualf(t, bottom, val2, "Test does not generate equivocating values...")

	NumThreshold := next.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	inputVotes := make([]event, 2*NumThreshold)
	expectedOutputs := make([]event, 2*NumThreshold)
	// generate quorum for bot
	for i := 0; i < int(NumThreshold); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, next, bottom)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	expectedOutputs[NumThreshold-1] = thresholdEvent{T: nextThreshold, Proposal: bottom}
	// generate quorum for v2
	for i := int(NumThreshold); i < int(2*NumThreshold); i++ {
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, next, val2)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	// the last output should be a panic. Express this by shortening expected outputs
	expectedOutputs = expectedOutputs[:2*NumThreshold-1]

	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VoteTracker did not panic on seeing two quorums for v1 != v2")
}

func TestVoteTrackerRejectsTooManyEquivocators(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()
	Num := soft.threshold(config.Consensus[protocol.ConsensusCurrentVersion])
	inputVotes := make([]event, Num*2)
	expectedOutputs := make([]event, Num*2)
	for i := 0; i < int(2*Num); i++ {
		Val := proposalValue{BlockDigest: randomBlockHash()}
		inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, int(i/2), soft, Val)
		expectedOutputs[i] = thresholdEvent{T: none}
	}
	// We should now have threshold many equivocators... should have panicked when the last equivocation was seen.
	expectedOutputs[2*Num-2] = thresholdEvent{T: softThreshold, Proposal: inputVotes[2*Num-2].(voteAcceptedEvent).Vote.R.Proposal}
	expectedOutputs = expectedOutputs[:2*Num-1]
	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VoteTracker did not reject too many equivocations")
}

/* tests for filtering component of vote tracker */

func TestVoteTrackerFiltersDuplicateVoteOnce(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()
	v1 := randomBlockHash()
	Val1 := proposalValue{BlockDigest: v1}
	const Num = 10
	inputVotes := make([]event, Num+1)
	expectedOutputs := make([]event, Num+1)
	for i := 0; i < int(Num+1); i++ {
		switch {
		case i < Num:
			inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, next, Val1)
			expectedOutputs[i] = thresholdEvent{T: none}
		case i == Num:
			inputVotes[i] = voteFilterRequestEvent{RawVote: inputVotes[Num-1].(voteAcceptedEvent).Vote.R}
			expectedOutputs[i] = filteredStepEvent{T: voteFilteredStep}
		}
	}
	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VoteTracker did not filter duplicate")
}

func TestVoteTrackerForwardsFirstEquivocation(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()
	const V1Bound = 10
	const V2Bound = 20
	const V1V2Bound = 30

	// generate an equivocation value pair
	v1 := randomBlockHash()
	equivVal1 := proposalValue{BlockDigest: v1}
	v2 := randomBlockHash()
	equivVal2 := proposalValue{BlockDigest: v2}
	v3 := randomBlockHash()
	equivVal3 := proposalValue{BlockDigest: v3}
	require.NotEqualf(t, equivVal1, equivVal2, "Test does not generate equivocating values...")
	require.NotEqualf(t, equivVal2, equivVal3, "Test does not generate equivocating values...")
	require.NotEqualf(t, equivVal1, equivVal3, "Test does not generate equivocating values...")

	inputVotes := make([]event, V1V2Bound+1)
	expectedOutputs := make([]event, V1V2Bound+1)
	for i := 0; i < int(V1V2Bound+1); i++ {
		switch {
		case i < V1Bound:
			// these will eventually equivocate
			inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, next, equivVal1)
			expectedOutputs[i] = thresholdEvent{T: none}
		case i == V1Bound:
			// simple duplicate
			inputVotes[i] = voteFilterRequestEvent{RawVote: inputVotes[i-1].(voteAcceptedEvent).Vote.R}
			expectedOutputs[i] = filteredStepEvent{T: voteFilteredStep}
		case i < V2Bound:
			// these dont equivocate
			inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i, next, equivVal2)
			expectedOutputs[i] = thresholdEvent{T: none}
		case i == V2Bound:
			// simple duplicate
			rv := inputVotes[i-1].(voteAcceptedEvent).Vote.R
			inputVotes[i] = voteFilterRequestEvent{RawVote: rv}
			require.EqualValuesf(t, equivVal2, rv.Proposal, "test case is malformed, filtering incorrect vote")
			expectedOutputs[i] = filteredStepEvent{T: voteFilteredStep}
		case i == V2Bound+1:
			// make sure first equivocation is not filtered
			voteTwo := helper.MakeValidVoteAcceptedVal(t, V2Bound-1, next, equivVal1)
			inputVotes[i] = voteFilterRequestEvent{RawVote: voteTwo.Vote.R}
			expectedOutputs[i] = emptyEvent{}
		case i < V1V2Bound:
			// now, add some equivocations
			inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, i-V2Bound, next, equivVal2)
			expectedOutputs[i] = thresholdEvent{T: none}
		case i == V1V2Bound:
			voteThree := helper.MakeValidVoteAcceptedVal(t, 2, next, equivVal3)
			inputVotes[i] = voteFilterRequestEvent{RawVote: voteThree.Vote.R}
			expectedOutputs[i] = filteredStepEvent{T: voteFilteredStep}
		}
	}
	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VoteTracker filtered first equivocation")
}

func TestVoteTrackerFiltersFutureEquivocations(t *testing.T) {
	testPartitioning.PartitionTest(t)

	helper := voteMakerHelper{}
	helper.Setup()
	const Num = 100
	inputVotes := make([]event, Num)
	expectedOutputs := make([]event, Num)
	for i := 0; i < int(Num); i++ {
		switch {
		case i == 0:
			Val := proposalValue{BlockDigest: randomBlockHash()}
			inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, 0, soft, Val)
			expectedOutputs[i] = thresholdEvent{T: none}
		case i == 1:
			// first equivocation should not be filtered
			Val := proposalValue{BlockDigest: randomBlockHash()}
			VA := helper.MakeValidVoteAcceptedVal(t, 0, soft, Val)
			inputVotes[i] = voteFilterRequestEvent{RawVote: VA.Vote.R}
			expectedOutputs[i] = emptyEvent{}
		case i == 2:
			// add an equivocation
			Val := proposalValue{BlockDigest: randomBlockHash()}
			inputVotes[i] = helper.MakeValidVoteAcceptedVal(t, 0, soft, Val)
			expectedOutputs[i] = thresholdEvent{T: none}
		case i < Num:
			// future equivocations should be filtered
			Val := proposalValue{BlockDigest: randomBlockHash()}
			VA := helper.MakeValidVoteAcceptedVal(t, 0, soft, Val)
			inputVotes[i] = voteFilterRequestEvent{RawVote: VA.Vote.R}
			expectedOutputs[i] = filteredStepEvent{T: voteFilteredStep}
		}
	}
	testCase := determisticTraceTestCase{
		inputs:          inputVotes,
		expectedOutputs: expectedOutputs,
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: makeVoteTrackerZero(),
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VoteTracker did not filter equivocations")
}

/* Check that machine panics on unknown event */

func TestVoteTrackerRejectsUnknownEvent(t *testing.T) {
	testPartitioning.PartitionTest(t)

	testCase := determisticTraceTestCase{
		inputs: []event{
			emptyEvent{},
		},
		expectedOutputs: []event{},
	}
	voteTrackerAutomata := &ioAutomataConcrete{
		listener: &voteTracker{}, // we also want the base machine to panic, so don't wrap in contract
	}
	res, err := testCase.Validate(voteTrackerAutomata)
	require.NoError(t, err)
	require.NoErrorf(t, res, "VoteTracker did not reject unknown event")
}
