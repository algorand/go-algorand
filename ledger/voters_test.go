// Copyright (C) 2019-2024 Algorand, Inc.
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

package ledger

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func addBlockToAccountsUpdate(t *testing.T, blk bookkeeping.Block, ml *mockLedgerForTracker) {
	updates := ledgercore.MakeAccountDeltas(1)
	delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
	delta.Accts.MergeAccounts(updates)
	_, totals, err := ml.trackers.accts.LatestTotals()
	require.NoError(t, err)
	delta.Totals = totals
	ml.addBlock(blockEntry{block: blk}, delta)
}

func addRandomBlock(t *testing.T, ml *mockLedgerForTracker) {
	block := randomBlock(ml.Latest() + 1)
	block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
	addBlockToAccountsUpdate(t, block.block, ml)
}

func commitStateProofBlock(t *testing.T, ml *mockLedgerForTracker, stateProofNextRound basics.Round) {
	var stateTracking bookkeeping.StateProofTrackingData
	block := randomBlock(ml.Latest() + 1)
	block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
	stateTracking.StateProofNextRound = stateProofNextRound
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking

	addBlockToAccountsUpdate(t, block.block, ml)
	commitAll(t, ml)
}

func commitAll(t *testing.T, ml *mockLedgerForTracker) {
	dcc := commitSyncPartial(t, ml.trackers.acctsOnline, ml, ml.Latest())
	commitSyncPartialComplete(t, ml.trackers.acctsOnline, ml, dcc)
}

func checkVoters(a *require.Assertions, ao *onlineAccounts, expectedSize uint64) {
	a.Equal(expectedSize, uint64(len(ao.voters.votersForRoundCache)))
	for _, v := range ao.voters.votersForRoundCache {
		err := v.Wait()
		a.NoError(err)
		a.NotZero(v.TotalWeight)
		a.NotZero(len(v.Participants))
		a.NotZero(v.Tree.NumOfElements)
	}
}

func makeRandomOnlineAccounts(numberOfAccounts uint64) map[basics.Address]basics.AccountData {
	res := make(map[basics.Address]basics.AccountData)

	for i := uint64(0); i < numberOfAccounts; i++ {
		var data basics.AccountData

		// Avoid overflowing totals
		data.MicroAlgos.Raw = crypto.RandUint64() % (1 << 32)

		data.Status = basics.Online
		data.VoteLastValid = 10000000

		data.VoteFirstValid = 0
		data.RewardsBase = 0

		res[ledgertesting.RandomAddress()] = data
	}

	return res
}

func TestVoterTrackerDeleteVotersAfterStateproofConfirmed(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	intervalForTest := config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval
	numOfIntervals := config.Consensus[protocol.ConsensusCurrentVersion].StateProofMaxRecoveryIntervals - 1
	lookbackForTest := config.Consensus[protocol.ConsensusCurrentVersion].StateProofVotersLookback

	accts := []map[basics.Address]basics.AccountData{makeRandomOnlineAccounts(20)}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	// To cause all blocks to be committed, for easier processing by the voters tracker.
	conf.MaxAcctLookback = 0
	_, ao := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	i := uint64(1)
	// adding blocks to the voterstracker (in order to pass the numOfIntervals*stateproofInterval we add 1)
	for ; i < (numOfIntervals*intervalForTest)+1; i++ {
		addRandomBlock(t, ml)
	}

	checkVoters(a, ao, numOfIntervals)
	a.Equal(basics.Round(intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	// committing stateproof that confirm the (numOfIntervals - 1)th interval
	commitStateProofBlock(t, ml, basics.Round((numOfIntervals-1)*intervalForTest))

	// the tracker should have 3 entries
	//  - voters to confirm the numOfIntervals - 1 th interval
	//  - voters to confirm the numOfIntervals th interval
	//  - voters to confirm the numOfIntervals + 1  th interval
	checkVoters(a, ao, 3)
	a.Equal(basics.Round((numOfIntervals-2)*intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	commitStateProofBlock(t, ml, basics.Round(numOfIntervals*intervalForTest))

	checkVoters(a, ao, 2)
	a.Equal(basics.Round((numOfIntervals-1)*intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))
}

func TestLimitVoterTracker(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	intervalForTest := config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval
	recoveryIntervalForTests := config.Consensus[protocol.ConsensusCurrentVersion].StateProofMaxRecoveryIntervals
	lookbackForTest := config.Consensus[protocol.ConsensusCurrentVersion].StateProofVotersLookback

	accts := []map[basics.Address]basics.AccountData{makeRandomOnlineAccounts(20)}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	// To cause all blocks to be committed, for easier processing by the voters tracker.
	conf.MaxAcctLookback = 0
	_, ao := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	i := uint64(1)

	// since the first state proof is expected to happen on stateproofInterval*2 we would start give-up on state proofs
	// after intervalForTest*(recoveryIntervalForTests+3) are committed

	// should not give up on any state proof
	for ; i < intervalForTest*(recoveryIntervalForTests+2); i++ {
		addRandomBlock(t, ml)
	}

	commitAll(t, ml)

	// the votersForRoundCache should contains recoveryIntervalForTests+2 elements:
	// recoveryIntervalForTests  - since this is the recovery interval
	// + 1 - since votersForRoundCache would contain the votersForRound for the next state proof to come
	// + 1 - in order to confirm recoveryIntervalForTests number of state proofs we need recoveryIntervalForTests + 1 headers (for the commitment)
	checkVoters(a, ao, recoveryIntervalForTests+2)
	a.Equal(basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	// after adding the round intervalForTest*(recoveryIntervalForTests+3)+1 we expect the voter tracker to remove voters
	for ; i < intervalForTest*(recoveryIntervalForTests+3)+1; i++ {
		addRandomBlock(t, ml)
	}

	commitAll(t, ml)

	checkVoters(a, ao, recoveryIntervalForTests+2)
	a.Equal(basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval*2-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	// after adding the round intervalForTest*(recoveryIntervalForTests+3)+1 we expect the voter tracker to remove voters
	for ; i < intervalForTest*(recoveryIntervalForTests+4)+1; i++ {
		addRandomBlock(t, ml)
	}

	commitAll(t, ml)
	checkVoters(a, ao, recoveryIntervalForTests+2)
	a.Equal(basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval*3-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	// if the last round of the intervalForTest has not been added to the ledger the votersTracker would
	// retain one more element
	for ; i < intervalForTest*(recoveryIntervalForTests+5); i++ {
		addRandomBlock(t, ml)
	}

	commitAll(t, ml)
	checkVoters(a, ao, recoveryIntervalForTests+3)
	a.Equal(basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval*3-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	for ; i < intervalForTest*(recoveryIntervalForTests+5)+1; i++ {
		addRandomBlock(t, ml)
	}

	commitAll(t, ml)
	checkVoters(a, ao, recoveryIntervalForTests+2)
	a.Equal(basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval*4-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))
}

func TestTopNAccountsThatHaveNoMssKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	intervalForTest := config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval
	lookbackForTest := config.Consensus[protocol.ConsensusCurrentVersion].StateProofVotersLookback

	accts := []map[basics.Address]basics.AccountData{makeRandomOnlineAccounts(20)}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	_, ao := newAcctUpdates(t, ml, conf)
	// accountUpdates and onlineAccounts are closed via: ml.Close() -> ml.trackers.close()

	i := uint64(1)
	for ; i < (intervalForTest)+1; i++ {
		addRandomBlock(t, ml)
	}

	top, err := ao.voters.VotersForStateProof(basics.Round(intervalForTest - lookbackForTest))
	a.NoError(err)
	for j := 0; j < len(top.Participants); j++ {
		a.Equal(merklesignature.NoKeysCommitment, top.Participants[j].PK.Commitment)
	}
}

// implements ledgercore.OnlineAccountsFetcher
type testOnlineAccountsFetcher struct {
	topAccts   []*ledgercore.OnlineAccount
	totalStake basics.MicroAlgos
	err        error
}

func (o testOnlineAccountsFetcher) TopOnlineAccounts(rnd basics.Round, voteRnd basics.Round, n uint64, params *config.ConsensusParams, rewardsLevel uint64) (topOnlineAccounts []*ledgercore.OnlineAccount, totalOnlineStake basics.MicroAlgos, err error) {
	return o.topAccts, o.totalStake, o.err
}

func TestLatestCompletedVotersUpToWithError(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	// Set up mock ledger with initial data
	accts := []map[basics.Address]basics.AccountData{makeRandomOnlineAccounts(20)}
	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	_, ao := newAcctUpdates(t, ml, conf)

	// Add several blocks
	for i := uint64(1); i < 10; i++ {
		addRandomBlock(t, ml)
	}
	commitAll(t, ml)

	// Populate votersForRoundCache with test data
	for r := basics.Round(1); r <= 9; r += 2 { // simulate every odd round
		vr := ledgercore.MakeVotersForRound()
		if r%4 == 1 { // Simulate an error for rounds 1, 5, and 9
			vr.BroadcastError(fmt.Errorf("error loading data for round %d", r))
		} else {
			// Simulate a successful load of voter data
			hdr := bookkeeping.BlockHeader{Round: r}
			oaf := testOnlineAccountsFetcher{nil, basics.MicroAlgos{Raw: 1_000_000}, nil}
			require.NoError(t, vr.LoadTree(oaf, hdr))
		}

		ao.voters.setVoters(r, vr)
	}

	// LastCompletedVotersUpTo retrieves the highest round less than or equal to
	// the requested round where data is complete, ignoring rounds with errors.
	for _, tc := range []struct {
		reqRound, retRound uint64
		completed          bool
	}{
		{0, 0, false},
		{1, 0, false},
		{2, 0, false}, // requested 2, no completed rounds <= 2
		{3, 3, true},
		{4, 3, true},
		{5, 3, true}, // requested 5, got 3 (round 5 had error)
		{6, 3, true},
		{7, 7, true}, // requested 7, got 7 (last completed <= 8)
		{8, 7, true}, // requested 8, got 7 (last completed <= 8)
		{9, 7, true}, // requested 9, got 7 (err at 9)
		{10, 7, true},
		{11, 7, true},
	} {
		completedRound, voters := ao.voters.LatestCompletedVotersUpTo(basics.Round(tc.reqRound))
		a.Equal(completedRound, basics.Round(tc.retRound)) // No completed rounds before 2
		a.Equal(voters != nil, tc.completed)
	}

	// Test with errors in all rounds
	ao.voters.votersForRoundCache = make(map[basics.Round]*ledgercore.VotersForRound) // reset map
	for r := basics.Round(1); r <= 9; r += 2 {
		vr := ledgercore.MakeVotersForRound()
		vr.BroadcastError(fmt.Errorf("error loading data for round %d", r))
		ao.voters.setVoters(r, vr)
	}

	completedRound, voters := ao.voters.LatestCompletedVotersUpTo(basics.Round(9))
	a.Equal(basics.Round(0), completedRound) // No completed rounds due to errors
	a.Nil(voters)
}
