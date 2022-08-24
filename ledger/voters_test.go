// Copyright (C) 2019-2022 Algorand, Inc.
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

func addBlockToAccountsUpdate(blk bookkeeping.Block, ao *onlineAccounts, totals ledgercore.AccountTotals) {
	updates := ledgercore.MakeAccountDeltas(1)
	delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
	delta.Accts.MergeAccounts(updates)
	delta.Totals = totals
	ao.newBlock(blk, delta)
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
	au, ao := newAcctUpdates(t, ml, conf)
	defer au.close()
	defer ao.close()

	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	i := uint64(1)
	// adding blocks to the voterstracker (in order to pass the numOfIntervals*stateproofInterval we add 1)
	for ; i < (numOfIntervals*intervalForTest)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
		addBlockToAccountsUpdate(block.block, ao, totals)
	}

	checkVoters(a, ao, numOfIntervals)
	a.Equal(basics.Round(intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	block := randomBlock(basics.Round(i))
	i++
	block.block.CurrentProtocol = protocol.ConsensusCurrentVersion

	// committing stateproof that confirm the (numOfIntervals - 1)th interval
	var stateTracking bookkeeping.StateProofTrackingData
	stateTracking.StateProofNextRound = basics.Round((numOfIntervals - 1) * intervalForTest)
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	addBlockToAccountsUpdate(block.block, ao, totals)

	// the tracker should have 3 entries
	//  - voters to confirm the numOfIntervals - 1 th interval
	//  - voters to confirm the numOfIntervals th interval
	//  - voters to confirm the numOfIntervals + 1  th interval
	checkVoters(a, ao, 3)
	a.Equal(basics.Round((numOfIntervals-2)*intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	block = randomBlock(basics.Round(i))
	block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
	stateTracking.StateProofNextRound = basics.Round(numOfIntervals * intervalForTest)
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	addBlockToAccountsUpdate(block.block, ao, totals)

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
	au, ao := newAcctUpdates(t, ml, conf)
	defer au.close()
	defer ao.close()

	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	i := uint64(1)

	// since the first state proof is expected to happen on stateproofInterval*2 we would start give-up on state proofs
	// after intervalForTest*(recoveryIntervalForTests+3)

	// should not give up on any state proof
	for ; i < intervalForTest*(recoveryIntervalForTests+2); i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
		addBlockToAccountsUpdate(block.block, ao, totals)
	}

	// the votersForRoundCache should contains recoveryIntervalForTests+2 elements:
	// recoveryIntervalForTests  - since this is the recovery interval
	// + 1 - since votersForRoundCache would contain the votersForRound for the next state proof to come
	// + 1 - in order to confirm recoveryIntervalForTests number of state proofs we need recoveryIntervalForTests + 1 headers (for the commitment)
	checkVoters(a, ao, recoveryIntervalForTests+2)
	a.Equal(basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	// after adding the round intervalForTest*(recoveryIntervalForTests+3)+1 we expect the voter tracker to remove voters
	for ; i < intervalForTest*(recoveryIntervalForTests+3)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
		addBlockToAccountsUpdate(block.block, ao, totals)
	}

	checkVoters(a, ao, recoveryIntervalForTests+2)
	a.Equal(basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval*2-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	// after adding the round intervalForTest*(recoveryIntervalForTests+3)+1 we expect the voter tracker to remove voters
	for ; i < intervalForTest*(recoveryIntervalForTests+4)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
		addBlockToAccountsUpdate(block.block, ao, totals)
	}
	checkVoters(a, ao, recoveryIntervalForTests+2)
	a.Equal(basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval*3-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	// if the last round of the intervalForTest has not been added to the ledger the votersTracker would
	// retain one more element
	for ; i < intervalForTest*(recoveryIntervalForTests+5); i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
		addBlockToAccountsUpdate(block.block, ao, totals)
	}
	checkVoters(a, ao, recoveryIntervalForTests+3)
	a.Equal(basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval*3-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	for ; i < intervalForTest*(recoveryIntervalForTests+5)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
		addBlockToAccountsUpdate(block.block, ao, totals)
	}
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
	au, ao := newAcctUpdates(t, ml, conf)
	defer au.close()
	defer ao.close()

	_, totals, err := au.LatestTotals()
	require.NoError(t, err)

	i := uint64(1)
	for ; i < (intervalForTest)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
		addBlockToAccountsUpdate(block.block, ao, totals)
	}

	top, err := ao.voters.getVoters(basics.Round(intervalForTest - lookbackForTest))
	a.NoError(err)
	for j := 0; j < len(top.Participants); j++ {
		a.Equal(merklesignature.NoKeysCommitment, top.Participants[j].PK.Commitment)
	}
}
