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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func randomBlocksWithStateproof(currentRound uint64) bookkeeping.Block {
	interval := config.Consensus[protocol.ConsensusFuture].StateProofInterval

	block := randomBlock(basics.Round(currentRound))
	block.block.CurrentProtocol = protocol.ConsensusFuture
	if currentRound%interval != 0 && currentRound%(interval/2) == 0 {
		var stateTracking bookkeeping.StateProofTrackingData
		block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
		block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	}
	return block.block
}

func addBlockToAccountsUpdate(blk bookkeeping.Block, au *accountUpdates) {
	updates := ledgercore.MakeAccountDeltas(1)
	delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
	au.newBlock(blk, delta)
}

func TestVoterCleanAfterStateproofCommitted(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	intervalForTest := config.Consensus[protocol.ConsensusFuture].StateProofInterval
	numOfIntervals := config.Consensus[protocol.ConsensusFuture].StateProofRecoveryInterval - 1
	lookbackForTest := config.Consensus[protocol.ConsensusFuture].StateProofVotersLookback

	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}

	pooldata := basics.AccountData{}
	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	pooldata.Status = basics.NotParticipating
	accts[0][testPoolAddr] = pooldata

	sinkdata := basics.AccountData{}
	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
	sinkdata.Status = basics.NotParticipating
	accts[0][testSinkAddr] = sinkdata

	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusFuture, accts)
	defer ml.Close()

	conf := config.GetDefaultLocal()
	au := newAcctUpdates(t, ml, conf, ".")
	defer au.close()

	i := uint64(1)
	// adding blocks to the voterstracker (in order to pass the numOfIntervals*stateproofInterval we add 1)
	for ; i < (numOfIntervals*intervalForTest)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusFuture
		addBlockToAccountsUpdate(block.block, au)
	}

	a.Equal(numOfIntervals, uint64(len(au.voters.votersForRound)))
	a.Equal(basics.Round(intervalForTest-lookbackForTest), au.voters.lowestRound(basics.Round(i)))

	block := randomBlock(basics.Round(i))
	i++
	block.block.CurrentProtocol = protocol.ConsensusFuture

	// committing stateproof that confirm the (numOfIntervals - 1)th interval
	var stateTracking bookkeeping.StateProofTrackingData
	stateTracking.StateProofNextRound = basics.Round((numOfIntervals - 1) * intervalForTest)
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	addBlockToAccountsUpdate(block.block, au)

	// the tracker should have two entries
	//  - voters to confirm the numOfIntervals th interval
	//  - voters to confirm the numOfIntervals + 1  th interval
	a.Equal(uint64(2), uint64(len(au.voters.votersForRound)))
	a.Equal(basics.Round(intervalForTest*(numOfIntervals-1)-lookbackForTest), au.voters.lowestRound(basics.Round(i)))

	block = randomBlock(basics.Round(i))
	block.block.CurrentProtocol = protocol.ConsensusFuture
	stateTracking.StateProofNextRound = basics.Round(numOfIntervals * intervalForTest)
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	addBlockToAccountsUpdate(block.block, au)

	a.Equal(uint64(1), uint64(len(au.voters.votersForRound)))
	a.Equal(basics.Round(intervalForTest*(numOfIntervals)-lookbackForTest), au.voters.lowestRound(basics.Round(i)))
}

//
//func TestVoterCleanAfterStateproofCommittedRealData(t *testing.T) {
//	partitiontest.PartitionTest(t)
//	a := require.New(t)
//
//	intervalForTest := config.Consensus[protocol.ConsensusFuture].StateProofInterval
//
//	accts := []map[basics.Address]basics.AccountData{ledgertesting.RandomAccounts(20, true)}
//	rewardsLevels := []uint64{0}
//
//	pooldata := basics.AccountData{}
//	pooldata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
//	pooldata.Status = basics.NotParticipating
//	accts[0][testPoolAddr] = pooldata
//
//	sinkdata := basics.AccountData{}
//	sinkdata.MicroAlgos.Raw = 1000 * 1000 * 1000 * 1000
//	sinkdata.Status = basics.NotParticipating
//	accts[0][testSinkAddr] = sinkdata
//
//	ml := makeMockLedgerForTracker(t, true, int(intervalForTest)-1, protocol.ConsensusFuture, accts)
//	defer ml.Close()
//
//	conf := config.GetDefaultLocal()
//	au := newAcctUpdates(t, ml, conf, ".")
//	defer au.close()
//
//	// cover 10 genesis blocks
//	rewardLevel := uint64(0)
//	i := uint64(1)
//	for ; i < intervalForTest-1; i++ {
//		accts = append(accts, accts[0])
//		rewardsLevels = append(rewardsLevels, rewardLevel)
//	}
//
//	for ; i < intervalForTest+(20*intervalForTest); i++ {
//		blk := randomBlocksWithStateproof(i)
//		account, newReward := addBlockToAccountsUpdateWithRealAccounts(blk, rewardLevel, accts, au, a)
//		accts = append(accts, account)
//		rewardsLevels = append(rewardsLevels, newReward)
//		rewardLevel = newReward
//	}
//
//	block := randomBlock(basics.Round(intervalForTest + 20*intervalForTest))
//	block.block.CurrentProtocol = protocol.ConsensusFuture
//
//	var stateTracking bookkeeping.StateProofTrackingData
//	stateTracking.StateProofNextRound = basics.Round(21 * intervalForTest)
//	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
//	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
//
//	a.Equal(len(au.voters.votersForRound), 20)
//	addBlockToAccountsUpdateWithRealAccounts(block.block, rewardLevel, accts, au, a)
//
//	fmt.Println(len(au.voters.votersForRound))
//}
//
//func addBlockToAccountsUpdateWithRealAccounts(blk bookkeeping.Block, rewardLevel uint64, accts []map[basics.Address]basics.AccountData, au *accountUpdates, a *require.Assertions) (map[basics.Address]basics.AccountData, uint64) {
//	rnd := blk.Round()
//
//	rewardLevelDelta := crypto.RandUint64() % 5
//	rewardLevel += rewardLevelDelta
//
//	blk.RewardsLevel = rewardLevel
//	updates, totals := ledgertesting.RandomDeltasBalanced(1, accts[rnd-1], rewardLevel)
//	prevRound, prevTotals, err := au.LatestTotals()
//	a.Equal(rnd-1, prevRound)
//	a.NoError(err)
//
//	newPool := totals[testPoolAddr]
//	newPool.MicroAlgos.Raw -= prevTotals.RewardUnits()
//	updates.Upsert(testPoolAddr, newPool)
//	totals[testPoolAddr] = newPool
//	newAccts := applyPartialDeltas(accts[rnd-1], updates)
//
//	delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
//	delta.Accts.MergeAccounts(updates)
//	au.newBlock(blk, delta)
//	return newAccts, rewardLevel
//}
