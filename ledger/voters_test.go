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
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func addBlockToAccountsUpdate(blk bookkeeping.Block, ao *onlineAccounts) {
	updates := ledgercore.MakeAccountDeltas(1)
	delta := ledgercore.MakeStateDelta(&blk.BlockHeader, 0, updates.Len(), 0)
	ao.newBlock(blk, delta)
}

func TestVoterTrackerDeleteVotersAfterStateproofConfirmed(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	intervalForTest := config.Consensus[protocol.ConsensusFuture].StateProofInterval
	numOfIntervals := config.Consensus[protocol.ConsensusFuture].StateProofMaxRecoveryIntervals - 1
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
	au, ao := newAcctUpdates(t, ml, conf, ".")
	defer au.close()
	defer ao.close()

	i := uint64(1)
	// adding blocks to the voterstracker (in order to pass the numOfIntervals*stateproofInterval we add 1)
	for ; i < (numOfIntervals*intervalForTest)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusFuture
		addBlockToAccountsUpdate(block.block, ao)
	}

	a.Equal(numOfIntervals, uint64(len(ao.voters.votersForRoundCache)))
	a.Equal(basics.Round(intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	block := randomBlock(basics.Round(i))
	i++
	block.block.CurrentProtocol = protocol.ConsensusFuture

	// committing stateproof that confirm the (numOfIntervals - 1)th interval
	var stateTracking bookkeeping.StateProofTrackingData
	stateTracking.StateProofNextRound = basics.Round((numOfIntervals - 1) * intervalForTest)
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	addBlockToAccountsUpdate(block.block, ao)

	// the tracker should have 3 entries
	//  - voters to confirm the numOfIntervals - 1 th interval
	//  - voters to confirm the numOfIntervals th interval
	//  - voters to confirm the numOfIntervals + 1  th interval
	a.Equal(uint64(3), uint64(len(ao.voters.votersForRoundCache)))
	a.Equal(basics.Round((numOfIntervals-2)*intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	block = randomBlock(basics.Round(i))
	block.block.CurrentProtocol = protocol.ConsensusFuture
	stateTracking.StateProofNextRound = basics.Round(numOfIntervals * intervalForTest)
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	addBlockToAccountsUpdate(block.block, ao)

	a.Equal(uint64(2), uint64(len(ao.voters.votersForRoundCache)))
	a.Equal(basics.Round((numOfIntervals-1)*intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))
}

func TestLimitVoterTracker(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	intervalForTest := config.Consensus[protocol.ConsensusFuture].StateProofInterval
	recoveryIntervalForTests := config.Consensus[protocol.ConsensusFuture].StateProofMaxRecoveryIntervals
	numOfIntervals := recoveryIntervalForTests
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
	au, ao := newAcctUpdates(t, ml, conf, ".")
	defer au.close()
	defer ao.close()

	i := uint64(1)
	// adding blocks to the voterstracker (in order to pass the numOfIntervals*stateproofInterval we add 1)
	for ; i < (numOfIntervals*intervalForTest)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusFuture
		addBlockToAccountsUpdate(block.block, ao)
	}

	a.Equal(recoveryIntervalForTests, uint64(len(ao.voters.votersForRoundCache)))
	a.Equal(basics.Round(((i/intervalForTest)-recoveryIntervalForTests+1)*intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	// we add numOfIntervals*intervalForTest more blocks. the voter should have only recoveryIntervalForTests number of elements
	for ; i < 2*(numOfIntervals*intervalForTest)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusFuture
		addBlockToAccountsUpdate(block.block, ao)
	}

	a.Equal(recoveryIntervalForTests+1, uint64(len(ao.voters.votersForRoundCache)))
	a.Equal(basics.Round(((i/intervalForTest)-recoveryIntervalForTests)*intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))

	// we add numOfIntervals*intervalForTest more blocks. the voter should have only recoveryIntervalForTests number of elements
	for ; i < 3*(numOfIntervals*intervalForTest)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusFuture
		addBlockToAccountsUpdate(block.block, ao)
	}

	a.Equal(recoveryIntervalForTests+1, uint64(len(ao.voters.votersForRoundCache)))
	a.Equal(basics.Round(((i/intervalForTest)-recoveryIntervalForTests)*intervalForTest-lookbackForTest), ao.voters.lowestRound(basics.Round(i)))
}

func TestTopNAccountsThatHaveNoMssKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	intervalForTest := config.Consensus[protocol.ConsensusFuture].StateProofInterval
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
	au, ao := newAcctUpdates(t, ml, conf, ".")
	defer au.close()
	defer ao.close()

	i := uint64(1)
	for ; i < (intervalForTest)+1; i++ {
		block := randomBlock(basics.Round(i))
		block.block.CurrentProtocol = protocol.ConsensusFuture
		addBlockToAccountsUpdate(block.block, ao)
	}

	top, err := ao.voters.getVoters(basics.Round(intervalForTest - lookbackForTest))
	a.NoError(err)
	for j := 0; j < len(top.Participants); j++ {
		a.Equal(merklesignature.NoKeysCommitment, top.Participants[j].PK.Commitment)
	}
}
