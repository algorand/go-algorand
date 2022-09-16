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
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var defaultRoundsInterval = basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval)

func initializeLedgerSpt(t *testing.T) (*mockLedgerForTracker, *stateProofVerificationTracker) {
	a := require.New(t)
	accts := []map[basics.Address]basics.AccountData{makeRandomOnlineAccounts(20)}

	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, accts)

	spt := stateProofVerificationTracker{}

	conf := config.GetDefaultLocal()

	_, err := trackerDBInitialize(ml, false, ".")
	a.NoError(err)
	err = ml.trackers.initialize(ml, []ledgerTracker{&spt}, conf)
	a.NoError(err)
	err = ml.trackers.loadFromDisk(ml)

	return ml, &spt
}

func genesisBlock() *blockEntry {
	initialRound := basics.Round(1)
	block := randomBlock(initialRound)

	var stateTracking bookkeeping.StateProofTrackingData
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)

	stateTracking.StateProofNextRound = defaultRoundsInterval * 2
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking

	return &block
}

func blockStateProofsEnabled(prevBlock *blockEntry, stuckStateProofs bool) blockEntry {
	round := prevBlock.block.Round() + 1
	prevBlockLastAttestedRound := prevBlock.block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound

	block := randomBlock(round)
	block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
	blockStateProofInterval := basics.Round(block.block.ConsensusProtocol().StateProofInterval)

	var stateTracking bookkeeping.StateProofTrackingData
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)

	if !stuckStateProofs && round > prevBlockLastAttestedRound {
		stateTracking.StateProofNextRound = prevBlockLastAttestedRound + blockStateProofInterval
	} else {
		stateTracking.StateProofNextRound = prevBlockLastAttestedRound
	}

	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	return block
}

func feedBlocks(ml *mockLedgerForTracker, numOfBlocks uint64, prevBlock *blockEntry, stuckStateProofs bool) *blockEntry {
	for i := uint64(1); i <= numOfBlocks; i++ {
		block := blockStateProofsEnabled(prevBlock, stuckStateProofs)
		stateProofDelta := basics.Round(0)

		prevStateProofNextRound := prevBlock.block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound
		currentStateProofNextRound := block.block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound

		if currentStateProofNextRound != prevStateProofNextRound {
			stateProofDelta = currentStateProofNextRound
		}

		ml.trackers.newBlock(block.block, ledgercore.StateDelta{StateProofNext: stateProofDelta})
		prevBlock = &block
	}

	return prevBlock
}

func verifyTrackerDB(t *testing.T, spt *stateProofVerificationTracker,
	startDataIndex uint64, endDataIndex uint64, dataPresenceExpected bool) {
	a := require.New(t)

	for dataIndex := startDataIndex; dataIndex < endDataIndex; dataIndex++ {
		targetStateProofRound := basics.Round(dataIndex+2) * defaultRoundsInterval
		_, err := spt.LookupVerificationData(targetStateProofRound)

		if dataPresenceExpected {
			a.NoError(err)
		} else {
			a.ErrorIs(err, sql.ErrNoRows)
		}
	}
}

func TestStateProofVerificationTracker_StateProofsNotStuck(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedDataNum := uint64(12)
	lastBlock := feedBlocks(ml, expectedDataNum*uint64(defaultRoundsInterval), genesisBlock(), false)

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	// The last verification data should still be in the DB since the state proof it is used to verify has not
	// yet been committed.
	expectedRemainingDataNum := expectedDataNum - 1
	verifyTrackerDB(t, spt, 0, expectedRemainingDataNum, false)
}

func TestStateProofVerificationTracker_CommitAddition(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedDataNum := uint64(1)

	lastBlock := feedBlocks(ml, expectedDataNum*uint64(defaultRoundsInterval), genesisBlock(), true)
	a.Equal(expectedDataNum, uint64(len(spt.trackedData)))

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	a.Equal(uint64(0), uint64(len(spt.trackedData)))

	verifyTrackerDB(t, spt, 0, expectedDataNum, true)
}

func TestStateProofVerificationTracker_Removal(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(6)
	dataToRemove := uint64(3)

	lastStuckBlock := feedBlocks(ml, dataToAdd*uint64(defaultRoundsInterval), genesisBlock(), true)
	lastBlock := feedBlocks(ml, dataToRemove, lastStuckBlock, false)

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	verifyTrackerDB(t, spt, 0, dataToRemove, false)
	verifyTrackerDB(t, spt, dataToRemove, dataToAdd, true)
}

// TODO: Test addition and removal after exceeding initial capacity
// TODO: Test interval size change
// TODO: Test state proofs disabled
// TODO: Test commit not all state proofs
// TODO: Test disk initialization
// TODO: Test stress
// TODO: Test locking?
