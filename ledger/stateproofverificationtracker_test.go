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

type TrackingLocation uint64

const (
	any TrackingLocation = iota
	trackerDB
	trackerMemory
)

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

func verifyTracking(t *testing.T, spt *stateProofVerificationTracker,
	startDataIndex uint64, endDataIndex uint64, dataPresenceExpected bool, trackingLocation TrackingLocation) {
	a := require.New(t)

	for dataIndex := startDataIndex; dataIndex < endDataIndex; dataIndex++ {
		targetStateProofRound := basics.Round(dataIndex+2) * defaultRoundsInterval

		var err error
		var expectedNotFoundErr error
		switch trackingLocation {
		case any:
			_, err = spt.LookupVerificationData(targetStateProofRound)
			expectedNotFoundErr = sql.ErrNoRows
		case trackerDB:
			_, err = spt.dbQueries.lookupData(targetStateProofRound)
			expectedNotFoundErr = sql.ErrNoRows
		case trackerMemory:
			_, err = spt.lookupDataInTrackedMemory(targetStateProofRound)
			expectedNotFoundErr = errStateProofVerificationDataNotFound
		}

		if dataPresenceExpected {
			a.NoError(err)
		} else {
			a.ErrorIs(err, expectedNotFoundErr)
		}
	}
}

func TestStateProofVerificationTracker_StateProofsDisabled(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	roundsAmount := basics.Round(1000)
	for round := basics.Round(1); round <= roundsAmount; round++ {
		block := randomBlock(round)
		// Last protocol version without state proofs.
		block.block.CurrentProtocol = protocol.ConsensusV33
		ml.trackers.newBlock(block.block, ledgercore.StateDelta{})
	}

	ml.trackers.committedUpTo(roundsAmount)
	ml.trackers.waitAccountsWriting()
	verifyTracking(t, spt, 0, uint64(roundsAmount/defaultRoundsInterval), false, any)
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

	expectedRemainingDataNum := expectedDataNum - 1
	verifyTracking(t, spt, 0, expectedRemainingDataNum, false, any)

	// The last verification data should still be tracked since the round with the state proof transaction it is used
	// to verify has not yet been committed.
	verifyTracking(t, spt, expectedDataNum, expectedDataNum, true, any)
}

func TestStateProofVerificationTracker_CommitDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedDataNum := uint64(1)

	lastBlock := feedBlocks(ml, expectedDataNum*uint64(defaultRoundsInterval), genesisBlock(), true)

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, 0, expectedDataNum, false, trackerMemory)
	verifyTracking(t, spt, 0, expectedDataNum, true, trackerDB)
}

func TestStateProofVerificationTracker_CommitPartialDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(10)
	_ = feedBlocks(ml, dataToAdd*uint64(defaultRoundsInterval), genesisBlock(), true)

	expectedDataInDbNum := uint64(2)
	expectedDataInMemoryNum := dataToAdd - expectedDataInDbNum
	ml.trackers.committedUpTo(defaultRoundsInterval * basics.Round(expectedDataInDbNum))
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, 0, expectedDataInDbNum, true, trackerDB)
	verifyTracking(t, spt, 0, expectedDataInDbNum, false, trackerMemory)

	verifyTracking(t, spt, expectedDataInDbNum, expectedDataInMemoryNum, false, trackerDB)
	verifyTracking(t, spt, expectedDataInDbNum, expectedDataInMemoryNum, true, trackerMemory)
}

func TestStateProofVerificationTracker_CommitNoDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(10)
	_ = feedBlocks(ml, dataToAdd*uint64(defaultRoundsInterval), genesisBlock(), true)

	ml.trackers.committedUpTo(defaultRoundsInterval - 1)
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, 0, dataToAdd, true, trackerMemory)
	verifyTracking(t, spt, 0, dataToAdd, false, trackerDB)
}

func TestStateProofVerificationTracker_CommitFullDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(6)
	maxStateProofsToGenerate := dataToAdd - 1

	lastStuckBlock := feedBlocks(ml, dataToAdd*uint64(defaultRoundsInterval), genesisBlock(), true)
	lastBlock := feedBlocks(ml, maxStateProofsToGenerate, lastStuckBlock, false)

	verifyTracking(t, spt, 0, dataToAdd, true, trackerMemory)

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, 0, maxStateProofsToGenerate, false, any)

	verifyTracking(t, spt, dataToAdd, dataToAdd, true, trackerDB)
}

func TestStateProofVerificationTracker_CommitPartialDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(6)
	maxStateProofsToGenerate := dataToAdd - 1
	dataToRemove := maxStateProofsToGenerate - 1

	lastStuckBlock := feedBlocks(ml, dataToAdd*uint64(defaultRoundsInterval), genesisBlock(), true)
	_ = feedBlocks(ml, maxStateProofsToGenerate, lastStuckBlock, false)

	verifyTracking(t, spt, 0, dataToAdd, true, trackerMemory)

	ml.trackers.committedUpTo(lastStuckBlock.block.Round() + basics.Round(dataToRemove))
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, 0, dataToRemove, false, any)
	verifyTracking(t, spt, dataToRemove, dataToAdd, true, trackerDB)
}

func TestStateProofVerificationTracker_CommitNoDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(6)
	maxStateProofsToGenerate := dataToAdd - 1
	offsetBeforeStateProofs := uint64(defaultRoundsInterval / 2)

	lastStuckBlock := feedBlocks(ml, dataToAdd*uint64(defaultRoundsInterval)+offsetBeforeStateProofs, genesisBlock(), true)
	_ = feedBlocks(ml, maxStateProofsToGenerate, lastStuckBlock, false)

	verifyTracking(t, spt, 0, dataToAdd, true, trackerMemory)

	ml.trackers.committedUpTo(lastStuckBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, 0, dataToAdd, true, trackerDB)
	a.Equal(maxStateProofsToGenerate, uint64(len(spt.trackedDeletionData)))
}

// TODO: Test interval size change
// TODO: Test lookup for not yet generated
// TODO: Test disk initialization
// TODO: Test stress
// TODO: Test errors
// TODO: Test locking?
