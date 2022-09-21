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

const defaultStateProofInterval = uint64(256)
const firstStateProofRound = basics.Round(defaultStateProofInterval * 2)

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

	stateTracking.StateProofNextRound = basics.Round(defaultStateProofInterval * 2)
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking

	return &block
}

func blockStateProofsEnabled(prevBlock *blockEntry, stateProofInterval uint64, stuckStateProofs bool) blockEntry {
	round := prevBlock.block.Round() + 1
	prevBlockLastAttestedRound := prevBlock.block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound

	modifiedConsensus := config.Consensus[protocol.ConsensusCurrentVersion]
	modifiedConsensus.StateProofInterval = stateProofInterval
	config.Consensus[protocol.ConsensusCurrentVersion] = modifiedConsensus

	block := randomBlock(round)
	block.block.CurrentProtocol = protocol.ConsensusCurrentVersion

	var stateTracking bookkeeping.StateProofTrackingData
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)

	if !stuckStateProofs && round > prevBlockLastAttestedRound {
		stateTracking.StateProofNextRound = prevBlockLastAttestedRound + basics.Round(block.block.ConsensusProtocol().StateProofInterval)
	} else {
		stateTracking.StateProofNextRound = prevBlockLastAttestedRound
	}

	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	return block
}

func feedBlocksUpToRound(ml *mockLedgerForTracker, prevBlock *blockEntry, targetRound basics.Round,
	stateProofInterval uint64, stuckStateProofs bool) *blockEntry {
	for i := prevBlock.block.Round(); i < targetRound; i++ {
		block := blockStateProofsEnabled(prevBlock, stateProofInterval, stuckStateProofs)
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
	startRound basics.Round, dataAmount uint64, stateProofInterval uint64, dataPresenceExpected bool, trackingLocation TrackingLocation) {
	a := require.New(t)

	finalTargetStateProofRound := startRound + basics.Round((dataAmount-1)*stateProofInterval)
	for targetStateProofRound := startRound; targetStateProofRound <= finalTargetStateProofRound; targetStateProofRound += basics.Round(stateProofInterval) {

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

	verifyTracking(t, spt, firstStateProofRound, uint64(roundsAmount)/defaultStateProofInterval, defaultStateProofInterval, false, any)
}

func TestStateProofVerificationTracker_StateProofsNotStuck(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedDataNum := uint64(12)
	lastBlock := feedBlocksUpToRound(ml, genesisBlock(),
		basics.Round(expectedDataNum*defaultStateProofInterval+defaultStateProofInterval-1),
		defaultStateProofInterval, false)

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	expectedRemainingDataNum := expectedDataNum - 1
	verifyTracking(t, spt, firstStateProofRound, expectedRemainingDataNum, defaultStateProofInterval, false, any)

	lastStateProofTargetRound := firstStateProofRound + basics.Round(expectedRemainingDataNum*defaultStateProofInterval)
	// The last verification data should still be tracked since the round with the state proof transaction it is used
	// to verify has not yet been committed.
	verifyTracking(t, spt, lastStateProofTargetRound, 1, defaultStateProofInterval, true, any)
}

func TestStateProofVerificationTracker_CommitFUllDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedDataNum := uint64(10)

	lastBlock := feedBlocksUpToRound(ml, genesisBlock(), basics.Round(expectedDataNum*defaultStateProofInterval),
		defaultStateProofInterval, true)

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, firstStateProofRound, expectedDataNum, defaultStateProofInterval, false, trackerMemory)
	verifyTracking(t, spt, firstStateProofRound, expectedDataNum, defaultStateProofInterval, true, trackerDB)
}

func TestStateProofVerificationTracker_CommitPartialDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(10)
	_ = feedBlocksUpToRound(ml, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	expectedDataInDbNum := uint64(2)
	expectedDataInMemoryNum := dataToAdd - expectedDataInDbNum
	ml.trackers.committedUpTo(basics.Round(defaultStateProofInterval * expectedDataInDbNum))
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, firstStateProofRound, expectedDataInDbNum, defaultStateProofInterval, true, trackerDB)
	verifyTracking(t, spt, firstStateProofRound, expectedDataInDbNum, defaultStateProofInterval, false, trackerMemory)

	firstNonFlushedDataTargetRound := firstStateProofRound + basics.Round(expectedDataInDbNum*defaultStateProofInterval)
	verifyTracking(t, spt, firstNonFlushedDataTargetRound, expectedDataInMemoryNum, defaultStateProofInterval, false, trackerDB)
	verifyTracking(t, spt, firstNonFlushedDataTargetRound, expectedDataInMemoryNum, defaultStateProofInterval, true, trackerMemory)
}

func TestStateProofVerificationTracker_CommitNoDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(10)
	_ = feedBlocksUpToRound(ml, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	ml.trackers.committedUpTo(basics.Round(defaultStateProofInterval - 1))
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, firstStateProofRound, dataToAdd, defaultStateProofInterval, true, trackerMemory)
	verifyTracking(t, spt, firstStateProofRound, dataToAdd, defaultStateProofInterval, false, trackerDB)
}

func TestStateProofVerificationTracker_CommitFullDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(6)
	maxStateProofsToGenerate := dataToAdd - 1

	lastStuckBlock := feedBlocksUpToRound(ml, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)
	lastBlock := feedBlocksUpToRound(ml, lastStuckBlock, lastStuckBlock.block.Round()+basics.Round(maxStateProofsToGenerate),
		defaultStateProofInterval, false)

	verifyTracking(t, spt, firstStateProofRound, dataToAdd, defaultStateProofInterval, true, trackerMemory)

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, firstStateProofRound, maxStateProofsToGenerate, defaultStateProofInterval, false, any)

	lastStateProofTargetRound := firstStateProofRound + basics.Round(maxStateProofsToGenerate*defaultStateProofInterval)
	// The last verification data should still be tracked since the round with the state proof transaction it is used
	// to verify has not yet been committed.
	verifyTracking(t, spt, lastStateProofTargetRound, 1, defaultStateProofInterval, true, any)
}

func TestStateProofVerificationTracker_CommitPartialDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(6)
	maxStateProofsToGenerate := dataToAdd - 1
	dataToRemove := maxStateProofsToGenerate - 1

	lastStuckBlock := feedBlocksUpToRound(ml, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)
	_ = feedBlocksUpToRound(ml, lastStuckBlock,
		lastStuckBlock.block.Round()+basics.Round(maxStateProofsToGenerate*defaultStateProofInterval),
		defaultStateProofInterval, false)

	verifyTracking(t, spt, firstStateProofRound, dataToAdd, defaultStateProofInterval, true, trackerMemory)

	ml.trackers.committedUpTo(lastStuckBlock.block.Round() + basics.Round(dataToRemove))
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, firstStateProofRound, dataToRemove, defaultStateProofInterval, false, any)
	verifyTracking(t, spt, firstStateProofRound+basics.Round(dataToRemove*defaultStateProofInterval),
		dataToAdd-dataToRemove, defaultStateProofInterval, true, trackerDB)
}

func TestStateProofVerificationTracker_CommitNoDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(6)
	maxStateProofsToGenerate := dataToAdd - 1
	offsetBeforeStateProofs := basics.Round(defaultStateProofInterval / 2)

	lastStuckBlock := feedBlocksUpToRound(ml, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	lastStuckBlockRound := lastStuckBlock.block.Round()
	var block blockEntry
	for round := lastStuckBlockRound + 1; round <= lastStuckBlockRound+offsetBeforeStateProofs; round++ {
		block = randomBlock(round)
		block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
		ml.trackers.newBlock(block.block, ledgercore.StateDelta{})
	}

	_ = feedBlocksUpToRound(ml, &block, block.block.Round()+basics.Round(maxStateProofsToGenerate), defaultStateProofInterval, false)

	verifyTracking(t, spt, firstStateProofRound, dataToAdd, defaultStateProofInterval, true, trackerMemory)

	ml.trackers.committedUpTo(lastStuckBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	verifyTracking(t, spt, firstStateProofRound, dataToAdd, defaultStateProofInterval, true, trackerDB)
	a.Equal(maxStateProofsToGenerate, uint64(len(spt.trackedDeletionData)))
}

func TestStateProofVerificationTracker_StateProofIntervalChange(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	newStateProofInterval := defaultStateProofInterval * 2

	oldIntervalData := uint64(5)
	newIntervalData := uint64(6)

	lastOldIntervalBlock := feedBlocksUpToRound(ml, genesisBlock(), basics.Round(oldIntervalData*defaultStateProofInterval),
		defaultStateProofInterval, true)
	lastStuckBlock := feedBlocksUpToRound(ml, lastOldIntervalBlock, lastOldIntervalBlock.block.Round()+basics.Round(newIntervalData*newStateProofInterval),
		newStateProofInterval, true)

	verifyTracking(t, spt, firstStateProofRound, oldIntervalData, defaultStateProofInterval,
		true, any)
	firstNewIntervalStateProofRound := lastOldIntervalBlock.block.Round() + basics.Round(defaultStateProofInterval)
	verifyTracking(t, spt, firstNewIntervalStateProofRound, newIntervalData,
		newStateProofInterval, true, any)

	newIntervalRemovedStateProofs := newIntervalData - (newIntervalData / 2)
	// State Proofs for old blocks should be generated using the old interval.
	lastOldIntervalStateProofBlock := feedBlocksUpToRound(ml, lastStuckBlock,
		lastStuckBlock.block.Round()+basics.Round(oldIntervalData)-1,
		defaultStateProofInterval, false)
	lastBlock := feedBlocksUpToRound(ml, lastOldIntervalStateProofBlock,
		lastOldIntervalStateProofBlock.block.Round()+basics.Round(newIntervalRemovedStateProofs),
		newStateProofInterval, false)

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	firstRemainingStateProofRound := firstNewIntervalStateProofRound +
		basics.Round(newIntervalRemovedStateProofs*newStateProofInterval)
	verifyTracking(t, spt, firstStateProofRound, oldIntervalData, defaultStateProofInterval,
		false, any)
	verifyTracking(t, spt, firstNewIntervalStateProofRound,
		newIntervalRemovedStateProofs, newStateProofInterval, false, any)
	verifyTracking(t, spt, firstRemainingStateProofRound, newIntervalData-newIntervalRemovedStateProofs,
		newStateProofInterval, true, any)
}

// TODO: Test lookup for not yet generated
// TODO: Test lookup errors
// TODO: Test locking?
