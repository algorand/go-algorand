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
	"context"
	"database/sql"
	"errors"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const defaultStateProofInterval = uint64(256)
const defaultFirstStateProofDataRound = basics.Round(defaultStateProofInterval * 2)
const unusedByStateProofTracker = basics.Round(0)

type StateProofTrackingLocation uint64

const (
	any StateProofTrackingLocation = iota
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
	err = spt.loadFromDisk(ml, unusedByStateProofTracker)
	a.NoError(err)

	return ml, &spt
}

func mockCommit(t *testing.T, spt *stateProofVerificationTracker, ml *mockLedgerForTracker, dbRound basics.Round, newBase basics.Round) {
	a := require.New(t)

	offset := uint64(newBase - dbRound)

	dcr := deferredCommitRange{offset: offset}

	dcc := deferredCommitContext{
		deferredCommitRange: dcr,
		newBase:             newBase,
	}

	spt.committedUpTo(newBase)
	spt.produceCommittingTask(newBase, dbRound, &dcr)
	err := spt.prepareCommit(&dcc)
	a.NoError(err)

	err = ml.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		return spt.commitRound(ctx, tx, &dcc)
	})
	a.NoError(err)

	postCommitCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spt.postCommit(postCommitCtx, &dcc)
	spt.postCommitUnlocked(postCommitCtx, &dcc)
}

func genesisBlock() *blockEntry {
	initialRound := basics.Round(0)
	block := randomBlock(initialRound)

	var stateTracking bookkeeping.StateProofTrackingData
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)

	stateTracking.StateProofNextRound = basics.Round(defaultStateProofInterval * 2)
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking

	return &block
}

func createMockedStateProofCommitmentOnBlock(blk *blockEntry, stateTracking *bookkeeping.StateProofTrackingData) {
	if uint64(blk.block.Round())%config.Consensus[blk.block.CurrentProtocol].StateProofInterval != 0 {
		return
	}

	var commitment [stateproof.HashSize]byte
	rand.Read(commitment[:])
	stateTracking.StateProofVotersCommitment = commitment[:]
	stateTracking.StateProofOnlineTotalWeight = basics.MicroAlgos{Raw: rand.Uint64()}
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
	createMockedStateProofCommitmentOnBlock(&block, &stateTracking)

	if !stuckStateProofs && round > prevBlockLastAttestedRound {
		stateTracking.StateProofNextRound = prevBlockLastAttestedRound + basics.Round(block.block.ConsensusProtocol().StateProofInterval)
	} else {
		stateTracking.StateProofNextRound = prevBlockLastAttestedRound
	}

	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	return block
}

func feedBlocksUpToRound(spt *stateProofVerificationTracker, prevBlock *blockEntry, targetRound basics.Round,
	stateProofInterval uint64, stuckStateProofs bool) *blockEntry {
	for i := prevBlock.block.Round(); i < targetRound; i++ {
		block := blockStateProofsEnabled(prevBlock, stateProofInterval, stuckStateProofs)
		stateProofDelta := basics.Round(0)

		prevStateProofNextRound := prevBlock.block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound
		currentStateProofNextRound := block.block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound

		if currentStateProofNextRound != prevStateProofNextRound {
			stateProofDelta = currentStateProofNextRound
		}

		spt.newBlock(block.block, ledgercore.StateDelta{StateProofNext: stateProofDelta})
		prevBlock = &block
	}

	return prevBlock
}

func verifyStateProofVerificationTracking(t *testing.T, spt *stateProofVerificationTracker,
	startRound basics.Round, dataAmount uint64, stateProofInterval uint64, dataPresenceExpected bool, trackingLocation StateProofTrackingLocation) {
	a := require.New(t)

	finalTargetStateProofRound := startRound + basics.Round((dataAmount-1)*stateProofInterval)

	for targetStateProofRound := startRound; targetStateProofRound <= finalTargetStateProofRound; targetStateProofRound += basics.Round(stateProofInterval) {
		var err error
		switch trackingLocation {
		case any:
			_, err = spt.lookupFirstStage(targetStateProofRound)
		case trackerDB:
			_, err = spt.dbQueries.lookupFirstStageStateProofVerification(targetStateProofRound)
			if err != nil && errors.Is(err, sql.ErrNoRows) {
				err = errStateProofVerificationDataNotFound
			}
		case trackerMemory:
			_, err = spt.lookupFirstStageDataInTrackedMemory(targetStateProofRound)
		}

		if dataPresenceExpected {
			a.NoError(err)
		} else {
			a.ErrorIs(err, errStateProofVerificationDataNotFound)
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
		spt.newBlock(block.block, ledgercore.StateDelta{})
	}

	mockCommit(t, spt, ml, 0, roundsAmount)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, uint64(roundsAmount)/defaultStateProofInterval, defaultStateProofInterval, false, any)
}

func TestStateProofVerificationTracker_StateProofsNotStuck(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedDataNum := uint64(12)
	lastBlock := feedBlocksUpToRound(spt, genesisBlock(),
		basics.Round(expectedDataNum*defaultStateProofInterval+defaultStateProofInterval-1),
		defaultStateProofInterval, false)

	mockCommit(t, spt, ml, 0, lastBlock.block.Round())

	expectedRemainingDataNum := expectedDataNum - 1
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, expectedRemainingDataNum, defaultStateProofInterval, false, any)

	lastStateProofTargetRound := defaultFirstStateProofDataRound + basics.Round(expectedRemainingDataNum*defaultStateProofInterval)
	// The last verification data should still be tracked since the round with the state proof transaction it is used
	// to verify has not yet been committed.
	verifyStateProofVerificationTracking(t, spt, lastStateProofTargetRound, 1, defaultStateProofInterval, true, any)
}

func TestStateProofVerificationTracker_CommitFullDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedDataNum := uint64(10)

	lastBlock := feedBlocksUpToRound(spt, genesisBlock(), basics.Round(expectedDataNum*defaultStateProofInterval),
		defaultStateProofInterval, true)

	mockCommit(t, spt, ml, 0, lastBlock.block.Round())

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, expectedDataNum, defaultStateProofInterval, false, trackerMemory)
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, expectedDataNum, defaultStateProofInterval, true, trackerDB)
}

func TestStateProofVerificationTracker_CommitPartialDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(10)
	_ = feedBlocksUpToRound(spt, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	expectedDataInDbNum := uint64(2)
	expectedDataInMemoryNum := dataToAdd - expectedDataInDbNum

	mockCommit(t, spt, ml, 0, basics.Round(defaultStateProofInterval*expectedDataInDbNum))

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, expectedDataInDbNum, defaultStateProofInterval, true, trackerDB)
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, expectedDataInDbNum, defaultStateProofInterval, false, trackerMemory)

	firstNonFlushedDataTargetRound := defaultFirstStateProofDataRound + basics.Round(expectedDataInDbNum*defaultStateProofInterval)
	verifyStateProofVerificationTracking(t, spt, firstNonFlushedDataTargetRound, expectedDataInMemoryNum, defaultStateProofInterval, false, trackerDB)
	verifyStateProofVerificationTracking(t, spt, firstNonFlushedDataTargetRound, expectedDataInMemoryNum, defaultStateProofInterval, true, trackerMemory)
}

func TestStateProofVerificationTracker_CommitNoDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(10)
	_ = feedBlocksUpToRound(spt, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	mockCommit(t, spt, ml, 0, basics.Round(defaultStateProofInterval-1))

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, dataToAdd, defaultStateProofInterval, true, trackerMemory)
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, dataToAdd, defaultStateProofInterval, false, trackerDB)
}

func TestStateProofVerificationTracker_CommitFullDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(6)
	maxStateProofsToGenerate := dataToAdd - 1

	lastStuckBlock := feedBlocksUpToRound(spt, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)
	lastBlock := feedBlocksUpToRound(spt, lastStuckBlock, lastStuckBlock.block.Round()+basics.Round(maxStateProofsToGenerate),
		defaultStateProofInterval, false)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, dataToAdd, defaultStateProofInterval, true, trackerMemory)

	mockCommit(t, spt, ml, 0, lastBlock.block.Round())

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, maxStateProofsToGenerate, defaultStateProofInterval, false, any)

	lastStateProofTargetRound := defaultFirstStateProofDataRound + basics.Round(maxStateProofsToGenerate*defaultStateProofInterval)
	// The last verification data should still be tracked since the round with the state proof transaction it is used
	// to verify has not yet been committed.
	verifyStateProofVerificationTracking(t, spt, lastStateProofTargetRound, 1, defaultStateProofInterval, true, any)
}

func TestStateProofVerificationTracker_CommitPartialDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(6)
	maxStateProofsToGenerate := dataToAdd - 1
	dataToRemove := maxStateProofsToGenerate - 1

	lastStuckBlock := feedBlocksUpToRound(spt, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)
	_ = feedBlocksUpToRound(spt, lastStuckBlock,
		lastStuckBlock.block.Round()+basics.Round(maxStateProofsToGenerate*defaultStateProofInterval),
		defaultStateProofInterval, false)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, dataToAdd, defaultStateProofInterval, true, trackerMemory)

	mockCommit(t, spt, ml, 0, lastStuckBlock.block.Round()+basics.Round(dataToRemove))

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, dataToRemove, defaultStateProofInterval, false, any)
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound+basics.Round(dataToRemove*defaultStateProofInterval),
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

	lastStuckBlock := feedBlocksUpToRound(spt, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	lastStuckBlockRound := lastStuckBlock.block.Round()
	var block blockEntry
	for round := lastStuckBlockRound + 1; round <= lastStuckBlockRound+offsetBeforeStateProofs; round++ {
		block = randomBlock(round)
		block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
		spt.newBlock(block.block, ledgercore.StateDelta{})
	}

	_ = feedBlocksUpToRound(spt, &block, block.block.Round()+basics.Round(maxStateProofsToGenerate), defaultStateProofInterval, false)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, dataToAdd, defaultStateProofInterval, true, trackerMemory)

	mockCommit(t, spt, ml, 0, lastStuckBlockRound)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, dataToAdd, defaultStateProofInterval, true, trackerDB)
	a.Equal(maxStateProofsToGenerate, uint64(len(spt.trackedDeleteData)))
}

func TestStateProofVerificationTracker_StateProofIntervalChange(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	newStateProofInterval := defaultStateProofInterval * 2

	oldIntervalData := uint64(5)
	newIntervalData := uint64(6)

	lastOldIntervalBlock := feedBlocksUpToRound(spt, genesisBlock(), basics.Round(oldIntervalData*defaultStateProofInterval),
		defaultStateProofInterval, true)
	lastStuckBlock := feedBlocksUpToRound(spt, lastOldIntervalBlock, lastOldIntervalBlock.block.Round()+basics.Round(newIntervalData*newStateProofInterval),
		newStateProofInterval, true)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, oldIntervalData, defaultStateProofInterval,
		true, any)
	firstNewIntervalStateProofRound := lastOldIntervalBlock.block.Round() + basics.Round(defaultStateProofInterval)
	verifyStateProofVerificationTracking(t, spt, firstNewIntervalStateProofRound, newIntervalData,
		newStateProofInterval, true, any)

	newIntervalRemovedStateProofs := newIntervalData - (newIntervalData / 2)
	// State Proofs for old blocks should be generated using the old interval.
	lastOldIntervalStateProofBlock := feedBlocksUpToRound(spt, lastStuckBlock,
		lastStuckBlock.block.Round()+basics.Round(oldIntervalData)-1,
		defaultStateProofInterval, false)
	lastBlock := feedBlocksUpToRound(spt, lastOldIntervalStateProofBlock,
		lastOldIntervalStateProofBlock.block.Round()+basics.Round(newIntervalRemovedStateProofs),
		newStateProofInterval, false)

	mockCommit(t, spt, ml, 0, lastBlock.block.Round())

	firstRemainingStateProofRound := firstNewIntervalStateProofRound +
		basics.Round(newIntervalRemovedStateProofs*newStateProofInterval)
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofDataRound, oldIntervalData, defaultStateProofInterval,
		false, any)
	verifyStateProofVerificationTracking(t, spt, firstNewIntervalStateProofRound,
		newIntervalRemovedStateProofs, newStateProofInterval, false, any)
	verifyStateProofVerificationTracking(t, spt, firstRemainingStateProofRound, newIntervalData-newIntervalRemovedStateProofs,
		newStateProofInterval, true, any)
}

func TestStateProofVerificationTracker_LookupVerificationData(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(10)
	_ = feedBlocksUpToRound(spt, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	expectedDataInDbNum := uint64(2)

	mockCommit(t, spt, ml, 0, basics.Round(defaultStateProofInterval*expectedDataInDbNum))

	_, err := spt.LookupVerificationData(basics.Round(0))
	a.ErrorIs(err, errStateProofVerificationDataNotFound)
	a.ErrorContains(err, "no rows")

	lastStateProofRound := basics.Round(defaultStateProofInterval + dataToAdd*defaultStateProofInterval)
	_, err = spt.LookupVerificationData(lastStateProofRound + basics.Round(defaultStateProofInterval))
	a.ErrorIs(err, errStateProofVerificationDataNotFound)
	a.ErrorContains(err, "greater than maximum")

	// First stage is taken from disk second stage taken from memory
	dbDataRound := basics.Round(defaultStateProofInterval + expectedDataInDbNum*defaultStateProofInterval)
	dbData, err := spt.LookupVerificationData(dbDataRound)
	a.NoError(err)
	a.Equal(dbDataRound, dbData.TargetStateProofRound)
	a.Equal(protocol.ConsensusCurrentVersion, dbData.Version)

	// First and second stage taken from disk
	dbDataRound = basics.Round(defaultStateProofInterval + (expectedDataInDbNum-1)*defaultStateProofInterval)
	dbData, err = spt.LookupVerificationData(dbDataRound)
	a.NoError(err)
	a.Equal(dbDataRound, dbData.TargetStateProofRound)
	a.Equal(protocol.ConsensusCurrentVersion, dbData.Version)

	memoryDataRound := basics.Round(defaultStateProofInterval + (expectedDataInDbNum+1)*defaultStateProofInterval)
	memoryData, err := spt.LookupVerificationData(memoryDataRound)
	a.NoError(err)
	a.Equal(memoryDataRound, memoryData.TargetStateProofRound)
	a.Equal(protocol.ConsensusCurrentVersion, memoryData.Version)

	// First stage data should be in memory. Second stage didn't happen yet.
	memoryDataRound = basics.Round((dataToAdd + 1) * defaultStateProofInterval)
	memoryData, err = spt.LookupVerificationData(memoryDataRound)
	a.ErrorIs(err, errStateProofVerificationDataNotFound)
	a.ErrorContains(err, "second stage data ")

	// This error shouldn't happen in normal flow - we force it to happen for the test.
	memoryDataRound = basics.Round(defaultStateProofInterval + (expectedDataInDbNum+1)*defaultStateProofInterval)
	spt.trackedFirstStageData[0].firstStageVerificationData.TargetStateProofRound = 0
	_, err = spt.LookupVerificationData(memoryDataRound)
	a.ErrorIs(err, errStateProofVerificationDataNotFound)
	a.ErrorContains(err, "memory lookup failed")
}

func TestStateProofVerificationTracker_PanicInvalidBlockInsertion(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	dataToAdd := uint64(1)
	_ = feedBlocksUpToRound(spt, genesisBlock(), basics.Round(dataToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	pastBlock := randomBlock(0)
	a.Panics(func() { spt.insertFirstStageCommitData(&pastBlock.block) })
}
