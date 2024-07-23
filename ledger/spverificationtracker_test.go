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
	"context"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

const defaultStateProofInterval = uint64(256)
const defaultFirstStateProofContextRound = basics.Round(defaultStateProofInterval * 2)
const defaultFirstStateProofContextInterval = basics.Round(2)
const unusedByStateProofTracker = basics.Round(0)

type StateProofTrackingLocation uint64

const (
	spverDBLoc StateProofTrackingLocation = iota
	trackerDB
	trackerMemory
)

func initializeLedgerSpt(t *testing.T) (*mockLedgerForTracker, *spVerificationTracker) {
	a := require.New(t)
	accts := []map[basics.Address]basics.AccountData{makeRandomOnlineAccounts(20)}

	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, accts)

	spt := spVerificationTracker{}

	conf := config.GetDefaultLocal()

	_, err := trackerDBInitialize(ml, false, ".")
	a.NoError(err)

	err = ml.trackers.initialize(ml, []ledgerTracker{&spt}, conf)
	a.NoError(err)
	err = spt.loadFromDisk(ml, unusedByStateProofTracker)
	a.NoError(err)

	return ml, &spt
}

func mockCommit(t *testing.T, spt *spVerificationTracker, ml *mockLedgerForTracker, dbRound basics.Round, newBase basics.Round) {
	a := require.New(t)

	offset := uint64(newBase - dbRound)

	dcr := deferredCommitRange{offset: offset}

	dcc := deferredCommitContext{
		deferredCommitRange: dcr,
	}

	spt.committedUpTo(newBase)
	spt.produceCommittingTask(newBase, dbRound, &dcr)
	err := spt.prepareCommit(&dcc)
	a.NoError(err)

	err = ml.dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
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

func feedBlocksUpToRound(spt *spVerificationTracker, prevBlock *blockEntry, targetRound basics.Round,
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

func verifyStateProofVerificationTracking(t *testing.T, spt *spVerificationTracker,
	startRound basics.Round, contextAmount uint64, stateProofInterval uint64, contextPresenceExpected bool, trackingLocation StateProofTrackingLocation) {
	a := require.New(t)

	finalLastAttestedRound := startRound + basics.Round((contextAmount-1)*stateProofInterval)

	for lastAttestedRound := startRound; lastAttestedRound <= finalLastAttestedRound; lastAttestedRound += basics.Round(stateProofInterval) {
		var err error
		switch trackingLocation {
		case spverDBLoc:
			_, err = spt.LookupVerificationContext(lastAttestedRound)
		case trackerDB:
			_, err = spt.lookupContextInDB(lastAttestedRound)
		case trackerMemory:
			_, err = spt.lookupContextInTrackedMemory(lastAttestedRound)
		}

		if contextPresenceExpected {
			a.NoError(err)
		} else {
			a.ErrorIs(err, errSPVerificationContextNotFound)
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

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, uint64(roundsAmount)/defaultStateProofInterval, defaultStateProofInterval, false, spverDBLoc)
}

func TestStateProofVerificationTracker_StateProofsNotStuck(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedContextNum := uint64(12)
	lastBlock := feedBlocksUpToRound(spt, genesisBlock(),
		basics.Round(expectedContextNum*defaultStateProofInterval+defaultStateProofInterval-1),
		defaultStateProofInterval, false)

	mockCommit(t, spt, ml, 0, lastBlock.block.Round())

	expectedRemainingContextNum := expectedContextNum - 1
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, expectedRemainingContextNum, defaultStateProofInterval, false, spverDBLoc)

	finalLastAttestedRound := defaultFirstStateProofContextRound + basics.Round(expectedRemainingContextNum*defaultStateProofInterval)
	// The last verification context should still be tracked since the round with the state proof transaction it is used
	// to verify has not yet been committed.
	verifyStateProofVerificationTracking(t, spt, finalLastAttestedRound, 1, defaultStateProofInterval, true, spverDBLoc)
}

func TestStateProofVerificationTracker_CommitFUllDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedContextNum := uint64(10)

	lastBlock := feedBlocksUpToRound(spt, genesisBlock(), basics.Round(expectedContextNum*defaultStateProofInterval),
		defaultStateProofInterval, true)

	mockCommit(t, spt, ml, 0, lastBlock.block.Round())

	spt.lastLookedUpVerificationContext = ledgercore.StateProofVerificationContext{}
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, expectedContextNum, defaultStateProofInterval, false, trackerMemory)
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, expectedContextNum, defaultStateProofInterval, true, trackerDB)
}

func TestStateProofVerificationTracker_CommitPartialDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	contextToAdd := uint64(10)
	_ = feedBlocksUpToRound(spt, genesisBlock(), basics.Round(contextToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	expectedContextInDbNum := uint64(2)
	expectedContextInMemoryNum := contextToAdd - expectedContextInDbNum

	mockCommit(t, spt, ml, 0, basics.Round(defaultStateProofInterval*expectedContextInDbNum))

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, expectedContextInDbNum, defaultStateProofInterval, true, trackerDB)
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, expectedContextInDbNum, defaultStateProofInterval, false, trackerMemory)

	firstNonFlushedContextTargetRound := defaultFirstStateProofContextRound + basics.Round(expectedContextInDbNum*defaultStateProofInterval)
	verifyStateProofVerificationTracking(t, spt, firstNonFlushedContextTargetRound, expectedContextInMemoryNum, defaultStateProofInterval, false, trackerDB)
	verifyStateProofVerificationTracking(t, spt, firstNonFlushedContextTargetRound, expectedContextInMemoryNum, defaultStateProofInterval, true, trackerMemory)
}

func TestStateProofVerificationTracker_CommitNoDbFlush(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	contextToAdd := uint64(10)
	_ = feedBlocksUpToRound(spt, genesisBlock(), basics.Round(contextToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	mockCommit(t, spt, ml, 0, basics.Round(defaultStateProofInterval-1))

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, contextToAdd, defaultStateProofInterval, true, trackerMemory)
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, contextToAdd, defaultStateProofInterval, false, trackerDB)
}

func TestStateProofVerificationTracker_CommitFullDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	contextToAdd := uint64(6)
	maxStateProofsToGenerate := contextToAdd - 1

	lastStuckBlock := feedBlocksUpToRound(spt, genesisBlock(), basics.Round(contextToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)
	lastBlock := feedBlocksUpToRound(spt, lastStuckBlock, lastStuckBlock.block.Round()+basics.Round(maxStateProofsToGenerate),
		defaultStateProofInterval, false)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, contextToAdd, defaultStateProofInterval, true, trackerMemory)

	mockCommit(t, spt, ml, 0, lastBlock.block.Round())

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, maxStateProofsToGenerate, defaultStateProofInterval, false, spverDBLoc)

	finalLastAttestedRound := defaultFirstStateProofContextRound + basics.Round(maxStateProofsToGenerate*defaultStateProofInterval)
	// The last verification context should still be tracked since the round with the state proof transaction it is used
	// to verify has not yet been committed.
	verifyStateProofVerificationTracking(t, spt, finalLastAttestedRound, 1, defaultStateProofInterval, true, spverDBLoc)
}

func TestStateProofVerificationTracker_CommitPartialDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	contextToAdd := uint64(6)
	maxStateProofsToGenerate := contextToAdd - 1
	contextToRemove := maxStateProofsToGenerate - 1

	lastStuckBlock := feedBlocksUpToRound(spt, genesisBlock(), basics.Round(contextToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)
	_ = feedBlocksUpToRound(spt, lastStuckBlock,
		lastStuckBlock.block.Round()+basics.Round(maxStateProofsToGenerate*defaultStateProofInterval),
		defaultStateProofInterval, false)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, contextToAdd, defaultStateProofInterval, true, trackerMemory)

	mockCommit(t, spt, ml, 0, lastStuckBlock.block.Round()+basics.Round(contextToRemove))

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, contextToRemove, defaultStateProofInterval, false, spverDBLoc)
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound+basics.Round(contextToRemove*defaultStateProofInterval),
		contextToAdd-contextToRemove, defaultStateProofInterval, true, trackerDB)
}

func TestStateProofVerificationTracker_CommitNoDbPruning(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	contextToAdd := uint64(6)
	maxStateProofsToGenerate := contextToAdd - 1
	offsetBeforeStateProofs := basics.Round(defaultStateProofInterval / 2)

	lastStuckBlock := feedBlocksUpToRound(spt, genesisBlock(), basics.Round(contextToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	lastStuckBlockRound := lastStuckBlock.block.Round()
	var block blockEntry
	for round := lastStuckBlockRound + 1; round <= lastStuckBlockRound+offsetBeforeStateProofs; round++ {
		block = randomBlock(round)
		block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
		spt.newBlock(block.block, ledgercore.StateDelta{})
	}

	_ = feedBlocksUpToRound(spt, &block, block.block.Round()+basics.Round(maxStateProofsToGenerate), defaultStateProofInterval, false)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, contextToAdd, defaultStateProofInterval, true, trackerMemory)

	mockCommit(t, spt, ml, 0, lastStuckBlockRound)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, contextToAdd, defaultStateProofInterval, true, trackerDB)
	a.Equal(maxStateProofsToGenerate, uint64(len(spt.pendingDeleteContexts)))
}

func TestStateProofVerificationTracker_StateProofIntervalChange(t *testing.T) {
	partitiontest.PartitionTest(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	newStateProofInterval := defaultStateProofInterval * 2

	oldIntervalContext := uint64(5)
	newIntervalContext := uint64(6)

	lastOldIntervalBlock := feedBlocksUpToRound(spt, genesisBlock(), basics.Round(oldIntervalContext*defaultStateProofInterval),
		defaultStateProofInterval, true)
	lastStuckBlock := feedBlocksUpToRound(spt, lastOldIntervalBlock, lastOldIntervalBlock.block.Round()+basics.Round(newIntervalContext*newStateProofInterval),
		newStateProofInterval, true)

	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, oldIntervalContext, defaultStateProofInterval,
		true, spverDBLoc)
	firstNewIntervalLastAttestedRound := lastOldIntervalBlock.block.Round() + basics.Round(defaultStateProofInterval)
	verifyStateProofVerificationTracking(t, spt, firstNewIntervalLastAttestedRound, newIntervalContext,
		newStateProofInterval, true, spverDBLoc)

	newIntervalRemovedStateProofs := newIntervalContext - (newIntervalContext / 2)
	// State Proofs for old blocks should be generated using the old interval.
	lastOldIntervalStateProofBlock := feedBlocksUpToRound(spt, lastStuckBlock,
		lastStuckBlock.block.Round()+basics.Round(oldIntervalContext)-1,
		defaultStateProofInterval, false)
	lastBlock := feedBlocksUpToRound(spt, lastOldIntervalStateProofBlock,
		lastOldIntervalStateProofBlock.block.Round()+basics.Round(newIntervalRemovedStateProofs),
		newStateProofInterval, false)

	mockCommit(t, spt, ml, 0, lastBlock.block.Round())

	firstRemainingLastAttestedRound := firstNewIntervalLastAttestedRound +
		basics.Round(newIntervalRemovedStateProofs*newStateProofInterval)
	verifyStateProofVerificationTracking(t, spt, defaultFirstStateProofContextRound, oldIntervalContext, defaultStateProofInterval,
		false, spverDBLoc)
	verifyStateProofVerificationTracking(t, spt, firstNewIntervalLastAttestedRound,
		newIntervalRemovedStateProofs, newStateProofInterval, false, spverDBLoc)
	verifyStateProofVerificationTracking(t, spt, firstRemainingLastAttestedRound, newIntervalContext-newIntervalRemovedStateProofs,
		newStateProofInterval, true, spverDBLoc)
}

func TestStateProofVerificationTracker_LookupVerificationContext(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	contextToAdd := uint64(10)
	_ = feedBlocksUpToRound(spt, genesisBlock(), basics.Round(contextToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	expectedContextInDbNum := uint64(2)

	mockCommit(t, spt, ml, 0, basics.Round(defaultStateProofInterval*expectedContextInDbNum))

	_, err := spt.LookupVerificationContext(basics.Round(0))
	a.ErrorIs(err, errSPVerificationContextNotFound)
	a.ErrorContains(err, "not found")

	finalLastAttestedRound := basics.Round(defaultStateProofInterval + contextToAdd*defaultStateProofInterval)
	_, err = spt.LookupVerificationContext(finalLastAttestedRound + basics.Round(defaultStateProofInterval))
	a.ErrorIs(err, errSPVerificationContextNotFound)
	a.ErrorContains(err, "greater than maximum")

	dbContextRound := basics.Round(defaultStateProofInterval + expectedContextInDbNum*defaultStateProofInterval)
	dbContext, err := spt.LookupVerificationContext(dbContextRound)
	a.NoError(err)
	a.Equal(dbContextRound, dbContext.LastAttestedRound)

	memoryContextRound := basics.Round(defaultStateProofInterval + (expectedContextInDbNum+1)*defaultStateProofInterval)

	memoryContext, err := spt.LookupVerificationContext(memoryContextRound)
	a.NoError(err)
	a.Equal(memoryContextRound, memoryContext.LastAttestedRound)

	// This error shouldn't happen in normal flow - we force it to happen for the test.
	spt.pendingCommitContexts[0].verificationContext.LastAttestedRound = 0
	spt.lastLookedUpVerificationContext = ledgercore.StateProofVerificationContext{}
	_, err = spt.LookupVerificationContext(memoryContextRound)
	a.ErrorIs(err, errSPVerificationContextNotFound)
	a.ErrorContains(err, "memory lookup failed")
}

func TestStateProofVerificationTracker_PanicInvalidBlockInsertion(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	contextToAdd := uint64(1)
	_ = feedBlocksUpToRound(spt, genesisBlock(), basics.Round(contextToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	pastBlock := randomBlock(0)
	a.Panics(func() { spt.appendCommitContext(&pastBlock.block) })
}

func TestStateProofVerificationTracker_lastLookupContextUpdatedAfterLookup(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	mockLedger, spt := initializeLedgerSpt(t)
	defer mockLedger.Close()
	defer spt.close()

	a.Empty(spt.lastLookedUpVerificationContext)

	NumberOfVerificationContextToAdd := uint64(10)
	_ = feedBlocksUpToRound(spt, genesisBlock(), basics.Round(NumberOfVerificationContextToAdd*defaultStateProofInterval),
		defaultStateProofInterval, true)

	a.Empty(spt.lastLookedUpVerificationContext)

	expectedContextInDbNum := NumberOfVerificationContextToAdd
	for i := uint64(defaultFirstStateProofContextInterval); i < expectedContextInDbNum; i++ {
		vf, err := spt.LookupVerificationContext(basics.Round(defaultStateProofInterval * i))
		a.NoError(err)

		a.Equal(*vf, spt.lastLookedUpVerificationContext)
	}
}
