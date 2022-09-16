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

var defaultInterval = basics.Round(config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval)

func getGenesisBlock() *blockEntry {
	initialRound := basics.Round(1)
	block := randomBlock(initialRound)

	var stateTracking bookkeeping.StateProofTrackingData
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)

	stateTracking.StateProofNextRound = defaultInterval * 2
	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking

	return &block
}

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

func TestStateproofVerificationTracker_CommitAddition(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedNumberOfVerificationData := uint64(1)

	lastBlock := feedBlocks(ml, expectedNumberOfVerificationData*uint64(defaultInterval), getGenesisBlock(), true)
	a.Equal(expectedNumberOfVerificationData, uint64(len(spt.trackedData)))

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	a.Equal(uint64(0), uint64(len(spt.trackedData)))

	for stateProofVerificationDataIndex := uint64(0); stateProofVerificationDataIndex < expectedNumberOfVerificationData; stateProofVerificationDataIndex++ {
		targetStateProofRound := basics.Round(stateProofVerificationDataIndex+2) * defaultInterval
		_, err := spt.LookupVerificationData(targetStateProofRound)
		a.NoError(err)
	}
}

func TestStateproofVerificationTracker_Removal(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	intervalsToAdd := uint64(6)
	intervalsToRemove := uint64(3)

	lastStuckBlock := feedBlocks(ml, intervalsToAdd*uint64(defaultInterval), getGenesisBlock(), true)
	lastBlock := feedBlocks(ml, intervalsToRemove, lastStuckBlock, false)

	ml.trackers.committedUpTo(lastBlock.block.Round())
	ml.trackers.waitAccountsWriting()

	for stateProofVerificationDataIndex := uint64(0); stateProofVerificationDataIndex < intervalsToRemove; stateProofVerificationDataIndex++ {
		targetStateProofRound := basics.Round(stateProofVerificationDataIndex+2) * defaultInterval
		_, err := spt.LookupVerificationData(targetStateProofRound)
		a.ErrorIs(err, sql.ErrNoRows)
	}

	for stateProofVerificationDataIndex := intervalsToRemove; stateProofVerificationDataIndex < intervalsToAdd; stateProofVerificationDataIndex++ {
		targetStateProofRound := basics.Round(stateProofVerificationDataIndex+2) * defaultInterval
		_, err := spt.LookupVerificationData(targetStateProofRound)
		a.NoError(err)
	}
}

// TODO: Test addition and removal after exceeding initial capacity
// TODO: Test interval size change
