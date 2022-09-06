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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
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

func blockStateProofsEnabled(prevBlock *blockEntry, stuck bool) blockEntry {
	round := prevBlock.block.Round() + 1
	lastAttestedRound := prevBlock.block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound

	block := randomBlock(round)
	block.block.CurrentProtocol = protocol.ConsensusCurrentVersion
	statProofInterval := basics.Round(block.block.ConsensusProtocol().StateProofInterval)

	var stateTracking bookkeeping.StateProofTrackingData
	block.block.BlockHeader.StateProofTracking = make(map[protocol.StateProofType]bookkeeping.StateProofTrackingData)

	if !stuck && round-lastAttestedRound > statProofInterval {
		stateTracking.StateProofNextRound = lastAttestedRound + statProofInterval
	}

	block.block.BlockHeader.StateProofTracking[protocol.StateProofBasic] = stateTracking
	return block
}

func feedBlocks(ml *mockLedgerForTracker, numOfBlocks uint64, prevBlock *blockEntry, stuck bool) *blockEntry {
	for i := uint64(1); i <= numOfBlocks; i++ {
		block := blockStateProofsEnabled(prevBlock, stuck)
		ml.trackers.newBlock(block.block, ledgercore.StateDelta{})
		prevBlock = &block
	}

	return prevBlock
}

func TestStateproofVerificationTracker_Addition(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	expectedNumberOfVerificationData := uint64(2)
	numOfBlocks := expectedNumberOfVerificationData * config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval
	feedBlocks(ml, numOfBlocks, &blockEntry{}, true)

	a.Equal(uint64(len(spt.trackedData)), expectedNumberOfVerificationData)
}

func TestStateproofVerificationTracker_Removal(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	ml, spt := initializeLedgerSpt(t)
	defer ml.Close()
	defer spt.close()

	intervalsToAdd := uint64(6)
	intervalsToRemove := uint64(3)
	roundsInInterval := config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval

	lastStuckBlock := feedBlocks(ml, intervalsToAdd*roundsInInterval, &blockEntry{}, true)
	feedBlocks(ml, intervalsToRemove, lastStuckBlock, false)

	a.Equal(uint64(len(spt.trackedData)), intervalsToAdd-intervalsToRemove)
}
