// Copyright (C) 2019-2023 Algorand, Inc.
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

package node

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func followNodeDefaultGenesis() bookkeeping.Genesis {
	return bookkeeping.Genesis{
		SchemaID:    "go-test-follower-node-genesis",
		Proto:       protocol.ConsensusCurrentVersion,
		Network:     config.Devtestnet,
		FeeSink:     sinkAddr.String(),
		RewardsPool: poolAddr.String(),
		Allocation: []bookkeeping.GenesisAllocation{
			{
				Address: poolAddr.String(),
				State: basics.AccountData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000000000},
				},
			},
			{
				Address: sinkAddr.String(),
				State: basics.AccountData{
					MicroAlgos: basics.MicroAlgos{Raw: 1000000},
				},
			},
		},
	}
}

func setupFollowNode(t *testing.T) *AlgorandFollowerNode {
	cfg := config.GetDefaultLocal()
	cfg.EnableFollowMode = true
	genesis := followNodeDefaultGenesis()
	node, err := MakeFollower(logging.Base(), t.TempDir(), cfg, []string{}, genesis)
	require.NoError(t, err)
	return node
}

func remakeableFollowNode(t *testing.T, tempDir string, maxAcctLookback uint64) (*AlgorandFollowerNode, string) {
	cfg := config.GetDefaultLocal()
	cfg.EnableFollowMode = true
	cfg.DisableNetworking = true
	cfg.MaxAcctLookback = maxAcctLookback
	genesis := followNodeDefaultGenesis()
	if tempDir == "" {
		tempDir = t.TempDir()
	}
	followNode, err := MakeFollower(logging.Base(), tempDir, cfg, []string{}, genesis)
	require.NoError(t, err)
	return followNode, tempDir
}

func TestSyncRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	node := setupFollowNode(t)
	b := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round: 1,
		},
	}
	b.CurrentProtocol = protocol.ConsensusCurrentVersion
	err := node.Ledger().AddBlock(b, agreement.Certificate{})
	require.NoError(t, err)
	dbRound := uint64(node.Ledger().LatestTrackerCommitted())
	// Sync Round should be initialized to the ledger's dbRound + 1
	require.Equal(t, dbRound+1, node.GetSyncRound())
	// Set a new sync round
	require.NoError(t, node.SetSyncRound(dbRound+11))
	// Ensure it is persisted
	require.Equal(t, dbRound+11, node.GetSyncRound())
	// Unset the sync round and make sure get returns 0
	node.UnsetSyncRound()
	require.Equal(t, uint64(0), node.GetSyncRound())
}

func TestErrors(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// Validates that expected functions are disabled
	node := setupFollowNode(t)
	require.Error(t, node.BroadcastSignedTxGroup([]transactions.SignedTxn{}))
	require.Error(t, node.BroadcastInternalSignedTxGroup([]transactions.SignedTxn{}))
	_, err := node.Simulate(simulation.Request{})
	require.Error(t, err)
	_, err = node.GetParticipationKey(account.ParticipationID{})
	require.Error(t, err)
	require.Error(t, node.RemoveParticipationKey(account.ParticipationID{}))
	require.Error(t, node.AppendParticipationKeys(account.ParticipationID{}, account.StateProofKeys{}))
	_, err = node.InstallParticipationKey([]byte{})
	require.Error(t, err)
}

func TestDevModeWarning(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := config.GetDefaultLocal()
	cfg.EnableFollowMode = true
	genesis := followNodeDefaultGenesis()
	genesis.DevMode = true

	logger, hook := test.NewNullLogger()
	tlogger := logging.NewWrappedLogger(logger)
	_, err := MakeFollower(tlogger, t.TempDir(), cfg, []string{}, genesis)
	require.NoError(t, err)

	// check for the warning
	var foundEntry *logrus.Entry
	entries := hook.AllEntries()
	for i := range entries {
		if entries[i].Level == logrus.WarnLevel {
			foundEntry = entries[i]
		}
	}
	require.NotNil(t, foundEntry)
	require.Contains(t, foundEntry.Message, "Follower running on a devMode network. Must submit txns to a different node.")
}

// TestSyncRoundWithRemake extends TestSyncRound to simulate starting and stopping the network
func TestSyncRoundWithRemake(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	maxAcctLookback := uint64(100)

	followNode, tempDir := remakeableFollowNode(t, "", maxAcctLookback)
	addBlock := func(round basics.Round) {
		b := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				GenesisHash: followNode.ledger.GenesisHash(),
				Round:       round,
				RewardsState: bookkeeping.RewardsState{
					RewardsRate: 0,
					RewardsPool: poolAddr,
					FeeSink:     sinkAddr,
				},
			},
		}
		b.CurrentProtocol = protocol.ConsensusCurrentVersion
		err := followNode.Ledger().AddBlock(b, agreement.Certificate{})
		require.NoError(t, err)

		status, err := followNode.Status()
		require.NoError(t, err)
		require.Equal(t, round, status.LastRound)
	}

	// Part I. redo TestSyncRound
	// main differences are:
	// * cfg.DisableNetworking = true
	// * cfg.MaxAcctLookback = 100 (instead of 4)

	addBlock(basics.Round(1))

	dbRound := uint64(followNode.Ledger().LatestTrackerCommitted())
	// Sync Round should be initialized to the ledger's dbRound + 1
	require.Equal(t, dbRound+1, followNode.GetSyncRound())
	// Set a new sync round
	require.NoError(t, followNode.SetSyncRound(dbRound+11))
	// Ensure it is persisted
	require.Equal(t, dbRound+11, followNode.GetSyncRound())
	// Unset the sync round and make sure get returns 0
	followNode.UnsetSyncRound()
	require.Equal(t, uint64(0), followNode.GetSyncRound())

	// Part II. fast forward and then remake the node

	newRound := basics.Round(2 * maxAcctLookback)
	for i := basics.Round(2); i <= newRound; i++ {
		addBlock(i)
	}

	followNode, _ = remakeableFollowNode(t, tempDir, maxAcctLookback)
	status, err := followNode.Status()
	require.NoError(t, err)
	require.Equal(t, newRound, status.LastRound)

	// syncRound should be at
	// newRound - maxAcctLookback + 1 = maxAcctLookback + 1
	syncRound := followNode.GetSyncRound()
	require.Equal(t, uint64(maxAcctLookback+1), syncRound)
}

func TestFastCatchupResume(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	node := setupFollowNode(t)
	node.ctx = context.Background()

	// Initialize sync round to a future round.
	syncRound := uint64(10000)
	node.SetSyncRound(syncRound)
	require.Equal(t, syncRound, node.GetSyncRound())

	// Force catchpoint catchup mode to end, this should set the sync round to the current ledger round (0).
	out := node.SetCatchpointCatchupMode(false)
	<-out

	// Verify the sync was reset.
	assert.Equal(t, uint64(0), node.GetSyncRound())
}
