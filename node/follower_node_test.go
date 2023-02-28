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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
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
	latestRound := uint64(node.Ledger().Latest())
	// Sync Round should be initialized to the ledger's latest round
	require.Equal(t, latestRound, node.GetSyncRound())
	// Set a new sync round
	require.NoError(t, node.SetSyncRound(latestRound+10))
	// Ensure it is persisted
	require.Equal(t, latestRound+10, node.GetSyncRound())
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
	_, err := node.Simulate([]transactions.SignedTxn{})
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
