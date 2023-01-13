package node

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

func setupDataNode(t *testing.T) *AlgorandDataNode {
	cfg := config.GetDefaultLocal()
	cfg.NodeSyncMode = true
	genesis := bookkeeping.Genesis{
		SchemaID:    "go-test-data-node-genesis",
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
	node, err := MakeData(logging.Base(), t.TempDir(), cfg, []string{}, genesis)
	require.NoError(t, err)
	return node
}

func TestSyncRound(t *testing.T) {
	node := setupDataNode(t)
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
	// Validates that expected functions are disabled
	node := setupDataNode(t)
	require.Error(t, node.BroadcastSignedTxGroup([]transactions.SignedTxn{}))
	require.Error(t, node.BroadcastInternalSignedTxGroup([]transactions.SignedTxn{}))
	_, _, err := node.Simulate([]transactions.SignedTxn{})
	require.Error(t, err)
	_, err = node.GetParticipationKey(account.ParticipationID{})
	require.Error(t, err)
	require.Error(t, node.RemoveParticipationKey(account.ParticipationID{}))
	require.Error(t, node.AppendParticipationKeys(account.ParticipationID{}, account.StateProofKeys{}))
	_, err = node.InstallParticipationKey([]byte{})
	require.Error(t, err)
	_, err = node.AssembleBlock(basics.Round(0))
	require.Error(t, err)
}
