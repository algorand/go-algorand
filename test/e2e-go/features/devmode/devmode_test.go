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

// Check that devmode is functioning as designed.
package devmode

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/netdeploy"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestDevMode(t *testing.T) {
	partitiontest.PartitionTest(t)
	fixtures.MultiProtocolTest(t, testDevMode, protocol.ConsensusFuture, protocol.ConsensusCurrentVersion)
}

func testDevMode(t *testing.T, version protocol.ConsensusVersion) {
	// Start devmode network, and make sure everything is primed by sending a transaction.
	var fixture fixtures.RestClientFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "DevModeNetwork.json"), netdeploy.OverrideConsensusVersion(version))
	fixture.Start()
	defer fixture.Shutdown()
	sender, err := fixture.GetRichestAccount()
	require.NoError(t, err)
	key := crypto.GenerateSignatureSecrets(crypto.Seed{})
	receiver := basics.Address(key.SignatureVerifier)
	txn := fixture.SendMoneyAndWait(0, 100000, 1000, sender.Address, receiver.String(), "")
	require.NotNil(t, txn.ConfirmedRound)
	firstRound := *txn.ConfirmedRound + 1
	blk, err := fixture.AlgodClient.Block(*txn.ConfirmedRound)
	require.NoError(t, err)
	seconds := blk.Block.TimeStamp
	prevTime := time.Unix(seconds, 0)
	// Set Block timestamp offset to test that consecutive txns properly get their block time set
	const blkOffset = uint64(1_000_000)
	err = fixture.AlgodClient.SetBlockTimestampOffset(blkOffset)
	require.NoError(t, err)
	resp, err := fixture.AlgodClient.GetBlockTimestampOffset()
	require.NoError(t, err)
	require.Equal(t, blkOffset, resp.Offset)

	// 2 transactions should be sent within one normal confirmation time.
	for i := uint64(0); i < 2; i++ {
		round := firstRound + i
		txn = fixture.SendMoneyAndWait(round, 100001, 1000, sender.Address, receiver.String(), "")
		// SendMoneyAndWait subtracts 1 from firstValid
		require.Equal(t, round-1, uint64(txn.Txn.Txn.FirstValid))
		newBlk, err := fixture.AlgodClient.Block(round)
		require.NoError(t, err)
		newBlkSeconds := newBlk.Block.TimeStamp
		currTime := time.Unix(newBlkSeconds, 0)
		require.Equal(t, currTime, prevTime.Add(1_000_000*time.Second))
		prevTime = currTime
	}
}

func TestTxnGroupDeltasDevMode(t *testing.T) {
	partitiontest.PartitionTest(t)
	fixtures.MultiProtocolTest(t, testTxnGroupDeltasDevMode, protocol.ConsensusFuture, protocol.ConsensusCurrentVersion)
}

// Starts up a devmode network, sends a txn, and fetches the txn group delta for that txn
func testTxnGroupDeltasDevMode(t *testing.T, version protocol.ConsensusVersion) {
	// Start devmode network, and send a transaction.
	var fixture fixtures.RestClientFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "DevModeTxnTracerNetwork.json"), netdeploy.OverrideConsensusVersion(version))
	fixture.Start()
	defer fixture.Shutdown()
	sender, err := fixture.GetRichestAccount()
	require.NoError(t, err)
	key := crypto.GenerateSignatureSecrets(crypto.Seed{})
	receiver := basics.Address(key.SignatureVerifier)

	status, err := fixture.AlgodClient.Status()
	require.NoError(t, err)
	curRound := status.LastRound

	wh, err := fixture.LibGoalClient.GetUnencryptedWalletHandle()
	require.NoError(t, err)

	fundingTx, err := fixture.LibGoalClient.SendPaymentFromWalletWithLease(wh, nil, sender.Address, receiver.String(), 1000, 100000, nil, "", [32]byte{1, 2, 3}, basics.Round(curRound).SubSaturate(1), 0)
	require.NoError(t, err)
	txn, err := fixture.WaitForConfirmedTxn(curRound+uint64(5), fundingTx.ID().String())
	require.NoError(t, err)
	require.NotNil(t, txn.ConfirmedRound)
	_, err = fixture.AlgodClient.Block(*txn.ConfirmedRound)
	require.NoError(t, err)

	// Test GetLedgerStateDeltaForTransactionGroup and verify the response contains a delta
	txngroupResponse, err := fixture.AlgodClient.GetLedgerStateDeltaForTransactionGroup(txn.Txn.ID().String())
	require.NoError(t, err)
	require.NotZero(t, txngroupResponse)

	// Test GetTransactionGroupLedgerStateDeltasForRound and verify the response contains the delta for our txn
	roundResponse, err := fixture.AlgodClient.GetTransactionGroupLedgerStateDeltasForRound(1)
	require.NoError(t, err)
	require.Equal(t, len(roundResponse.Deltas), 1)
	groupDelta := roundResponse.Deltas[0]
	require.Len(t, groupDelta.Ids, 1)
	require.Equal(t, groupDelta.Ids[0], txn.Txn.ID().String())

	// Assert that the TxIDs field across both endpoint responses is the same
	require.Equal(t, txngroupResponse.Txids, groupDelta.Delta.Txids)

	// Txleases should always be nil for JSON responses
	require.Nil(t, txngroupResponse.Txleases)
	require.Nil(t, groupDelta.Delta.Txleases)
}
