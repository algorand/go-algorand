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

package stateproofs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	sp "github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestStateProofs(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	r := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-stateproofs")
	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	consensusParams.StateProofInterval = 16
	consensusParams.StateProofTopVoters = 1024
	consensusParams.StateProofVotersLookback = 2
	consensusParams.StateProofWeightThreshold = (1 << 32) * 30 / 100
	consensusParams.StateProofStrengthTarget = 256
	consensusParams.StateProofRecoveryInterval = 6
	consensusParams.EnableStateProofKeyregCheck = true
	consensusParams.AgreementFilterTimeout = 1500 * time.Millisecond
	consensusParams.AgreementFilterTimeoutPeriod0 = 1500 * time.Millisecond
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))
	defer fixture.Shutdown()

	restClient, err := fixture.NC.AlgodClient()
	r.NoError(err)

	var lastStateProofBlock bookkeeping.Block
	var lastStateProofMessage stateproofmsg.Message
	libgoal := fixture.LibGoalClient

	expectedNumberOfStateProofs := uint64(4)
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs
	for rnd := uint64(1); rnd <= consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1); rnd++ {
		// send a dummy payment transaction to create non-empty blocks.
		sendPayment(r, &fixture, rnd)

		err = fixture.WaitForRound(rnd, 30*time.Second)
		r.NoError(err)

		blk, err := libgoal.BookkeepingBlock(rnd)
		r.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		if (rnd % consensusParams.StateProofInterval) == 0 {
			// Must have a merkle commitment for participants
			r.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			r.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight != basics.MicroAlgos{})

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		} else {
			r.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) == 0)
			r.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight == basics.MicroAlgos{})
		}

		for lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound &&
			lastStateProofBlock.Round() != 0 {
			nextStateProofRound := uint64(lastStateProofBlock.Round()) + consensusParams.StateProofInterval

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, libgoal, restClient, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams, expectedNumberOfStateProofs)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	r.Equalf(consensusParams.StateProofInterval*expectedNumberOfStateProofs, uint64(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}

func TestStateProofOverlappingKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)
	if testing.Short() {
		t.Skip()
	}

	r := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-stateproofs")
	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	consensusParams.StateProofInterval = 16
	consensusParams.StateProofTopVoters = 1024
	consensusParams.StateProofVotersLookback = 2
	consensusParams.StateProofWeightThreshold = (1 << 32) * 90 / 100
	consensusParams.StateProofStrengthTarget = 3
	consensusParams.EnableStateProofKeyregCheck = true
	consensusParams.AgreementFilterTimeout = 1000 * time.Millisecond
	consensusParams.AgreementFilterTimeoutPeriod0 = 1000 * time.Millisecond
	consensusParams.SeedLookback = 2
	consensusParams.SeedRefreshInterval = 8
	consensusParams.MaxBalLookback = 2 * consensusParams.SeedLookback * consensusParams.SeedRefreshInterval // 32
	consensusParams.StateProofRecoveryInterval = 4
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))
	defer fixture.Shutdown()

	// Get node libgoal clients in order to update their participation keys
	var libgoalNodeClients [5]libgoal.Client
	for i := 0; i < 5; i++ {
		nodeName := fmt.Sprintf("Node%d", i)
		c := fixture.GetLibGoalClientForNamedNode(nodeName)
		libgoalNodeClients[i] = c
	}

	// Get account address of each participating node
	var accounts [5]string
	for i, c := range libgoalNodeClients {
		parts, err := c.GetParticipationKeys() // should have 1 participation per node
		r.NoError(err)
		accounts[i] = parts[0].Address
	}

	restClient, err := fixture.NC.AlgodClient()
	r.NoError(err)

	var participations [5]account.Participation
	var lastStateProofBlock bookkeeping.Block
	var lastStateProofMessage stateproofmsg.Message
	libgoalClient := fixture.LibGoalClient

	k, err := libgoalNodeClients[0].GetParticipationKeys()
	r.NoError(err)
	voteLastValid := k[0].Key.VoteLastValid
	expectedNumberOfStateProofs := uint64(10)
	for rnd := uint64(1); rnd <= consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1); rnd++ {
		if rnd == voteLastValid-64 { // allow some buffer period before the voting keys are expired (for the keyreg to take effect)
			// Generate participation keys (for the same accounts)
			for i := 0; i < 5; i++ {
				// Overlapping stateproof keys (the key for round 0 is valid up to 256)
				_, part, err := installParticipationKey(t, libgoalNodeClients[i], accounts[i], 0, 200)
				r.NoError(err)
				participations[i] = part
			}
			// Register overlapping participation keys
			for i := 0; i < 5; i++ {
				registerParticipationAndWait(t, libgoalNodeClients[i], participations[i])
			}
		}

		// send a dummy payment transaction.
		sendPayment(r, &fixture, rnd)

		err = fixture.WaitForRound(rnd, 30*time.Second)
		r.NoError(err)

		blk, err := libgoalClient.BookkeepingBlock(rnd)
		r.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		t.Logf("Round %d, block %v\n", rnd, blk)

		if (rnd % consensusParams.StateProofInterval) == 0 {
			// Must have a merkle commitment for participants
			r.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			r.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight != basics.MicroAlgos{})

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		}

		for lastStateProofBlock.Round() != 0 && lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound {
			nextStateProofRound := uint64(lastStateProofBlock.Round()) + consensusParams.StateProofInterval

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, libgoalClient, restClient, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams, expectedNumberOfStateProofs)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	r.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}

func sendPayment(r *require.Assertions, fixture *fixtures.RestClientFixture, rnd uint64) {
	node0Client := fixture.GetLibGoalClientForNamedNode("Node0")
	node0Wallet, err := node0Client.GetUnencryptedWalletHandle()
	r.NoError(err)
	node0AccountList, err := node0Client.ListAddresses(node0Wallet)
	r.NoError(err)
	node0Account := node0AccountList[0]

	node1Client := fixture.GetLibGoalClientForNamedNode("Node1")
	node1Wallet, err := node1Client.GetUnencryptedWalletHandle()
	r.NoError(err)
	node1AccountList, err := node1Client.ListAddresses(node1Wallet)
	r.NoError(err)
	node1Account := node1AccountList[0]

	minTxnFee, _, err := fixture.CurrentMinFeeAndBalance()
	r.NoError(err)

	_, err = node0Client.SendPaymentFromUnencryptedWallet(node0Account, node1Account, minTxnFee, 1, []byte{byte(rnd)})
	r.NoError(err)
}

func verifyStateProofForRound(r *require.Assertions, libgoal libgoal.Client, restClient client.RestClient, nextStateProofRound uint64, prevStateProofMessage stateproofmsg.Message, lastStateProofBlock bookkeeping.Block, consensusParams config.ConsensusParams, expectedNumberOfStateProofs uint64) (stateproofmsg.Message, bookkeeping.Block) {
	curRound, err := libgoal.CurrentRound()
	r.NoError(err)

	res, err := restClient.TransactionsByAddr(transactions.StateProofSender.String(), 0, curRound, expectedNumberOfStateProofs+1)
	r.NoError(err)

	var stateProof sp.StateProof
	var stateProofMessage stateproofmsg.Message
	stateProofFound := false
	for _, txn := range res.Transactions {
		r.Equal(txn.Type, string(protocol.StateProofTx))
		r.True(txn.StateProof != nil)
		if txn.StateProof.StateProofIntervalLatestRound == nextStateProofRound {
			err = protocol.Decode(txn.StateProof.StateProof, &stateProof)
			r.NoError(err)
			err = protocol.Decode(txn.StateProof.StateProofMessage, &stateProofMessage)
			r.NoError(err)
			stateProofFound = true
		}
	}
	r.True(stateProofFound)

	nextStateProofBlock, err := libgoal.BookkeepingBlock(nextStateProofRound)
	r.NoError(err)

	if !prevStateProofMessage.MsgIsZero() {
		//if we have a previous stateproof message we can verify the current stateproof using data from it
		verifier := sp.MkVerifierWithLnProvenWeight(prevStateProofMessage.VotersCommitment, prevStateProofMessage.LnProvenWeight, consensusParams.StateProofStrengthTarget)
		err = verifier.Verify(uint64(nextStateProofBlock.Round()), stateProofMessage.IntoStateProofMessageHash(), &stateProof)
		r.NoError(err)
	}
	var votersRoot = make([]byte, sp.HashSize)
	copy(votersRoot[:], lastStateProofBlock.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment)

	provenWeight, overflowed := basics.Muldiv(lastStateProofBlock.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight.Raw, uint64(consensusParams.StateProofWeightThreshold), 1<<32)
	r.False(overflowed)

	verifier, err := sp.MkVerifier(votersRoot, provenWeight, consensusParams.StateProofStrengthTarget)
	r.NoError(err)

	err = verifier.Verify(uint64(nextStateProofBlock.Round()), stateProofMessage.IntoStateProofMessageHash(), &stateProof)
	r.NoError(err)
	return stateProofMessage, nextStateProofBlock
}

// TestRecoverFromLaggingStateProofChain simulates a situation where the stateproof chain is lagging after the main chain.
// If the missing data is being accepted before  StateProofRecoveryInterval * StateProofInterval rounds have passed, nodes should
// be able to produce stateproofs and continue as normal
func TestRecoverFromLaggingStateProofChain(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	r := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-stateproofs")
	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	consensusParams.StateProofInterval = 16
	consensusParams.StateProofTopVoters = 1024
	consensusParams.StateProofVotersLookback = 2
	// Stateproof can be generated even if not all nodes function correctly. e.g node can be offline
	// and stateproofs might still get generated. in order to make sure that all nodes work correctly
	// we want the network to fail in generating stateproof if one node is not working correctly.
	// For that we will increase the proven Weight to be close to 100%. However, this change might not be enough.
	// if the signed Weight and the Proven Weight are very close to each other the number of reveals in the state proof
	// will exceed the MAX_NUMBER_OF_REVEALS and proofs would not get generated
	// for that reason we need to the decrease the StateProofStrengthTarget creating a "weak cert"
	consensusParams.StateProofWeightThreshold = (1 << 32) * 90 / 100
	consensusParams.StateProofStrengthTarget = 4
	consensusParams.StateProofRecoveryInterval = 4
	consensusParams.EnableStateProofKeyregCheck = true
	consensusParams.AgreementFilterTimeout = 1500 * time.Millisecond
	consensusParams.AgreementFilterTimeoutPeriod0 = 1500 * time.Millisecond
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))
	defer fixture.Shutdown()

	err := fixture.WaitForRound(1, 30*time.Second)
	r.NoError(err)

	dir, err := fixture.GetNodeDir("Node4")
	r.NoError(err)

	nc := nodecontrol.MakeNodeController(fixture.GetBinDir(), dir)
	//Stop one of the nodes to prevent SP generation due to insufficient signatures.
	nc.FullStop()

	restClient, err := fixture.NC.AlgodClient()
	r.NoError(err)

	var lastStateProofBlock bookkeeping.Block
	var lastStateProofMessage stateproofmsg.Message
	libgoal := fixture.LibGoalClient

	expectedNumberOfStateProofs := uint64(4)
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs
	for rnd := uint64(2); rnd <= consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1); rnd++ {
		// Start the node in the last interval after which the SP will be abandoned if SPs are not generated.
		if rnd == (consensusParams.StateProofRecoveryInterval)*consensusParams.StateProofInterval {
			t.Logf("at round %d starting node\n", rnd)
			dir, err = fixture.GetNodeDir("Node4")
			fixture.StartNode(dir)
		}

		// send a dummy payment transaction to create non-empty blocks
		sendPayment(r, &fixture, rnd)

		err = fixture.WaitForRound(rnd, 30*time.Second)
		r.NoError(err)

		blk, err := libgoal.BookkeepingBlock(rnd)
		r.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		if (rnd % consensusParams.StateProofInterval) == 0 {
			// Must have a merkle commitment for participants
			r.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			r.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight != basics.MicroAlgos{})

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		}

		// in case StateProofNextRound has changed (larger than the lastStateProofBlock ) we verify the new stateproof.
		// since the stateproof chain is catching up there would be several proofs to check
		for lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound &&
			lastStateProofBlock.Round() != 0 {
			nextStateProofRound := uint64(lastStateProofBlock.Round()) + consensusParams.StateProofInterval

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, libgoal, restClient, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams, expectedNumberOfStateProofs)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}
	r.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}

// TestUnableToRecoverFromLaggingStateProofChain simulates a situation where the stateproof chain is lagging after the main chain.
// unlike TestRecoverFromLaggingStateProofChain, in this test the node will start at a later round and the network will not be able to produce stateproofs/
func TestUnableToRecoverFromLaggingStateProofChain(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	r := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-stateproofs")
	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	consensusParams.StateProofInterval = 16
	consensusParams.StateProofTopVoters = 1024
	consensusParams.StateProofVotersLookback = 2
	// Stateproof can be generated even if not all nodes function correctly. e.g node can be offline
	// and stateproofs might still get generated. in order to make sure that all nodes work correctly
	// we want the network to fail in generating stateproof if one node is not working correctly.
	// For that we will increase the proven Weight to be close to 100%. However, this change might not be enough.
	// if the signed Weight and the Proven Weight are very close to each other the number of reveals in the state proof
	// will exceed the MAX_NUMBER_OF_REVEALS and proofs would not get generated
	// for that reason we need to the decrease the StateProofStrengthTarget creating a "weak cert"
	consensusParams.StateProofWeightThreshold = (1 << 32) * 90 / 100
	consensusParams.StateProofStrengthTarget = 4
	consensusParams.StateProofRecoveryInterval = 4
	consensusParams.EnableStateProofKeyregCheck = true
	consensusParams.AgreementFilterTimeout = 1500 * time.Millisecond
	consensusParams.AgreementFilterTimeoutPeriod0 = 1500 * time.Millisecond
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))
	defer fixture.Shutdown()

	err := fixture.WaitForRound(1, 30*time.Second)
	r.NoError(err)

	dir, err := fixture.GetNodeDir("Node4")
	nc := nodecontrol.MakeNodeController(fixture.GetBinDir(), dir)
	nc.FullStop()

	var lastStateProofBlock bookkeeping.Block
	libgoal := fixture.LibGoalClient

	expectedNumberOfStateProofs := uint64(4)
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs
	for rnd := uint64(2); rnd <= consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1); rnd++ {
		if rnd == (consensusParams.StateProofRecoveryInterval+2)*consensusParams.StateProofInterval {
			t.Logf("at round %d starting node\n", rnd)
			dir, err = fixture.GetNodeDir("Node4")
			fixture.StartNode(dir)
		}
		// send a dummy payment transaction to create non-empty blocks
		sendPayment(r, &fixture, rnd)

		err = fixture.WaitForRound(rnd, 30*time.Second)
		r.NoError(err)

		blk, err := libgoal.BookkeepingBlock(rnd)
		r.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		if (rnd % consensusParams.StateProofInterval) == 0 {
			// Must have a merkle commitment for participants
			r.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			r.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight != basics.MicroAlgos{})

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		}

		if lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound &&
			lastStateProofBlock.Round() != 0 {
			r.FailNow("found a state proof at round %d", blk.Round())
		}
	}
}

// installParticipationKey generates a new key for a given account and installs it with the client.
func installParticipationKey(t *testing.T, client libgoal.Client, addr string, firstValid, lastValid uint64) (resp generated.PostParticipationResponse, part account.Participation, err error) {
	dir, err := ioutil.TempDir("", "temporary_partkey_dir")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// Install overlapping participation keys...
	part, filePath, err := client.GenParticipationKeysTo(addr, firstValid, lastValid, 100, dir)
	require.NoError(t, err)
	require.NotNil(t, filePath)
	require.Equal(t, addr, part.Parent.String())

	resp, err = client.AddParticipationKey(filePath)
	return
}

func registerParticipationAndWait(t *testing.T, client libgoal.Client, part account.Participation) generated.NodeStatusResponse {
	currentRnd, err := client.CurrentRound()
	require.NoError(t, err)
	sAccount := part.Address().String()
	sWH, err := client.GetUnencryptedWalletHandle()
	require.NoError(t, err)
	goOnlineTx, err := client.MakeRegistrationTransactionWithGenesisID(part, 1000, currentRnd, uint64(part.LastValid), [32]byte{}, true)
	assert.NoError(t, err)
	require.Equal(t, sAccount, goOnlineTx.Src().String())
	onlineTxID, err := client.SignAndBroadcastTransaction(sWH, nil, goOnlineTx)
	require.NoError(t, err)
	require.NotEmpty(t, onlineTxID)
	status, err := client.WaitForRound(currentRnd + 1)
	require.NoError(t, err)
	return status
}
