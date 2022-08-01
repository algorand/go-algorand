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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	sp "github.com/algorand/go-algorand/crypto/stateproof"
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

type accountFetcher struct {
	nodeName      string
	accountNumber int
}

func (a accountFetcher) getAccount(r *require.Assertions, f *fixtures.RestClientFixture) string {
	node0Client := f.GetLibGoalClientForNamedNode(a.nodeName)
	node0Wallet, err := node0Client.GetUnencryptedWalletHandle()
	r.NoError(err)
	node0AccountList, err := node0Client.ListAddresses(node0Wallet)
	r.NoError(err)
	return node0AccountList[a.accountNumber]
}

func (a accountFetcher) getBalance(r *require.Assertions, f *fixtures.RestClientFixture) uint64 {
	balance, _ := f.GetBalanceAndRound(a.getAccount(r, f))
	return balance
}

type paymentSender struct {
	from   accountFetcher
	to     accountFetcher
	amount uint64
}

func (p paymentSender) sendPayment(a *require.Assertions, f *fixtures.RestClientFixture, round uint64) {
	account0 := p.from.getAccount(a, f)
	account1 := p.to.getAccount(a, f)

	minTxnFee, _, err := f.CurrentMinFeeAndBalance()
	a.NoError(err)

	client0 := f.GetLibGoalClientForNamedNode(p.from.nodeName)
	_, err = client0.SendPaymentFromUnencryptedWallet(account0, account1, minTxnFee, p.amount, []byte{byte(round)})
	a.NoError(err)
}

const timeoutUntilNextRound = 3 * time.Minute

func TestStateProofs(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-stateproofs")
	consensusParams := getDefaultStateProofConsensusParams()
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))
	defer fixture.Shutdown()

	verifyStateProofsCreation(t, &fixture, consensusParams)
}

func TestStateProofsMultiWallets(t *testing.T) {
	t.Skip("this test is heavy and should be run manually")
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-stateproofs")
	consensusParams := getDefaultStateProofConsensusParams()
	// Stateproof can be generated even if not all nodes function correctly. e.g node can be offline
	// and stateproofs might still get generated. in order to make sure that all nodes work correctly
	// we want the network to fail in generating stateproof if one node is not working correctly.
	// For that we will increase the proven Weight to be close to 100%. However, this change might not be enough.
	// if the signed Weight and the Proven Weight are very close to each other the number of reveals in the state proof
	// will exceed the MAX_NUMBER_OF_REVEALS and proofs would not get generated
	// for that reason we need to the decrease the StateProofStrengthTarget creating a "weak stateproof"
	consensusParams.StateProofWeightThreshold = (1 << 32) * 90 / 100
	consensusParams.StateProofStrengthTarget = 4
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProofMultiWallets.json"))
	defer fixture.Shutdown()

	verifyStateProofsCreation(t, &fixture, consensusParams)
}

func verifyStateProofsCreation(t *testing.T, fixture *fixtures.RestClientFixture, consensusParams config.ConsensusParams) {
	r := require.New(fixtures.SynchronizedTest(t))

	var lastStateProofBlock bookkeeping.Block
	var lastStateProofMessage stateproofmsg.Message
	libgoal := fixture.LibGoalClient

	expectedNumberOfStateProofs := uint64(4)
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs
	for rnd := uint64(1); rnd <= consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1); rnd++ {
		// send a dummy payment transaction to create non-empty blocks.
		paymentSender{
			from:   accountFetcher{nodeName: "Node0", accountNumber: 0},
			to:     accountFetcher{nodeName: "Node1", accountNumber: 0},
			amount: 1,
		}.sendPayment(r, fixture, rnd)

		err := fixture.WaitForRound(rnd, timeoutUntilNextRound)
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
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams, expectedNumberOfStateProofs)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	r.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}

func TestStateProofOverlappingKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)
	//if testing.Short() {
	//	t.Skip()
	//}

	r := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-stateproofs")
	consensusParams := getDefaultStateProofConsensusParams()
	consensusParams.StateProofWeightThreshold = (1 << 32) * 90 / 100
	consensusParams.StateProofStrengthTarget = 3
	consensusParams.AgreementFilterTimeout = 1000 * time.Millisecond
	consensusParams.AgreementFilterTimeoutPeriod0 = 1000 * time.Millisecond
	consensusParams.SeedLookback = 2
	consensusParams.SeedRefreshInterval = 8
	consensusParams.MaxBalLookback = 2 * consensusParams.SeedLookback * consensusParams.SeedRefreshInterval // 32
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
		paymentSender{
			from:   accountFetcher{nodeName: "Node0", accountNumber: 0},
			to:     accountFetcher{nodeName: "Node1", accountNumber: 0},
			amount: 1,
		}.sendPayment(r, &fixture, rnd)

		err = fixture.WaitForRound(rnd, timeoutUntilNextRound)
		r.NoError(err)

		blk, err := libgoalClient.BookkeepingBlock(rnd)
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

		for lastStateProofBlock.Round() != 0 && lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound {
			nextStateProofRound := uint64(lastStateProofBlock.Round()) + consensusParams.StateProofInterval

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, &fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams, expectedNumberOfStateProofs)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	r.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}

func TestStateProofMessageCommitmentVerification(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	r := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-stateproofs")
	consensusParams := getDefaultStateProofConsensusParams()
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))
	defer fixture.Shutdown()

	libgoalClient := fixture.LibGoalClient

	var startRound = uint64(1)
	var nextStateProofRound = uint64(0)
	var firstStateProofRound = 2 * consensusParams.StateProofInterval

	for rnd := startRound; nextStateProofRound <= firstStateProofRound; rnd++ {
		paymentSender{
			from:   accountFetcher{nodeName: "Node0", accountNumber: 0},
			to:     accountFetcher{nodeName: "Node1", accountNumber: 0},
			amount: 1,
		}.sendPayment(r, &fixture, rnd)

		err := fixture.WaitForRound(rnd, timeoutUntilNextRound)
		r.NoError(err)

		blk, err := libgoalClient.BookkeepingBlock(rnd)
		r.NoError(err)

		nextStateProofRound = uint64(blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
	}

	_, stateProofMessage := getStateProofByLastRound(r, &fixture, firstStateProofRound, 1)
	t.Logf("found first stateproof, attesting to rounds %d - %d. Verifying.\n", stateProofMessage.FirstAttestedRound, stateProofMessage.LastAttestedRound)

	for rnd := stateProofMessage.FirstAttestedRound; rnd <= stateProofMessage.LastAttestedRound; rnd++ {
		proofResp, singleLeafProof, err := fixture.LightBlockHeaderProof(rnd)
		r.NoError(err)

		blk, err := libgoalClient.BookkeepingBlock(rnd)
		r.NoError(err)

		lightBlockHeader := blk.ToLightBlockHeader()

		elems := make(map[uint64]crypto.Hashable)
		elems[proofResp.Index] = &lightBlockHeader
		err = merklearray.VerifyVectorCommitment(stateProofMessage.BlockHeadersCommitment, elems, singleLeafProof.ToProof())
		r.NoError(err)
	}
}

func getDefaultStateProofConsensusParams() config.ConsensusParams {
	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	consensusParams.StateProofInterval = 16
	consensusParams.StateProofTopVoters = 1024
	consensusParams.StateProofVotersLookback = 2
	consensusParams.StateProofWeightThreshold = (1 << 32) * 30 / 100
	consensusParams.StateProofStrengthTarget = 256
	consensusParams.StateProofMaxRecoveryIntervals = 6
	consensusParams.EnableStateProofKeyregCheck = true
	consensusParams.AgreementFilterTimeout = 1500 * time.Millisecond
	consensusParams.AgreementFilterTimeoutPeriod0 = 1500 * time.Millisecond

	return consensusParams
}

func getStateProofByLastRound(r *require.Assertions, fixture *fixtures.RestClientFixture, stateProofLatestRound uint64, expectedNumberOfStateProofs uint64) (sp.StateProof, stateproofmsg.Message) {
	restClient, err := fixture.NC.AlgodClient()
	r.NoError(err)

	curRound, err := fixture.LibGoalClient.CurrentRound()
	r.NoError(err)

	res, err := restClient.TransactionsByAddr(transactions.StateProofSender.String(), 0, curRound, expectedNumberOfStateProofs+1)
	r.NoError(err)

	var stateProof sp.StateProof
	var stateProofMessage stateproofmsg.Message
	for _, txn := range res.Transactions {
		r.Equal(txn.Type, string(protocol.StateProofTx))
		r.True(txn.StateProof != nil)
		if txn.StateProof.StateProofIntervalLatestRound == stateProofLatestRound {
			err = protocol.Decode(txn.StateProof.StateProof, &stateProof)
			r.NoError(err)
			err = protocol.Decode(txn.StateProof.StateProofMessage, &stateProofMessage)
			r.NoError(err)

			return stateProof, stateProofMessage
		}
	}

	r.FailNow("no state proof with latest round %d found", stateProofLatestRound)

	// Should never get here
	return sp.StateProof{}, stateproofmsg.Message{}
}

func verifyStateProofForRound(r *require.Assertions, fixture *fixtures.RestClientFixture, nextStateProofRound uint64, prevStateProofMessage stateproofmsg.Message, lastStateProofBlock bookkeeping.Block, consensusParams config.ConsensusParams, expectedNumberOfStateProofs uint64) (stateproofmsg.Message, bookkeeping.Block) {
	stateProof, stateProofMessage := getStateProofByLastRound(r, fixture, nextStateProofRound, expectedNumberOfStateProofs)

	nextStateProofBlock, err := fixture.LibGoalClient.BookkeepingBlock(nextStateProofRound)

	r.NoError(err)

	if !prevStateProofMessage.MsgIsZero() {
		//if we have a previous stateproof message we can verify the current stateproof using data from it
		verifier := sp.MkVerifierWithLnProvenWeight(prevStateProofMessage.VotersCommitment, prevStateProofMessage.LnProvenWeight, consensusParams.StateProofStrengthTarget)
		err = verifier.Verify(uint64(nextStateProofBlock.Round()), stateProofMessage.Hash(), &stateProof)
		r.NoError(err)
	}
	var votersRoot = make([]byte, sp.HashSize)
	copy(votersRoot[:], lastStateProofBlock.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment)

	provenWeight, overflowed := basics.Muldiv(lastStateProofBlock.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight.Raw, uint64(consensusParams.StateProofWeightThreshold), 1<<32)
	r.False(overflowed)

	verifier, err := sp.MkVerifier(votersRoot, provenWeight, consensusParams.StateProofStrengthTarget)
	r.NoError(err)

	err = verifier.Verify(uint64(nextStateProofBlock.Round()), stateProofMessage.Hash(), &stateProof)
	r.NoError(err)
	return stateProofMessage, nextStateProofBlock
}

// TestRecoverFromLaggingStateProofChain simulates a situation where the stateproof chain is lagging after the main chain.
// If the missing data is being accepted before  StateProofMaxRecoveryIntervals * StateProofInterval rounds have passed, nodes should
// be able to produce stateproofs and continue as normal
func TestRecoverFromLaggingStateProofChain(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	r := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-stateproofs")
	consensusParams := getDefaultStateProofConsensusParams()
	// Stateproof can be generated even if not all nodes function correctly. e.g node can be offline
	// and stateproofs might still get generated. in order to make sure that all nodes work correctly
	// we want the network to fail in generating stateproof if one node is not working correctly.
	// For that we will increase the proven Weight to be close to 100%. However, this change might not be enough.
	// if the signed Weight and the Proven Weight are very close to each other the number of reveals in the state proof
	// will exceed the MAX_NUMBER_OF_REVEALS and proofs would not get generated
	// for that reason we need to the decrease the StateProofStrengthTarget creating a "weak cert"
	consensusParams.StateProofWeightThreshold = (1 << 32) * 90 / 100
	consensusParams.StateProofStrengthTarget = 4
	consensusParams.StateProofMaxRecoveryIntervals = 4
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))
	defer fixture.Shutdown()

	err := fixture.WaitForRound(1, timeoutUntilNextRound)
	r.NoError(err)

	dir, err := fixture.GetNodeDir("Node4")
	r.NoError(err)

	nc := nodecontrol.MakeNodeController(fixture.GetBinDir(), dir)
	//Stop one of the nodes to prevent SP generation due to insufficient signatures.
	nc.FullStop()

	var lastStateProofBlock bookkeeping.Block
	var lastStateProofMessage stateproofmsg.Message
	libgoal := fixture.LibGoalClient

	expectedNumberOfStateProofs := uint64(4)
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs
	for rnd := uint64(2); rnd <= consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1); rnd++ {
		// Start the node in the last interval after which the SP will be abandoned if SPs are not generated.
		if rnd == (consensusParams.StateProofMaxRecoveryIntervals)*consensusParams.StateProofInterval {
			t.Logf("at round %d starting node\n", rnd)
			dir, err = fixture.GetNodeDir("Node4")
			fixture.StartNode(dir)
		}

		// send a dummy payment transaction to create non-empty blocks
		paymentSender{
			from:   accountFetcher{nodeName: "Node0", accountNumber: 0},
			to:     accountFetcher{nodeName: "Node1", accountNumber: 0},
			amount: 1,
		}.sendPayment(r, &fixture, rnd)

		err = fixture.WaitForRound(rnd, timeoutUntilNextRound)
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
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, &fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams, expectedNumberOfStateProofs)
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
	consensusParams := getDefaultStateProofConsensusParams()
	// Stateproof can be generated even if not all nodes function correctly. e.g node can be offline
	// and stateproofs might still get generated. in order to make sure that all nodes work correctly
	// we want the network to fail in generating stateproof if one node is not working correctly.
	// For that we will increase the proven Weight to be close to 100%. However, this change might not be enough.
	// if the signed Weight and the Proven Weight are very close to each other the number of reveals in the state proof
	// will exceed the MAX_NUMBER_OF_REVEALS and proofs would not get generated
	// for that reason we need to the decrease the StateProofStrengthTarget creating a "weak cert"
	consensusParams.StateProofWeightThreshold = (1 << 32) * 90 / 100
	consensusParams.StateProofStrengthTarget = 4
	consensusParams.StateProofMaxRecoveryIntervals = 4
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))
	defer fixture.Shutdown()

	err := fixture.WaitForRound(1, timeoutUntilNextRound)
	r.NoError(err)

	dir, err := fixture.GetNodeDir("Node4")
	nc := nodecontrol.MakeNodeController(fixture.GetBinDir(), dir)
	nc.FullStop()

	var lastStateProofBlock bookkeeping.Block
	libgoal := fixture.LibGoalClient

	expectedNumberOfStateProofs := uint64(4)
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs
	for rnd := uint64(2); rnd <= consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1); rnd++ {
		if rnd == (consensusParams.StateProofMaxRecoveryIntervals+2)*consensusParams.StateProofInterval {
			t.Logf("at round %d starting node\n", rnd)
			dir, err = fixture.GetNodeDir("Node4")
			fixture.StartNode(dir)
		}

		// send a dummy payment transaction to create non-empty blocks
		paymentSender{
			from:   accountFetcher{nodeName: "Node0", accountNumber: 0},
			to:     accountFetcher{nodeName: "Node1", accountNumber: 0},
			amount: 1,
		}.sendPayment(r, &fixture, rnd)

		err = fixture.WaitForRound(rnd, timeoutUntilNextRound)
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

// In this test, we have five nodes, where we only need four to create a StateProof.
// After making the first Stateproof, we transfer three-quarters of the stake of the
// rich node to the poor node. For both cases, we assert different stakes, that is, to
// conclude whether the poor node is used to create the StateProof or the rich node.
func TestAttestorsChangeTest(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))

	consensusParams := getDefaultStateProofConsensusParams()
	// Stateproof can be generated even if not all nodes function correctly. e.g node can be offline
	// and stateproofs might still get generated. in order to make sure that all nodes work correctly
	// we want the network to fail in generating stateproof if one node is not working correctly.
	// For that we will increase the proven Weight to be close to 100%. However, this change might not be enough.
	// if the signed Weight and the Proven Weight are very close to each other the number of reveals in the state proof
	// will exceed the MAX_NUMBER_OF_REVEALS and proofs would not get generated
	// for that reason we need to the decrease the StateProofStrengthTarget creating a "weak cert"
	consensusParams.StateProofWeightThreshold = (1 << 32) * 90 / 100
	consensusParams.StateProofStrengthTarget = 4
	consensusParams.StateProofTopVoters = 4

	configurableConsensus := config.ConsensusProtocols{
		protocol.ConsensusVersion("test-fast-stateproofs"): consensusParams,
	}

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "RichAccountStateProof.json"))
	defer fixture.Shutdown()

	var lastStateProofBlock bookkeeping.Block
	var lastStateProofMessage stateproofmsg.Message
	libgoal := fixture.LibGoalClient

	expectedNumberOfStateProofs := uint64(4)
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs

	paymentMaker := paymentSender{
		from: accountFetcher{nodeName: "richNode", accountNumber: 0},
		to:   accountFetcher{nodeName: "poorNode", accountNumber: 0},
	}

	for rnd := uint64(1); rnd <= consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1); rnd++ {
		// Changing the amount to pay. This should transfer most of the money from the rich node to the poort node.
		if consensusParams.StateProofInterval*2 == rnd {
			balance := paymentMaker.from.getBalance(a, &fixture)
			// ensuring that before the test, the rich node (from) has a significantly larger balance.
			a.True(balance/2 > paymentMaker.to.getBalance(a, &fixture))

			paymentMaker.amount = balance * 3 / 4
			paymentMaker.sendPayment(a, &fixture, rnd)
		}

		// verifies that rich account transferred most of its money to the account that sits on poorNode.
		if consensusParams.StateProofInterval*3 == rnd {
			a.True(paymentMaker.to.getBalance(a, &fixture) > paymentMaker.from.getBalance(a, &fixture))
		}

		a.NoError(fixture.WaitForRound(rnd, timeoutUntilNextRound))
		blk, err := libgoal.BookkeepingBlock(rnd)
		a.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		if (rnd % consensusParams.StateProofInterval) == 0 {
			// Must have a merkle commitment for participants
			a.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			a.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight != basics.MicroAlgos{})

			stake := blk.BlockHeader.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight.ToUint64()

			// the main part of the test (computing the total stake of the nodes):
			sum := uint64(0)
			for i := 1; i <= 3; i++ {
				sum += accountFetcher{fmt.Sprintf("Node%d", i), 0}.getBalance(a, &fixture)
			}

			// including the stake of the rich node:
			if blk.Round() < basics.Round(consensusParams.StateProofInterval*3) {
				sum += accountFetcher{"richNode", 0}.getBalance(a, &fixture)
			} else { // including the stake of the poor node (which is different)
				sum += accountFetcher{"poorNode", 0}.getBalance(a, &fixture)
			}

			a.Equal(sum, stake)

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		} else {
			a.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight == basics.MicroAlgos{})
		}

		for lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound &&
			lastStateProofBlock.Round() != 0 {
			nextStateProofRound := uint64(lastStateProofBlock.Round()) + consensusParams.StateProofInterval

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(a, &fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams, expectedNumberOfStateProofs)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	a.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}
