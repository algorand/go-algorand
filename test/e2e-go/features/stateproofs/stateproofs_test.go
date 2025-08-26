// Copyright (C) 2019-2025 Algorand, Inc.
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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	sp "github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/libgoal/participation"
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

func (a accountFetcher) goOffline(r *require.Assertions, f *fixtures.RestClientFixture, round basics.Round) {
	account0 := a.getAccount(r, f)

	minTxnFee, _, err := f.CurrentMinFeeAndBalance()
	r.NoError(err)

	client0 := f.GetLibGoalClientForNamedNode(a.nodeName)
	txn, err := client0.MakeUnsignedGoOfflineTx(account0, round, round+1000, minTxnFee, [32]byte{})
	r.NoError(err)
	wallet0, err := client0.GetUnencryptedWalletHandle()
	r.NoError(err)
	_, err = client0.SignAndBroadcastTransaction(wallet0, nil, txn)
	r.NoError(err)
}

type paymentSender struct {
	from   accountFetcher
	to     accountFetcher
	amount uint64
}

func (p paymentSender) sendPayment(a *require.Assertions, f *fixtures.RestClientFixture, round basics.Round) {
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
	if testing.Short() {
		fixture.Setup(t, filepath.Join("nettemplates", "StateProofSmall.json"))
	} else {
		fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))
	}
	defer fixture.Shutdown()

	verifyStateProofsCreation(t, &fixture, consensusParams)
}

func TestStateProofsMultiWallets(t *testing.T) {
	partitiontest.PartitionTest(t)

	if strings.ToUpper(os.Getenv("CIRCLECI")) == "TRUE" {
		t.Skip()
	}

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

	const expectedNumberOfStateProofs = 4
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs
	for rnd := basics.Round(1); rnd <= basics.Round(consensusParams.StateProofInterval)*(expectedNumberOfStateProofs+1); rnd++ {
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

		if (rnd % basics.Round(consensusParams.StateProofInterval)) == 0 {
			// Must have a merkle commitment for participants
			r.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			r.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight != basics.MicroAlgos{})

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		} else {
			r.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) == 0)
			r.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight == basics.MicroAlgos{})
		}

		for lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound &&
			lastStateProofBlock.Round() != 0 {
			nextStateProofRound := lastStateProofBlock.Round() + basics.Round(consensusParams.StateProofInterval)

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	r.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
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
	pNodes := 5
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))

	defer fixture.Shutdown()

	// Get node libgoal clients in order to update their participation keys
	libgoalNodeClients := make([]libgoal.Client, pNodes, pNodes)
	for i := 0; i < pNodes; i++ {
		nodeName := fmt.Sprintf("Node%d", i)
		c := fixture.GetLibGoalClientForNamedNode(nodeName)
		libgoalNodeClients[i] = c
	}

	// Get account address of each participating node
	accounts := make([]string, pNodes, pNodes)
	for i, c := range libgoalNodeClients {
		parts, err := c.GetParticipationKeys() // should have 1 participation per node
		r.NoError(err)
		accounts[i] = parts[0].Address
	}

	participations := make([]account.Participation, pNodes, pNodes)
	var lastStateProofBlock bookkeeping.Block
	var lastStateProofMessage stateproofmsg.Message
	libgoalClient := fixture.LibGoalClient

	const expectedNumberOfStateProofs = 8
	for rnd := basics.Round(1); rnd <= basics.Round(consensusParams.StateProofInterval)*(expectedNumberOfStateProofs+1); rnd++ {
		if rnd == basics.Round(consensusParams.StateProofInterval)*5 { // allow some buffer period before the voting keys are expired (for the keyreg to take effect)
			fmt.Println("at round.. installing", rnd)
			// Generate participation keys (for the same accounts)
			for i := 0; i < pNodes; i++ {
				// Overlapping stateproof keys (the key for round 0 is valid up to 256)
				_, part, err := installParticipationKey(t, libgoalNodeClients[i], accounts[i], 0, 400)
				r.NoError(err)
				participations[i] = part
			}
			// Register overlapping participation keys
			for i := 0; i < pNodes; i++ {
				registerParticipationAndWait(t, libgoalNodeClients[i], participations[i])
			}
		}

		// send a dummy payment transaction.
		paymentSender{
			from:   accountFetcher{nodeName: "Node0", accountNumber: 0},
			to:     accountFetcher{nodeName: "Node1", accountNumber: 0},
			amount: 1,
		}.sendPayment(r, &fixture, rnd)

		err := fixture.WaitForRound(rnd, timeoutUntilNextRound)
		r.NoError(err)

		blk, err := libgoalClient.BookkeepingBlock(rnd)
		r.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		if (rnd % basics.Round(consensusParams.StateProofInterval)) == 0 {
			// Must have a merkle commitment for participants
			r.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			r.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight != basics.MicroAlgos{})

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		}

		for lastStateProofBlock.Round() != 0 && lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound {
			nextStateProofRound := lastStateProofBlock.Round() + basics.Round(consensusParams.StateProofInterval)

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, &fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams)
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
	oldConsensus := config.SetConfigurableConsensusProtocols(configurableConsensus)
	defer config.SetConfigurableConsensusProtocols(oldConsensus)

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	if testing.Short() {
		fixture.Setup(t, filepath.Join("nettemplates", "StateProofSmall.json"))
	} else {
		fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))
	}
	defer fixture.Shutdown()

	libgoalClient := fixture.LibGoalClient

	var startRound = basics.Round(1)
	var nextStateProofRound = basics.Round(0)
	var firstStateProofRound = basics.Round(2 * consensusParams.StateProofInterval)

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

		nextStateProofRound = blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound
	}

	_, stateProofMessage := getStateProofByLastRound(r, &fixture, firstStateProofRound)
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
	consensusParams := config.Consensus[protocol.ConsensusFuture]

	consensusParams.StateProofTopVoters = 1024
	consensusParams.StateProofVotersLookback = 2
	consensusParams.StateProofWeightThreshold = (1 << 32) * 30 / 100
	consensusParams.StateProofStrengthTarget = 256
	consensusParams.StateProofMaxRecoveryIntervals = 6
	consensusParams.EnableStateProofKeyregCheck = true
	consensusParams.AgreementFilterTimeout = 1500 * time.Millisecond
	consensusParams.AgreementFilterTimeoutPeriod0 = 1500 * time.Millisecond

	if testing.Short() {
		consensusParams.StateProofInterval = 16
	} else {
		consensusParams.StateProofInterval = 32
	}

	return consensusParams
}

func getStateProofByLastRound(r *require.Assertions, fixture *fixtures.RestClientFixture, stateProofLatestRound basics.Round) (sp.StateProof, stateproofmsg.Message) {
	restClient, err := fixture.NC.AlgodClient()
	r.NoError(err)

	res, err := restClient.StateProofs(stateProofLatestRound)
	r.NoError(err)
	r.Equal(res.Message.LastAttestedRound, stateProofLatestRound)

	var stateProof sp.StateProof
	err = protocol.Decode(res.StateProof, &stateProof)
	r.NoError(err)

	msg := stateproofmsg.Message{
		BlockHeadersCommitment: res.Message.BlockHeadersCommitment,
		VotersCommitment:       res.Message.VotersCommitment,
		LnProvenWeight:         res.Message.LnProvenWeight,
		FirstAttestedRound:     res.Message.FirstAttestedRound,
		LastAttestedRound:      res.Message.LastAttestedRound,
	}
	return stateProof, msg
}

func verifyStateProofForRound(r *require.Assertions, fixture *fixtures.RestClientFixture, nextStateProofRound basics.Round, prevStateProofMessage stateproofmsg.Message, lastStateProofBlock bookkeeping.Block, consensusParams config.ConsensusParams) (stateproofmsg.Message, bookkeeping.Block) {
	stateProof, stateProofMessage := getStateProofByLastRound(r, fixture, nextStateProofRound)

	nextStateProofBlock, err := fixture.LibGoalClient.BookkeepingBlock(nextStateProofRound)

	r.NoError(err)

	if !prevStateProofMessage.MsgIsZero() {
		//if we have a previous stateproof message we can verify the current stateproof using data from it
		verifier := sp.MkVerifierWithLnProvenWeight(prevStateProofMessage.VotersCommitment, prevStateProofMessage.LnProvenWeight, consensusParams.StateProofStrengthTarget)
		err = verifier.Verify(nextStateProofBlock.Round(), stateProofMessage.Hash(), &stateProof)
		r.NoError(err)
	}
	var votersRoot = make([]byte, sp.HashSize)
	copy(votersRoot[:], lastStateProofBlock.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment)

	provenWeight, overflowed := basics.Muldiv(lastStateProofBlock.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight.Raw, uint64(consensusParams.StateProofWeightThreshold), 1<<32)
	r.False(overflowed)

	verifier, err := sp.MkVerifier(votersRoot, provenWeight, consensusParams.StateProofStrengthTarget)
	r.NoError(err)

	err = verifier.Verify(nextStateProofBlock.Round(), stateProofMessage.Hash(), &stateProof)
	r.NoError(err)
	return stateProofMessage, nextStateProofBlock
}

// TestStateProofRecoveryDuringRecoveryInterval simulates a situation where the stateproof chain is lagging after the main chain.
// If the missing data is being accepted before  StateProofMaxRecoveryIntervals * StateProofInterval rounds have passed, nodes should
// be able to produce stateproofs and continue as normal
func TestStateProofRecoveryDuringRecoveryPeriod(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}

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
	for rnd := basics.Round(2); rnd <= basics.Round(consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1)); rnd++ {
		// Start the node in the last interval after which the SP will be abandoned if SPs are not generated.
		if rnd == basics.Round((consensusParams.StateProofMaxRecoveryIntervals)*consensusParams.StateProofInterval) {
			t.Logf("at round %d starting node\n", rnd)
			dir, err = fixture.GetNodeDir("Node4")
			r.NoError(err)
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

		if (rnd % basics.Round(consensusParams.StateProofInterval)) == 0 {
			// Must have a merkle commitment for participants
			r.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			r.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight != basics.MicroAlgos{})

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
			nextStateProofRound := lastStateProofBlock.Round() + basics.Round(consensusParams.StateProofInterval)

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, &fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}
	r.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}

// TestStateProofRecovery test that the state proof chain can be recovered even after the StateProofMaxRecoveryIntervals has passed.
func TestStateProofRecovery(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}

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
	consensusParams.StateProofMaxRecoveryIntervals = 2
	consensusParams.StateProofUseTrackerVerification = true
	consensusParams.SeedLookback = 2
	consensusParams.SeedRefreshInterval = 2
	consensusParams.MaxBalLookback = 2 * consensusParams.SeedLookback * consensusParams.SeedRefreshInterval // 8
	consensusParams.MaxTxnLife = 13
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
	nc.FullStop()

	var lastStateProofBlock bookkeeping.Block
	libgoal := fixture.LibGoalClient

	var lastStateProofMessage stateproofmsg.Message

	const expectedNumberOfStateProofs = 7
	const numberOfGraceIntervals = 3
	rnd := basics.Round(2)
	for ; rnd <= basics.Round(consensusParams.StateProofInterval)*expectedNumberOfStateProofs; rnd++ {
		if rnd == basics.Round((consensusParams.StateProofMaxRecoveryIntervals+4)*consensusParams.StateProofInterval) {
			t.Logf("at round %d starting node\n", rnd)
			dir, err = fixture.GetNodeDir("Node4")
			r.NoError(err)
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

		if (rnd % basics.Round(consensusParams.StateProofInterval)) == 0 {
			// Must have a merkle commitment for participants
			r.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			r.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight != basics.MicroAlgos{})

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		}

		if lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound &&
			lastStateProofBlock.Round() != 0 {
			nextStateProofRound := lastStateProofBlock.Round() + basics.Round(consensusParams.StateProofInterval)

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, &fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	// at this point we expect the state proof chain to be completely caught up. However, In order to avoid flakiness on
	// heavily loaded machines, we would wait some extra round for the state proofs to catch up
	for ; rnd <= basics.Round(consensusParams.StateProofInterval)*(expectedNumberOfStateProofs+numberOfGraceIntervals); rnd++ {

		err = fixture.WaitForRound(rnd, timeoutUntilNextRound)
		r.NoError(err)

		blk, err := libgoal.BookkeepingBlock(rnd)
		r.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		if lastStateProofBlock.Round() == 0 {
			lastStateProofBlock = blk
		}

		if lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound &&
			lastStateProofBlock.Round() != 0 {
			nextStateProofRound := lastStateProofBlock.Round() + basics.Round(consensusParams.StateProofInterval)

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, &fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}

		if int(consensusParams.StateProofInterval*expectedNumberOfStateProofs) <= int(lastStateProofBlock.Round()) {
			return
		}
	}
	r.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}

// installParticipationKey generates a new key for a given account and installs it with the client.
func installParticipationKey(t *testing.T, client libgoal.Client, addr string, firstValid, lastValid basics.Round) (resp model.PostParticipationResponse, part account.Participation, err error) {
	dir, err := os.MkdirTemp("", "temporary_partkey_dir")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// Install overlapping participation keys...
	installFunc := func(keyPath string) error {
		return errors.New("the install directory is provided, so keys should not be installed")
	}
	part, filePath, err := participation.GenParticipationKeysTo(addr, firstValid, lastValid, 100, dir, installFunc)
	require.NoError(t, err)
	require.NotNil(t, filePath)
	require.Equal(t, addr, part.Parent.String())

	resp, err = client.AddParticipationKey(filePath)
	return
}

func registerParticipationAndWait(t *testing.T, client libgoal.Client, part account.Participation) model.NodeStatusResponse {
	currentRnd, err := client.CurrentRound()
	require.NoError(t, err)
	sAccount := part.Address().String()
	sWH, err := client.GetUnencryptedWalletHandle()
	require.NoError(t, err)
	goOnlineTx, err := client.MakeRegistrationTransactionWithGenesisID(part, 1000, currentRnd, part.LastValid, [32]byte{}, true)
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
func TestAttestorsChange(t *testing.T) {
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

	const expectedNumberOfStateProofs = 4
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs

	paymentMaker := paymentSender{
		from: accountFetcher{nodeName: "richNode", accountNumber: 0},
		to:   accountFetcher{nodeName: "poorNode", accountNumber: 0},
	}

	for rnd := basics.Round(1); rnd <= basics.Round(consensusParams.StateProofInterval)*(expectedNumberOfStateProofs+1); rnd++ {
		// Changing the amount to pay. This should transfer most of the money from the rich node to the poor node.
		if basics.Round(consensusParams.StateProofInterval)*2 == rnd {
			balance := paymentMaker.from.getBalance(a, &fixture)
			// ensuring that before the test, the rich node (from) has a significantly larger balance.
			a.True(balance/2 > paymentMaker.to.getBalance(a, &fixture))

			paymentMaker.amount = balance * 9 / 10
			paymentMaker.sendPayment(a, &fixture, rnd)
		}

		// verifies that rich account transferred most of its money to the account that sits on poorNode.
		if basics.Round(consensusParams.StateProofInterval)*3 == rnd {
			a.True(paymentMaker.to.getBalance(a, &fixture) > paymentMaker.from.getBalance(a, &fixture))
		}

		a.NoError(fixture.WaitForRound(rnd, timeoutUntilNextRound))

		blk, err := libgoal.BookkeepingBlock(rnd)
		a.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		if (rnd % basics.Round(consensusParams.StateProofInterval)) == 0 {
			// Must have a merkle commitment for participants
			a.True(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment) > 0)
			a.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight != basics.MicroAlgos{})

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		} else {
			a.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight == basics.MicroAlgos{})
		}

		for lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound &&
			lastStateProofBlock.Round() != 0 {
			nextStateProofRound := lastStateProofBlock.Round() + basics.Round(consensusParams.StateProofInterval)

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(a, &fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	a.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}

func TestTotalWeightChanges(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))

	consensusParams := getDefaultStateProofConsensusParams()

	consensusParams.StateProofWeightThreshold = (1 << 32) * 90 / 100
	consensusParams.StateProofStrengthTarget = 4
	consensusParams.StateProofTopVoters = 4

	configurableConsensus := config.ConsensusProtocols{
		protocol.ConsensusVersion("test-fast-stateproofs"): consensusParams,
	}

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	if testing.Short() {
		fixture.Setup(t, filepath.Join("nettemplates", "RichAccountStateProofSmall.json"))
	} else {
		fixture.Setup(t, filepath.Join("nettemplates", "RichAccountStateProof.json"))
	}
	defer fixture.Shutdown()

	var lastStateProofBlock bookkeeping.Block
	var lastStateProofMessage stateproofmsg.Message
	libgoal := fixture.LibGoalClient

	richNode := accountFetcher{nodeName: "richNode", accountNumber: 0}

	const expectedNumberOfStateProofs = 4
	// Loop through the rounds enough to check for expectedNumberOfStateProofs state proofs

	for rnd := basics.Round(1); rnd <= basics.Round(consensusParams.StateProofInterval)*(expectedNumberOfStateProofs+1); rnd++ {
		// Rich node goes offline
		if basics.Round(consensusParams.StateProofInterval*2-(consensusParams.StateProofInterval/2)) == rnd {
			// subtract 8 rounds since the total online stake is calculated prior to the actual state proof round (lookback)
			richNode.goOffline(a, &fixture, rnd)
		}

		if testing.Short() {
			a.NoError(fixture.WaitForRound(rnd, 30*time.Second))
		} else {
			a.NoError(fixture.WaitForRound(rnd, 120*time.Second))
		}
		blk, err := libgoal.BookkeepingBlock(rnd)
		a.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		if (rnd % basics.Round(consensusParams.StateProofInterval)) == 0 {
			// Must have a merkle commitment for participants
			a.Greater(len(blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment), 0)
			totalStake := blk.BlockHeader.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight.ToUint64()
			a.NotEqual(basics.MicroAlgos{}, totalStake)

			if rnd <= basics.Round(consensusParams.StateProofInterval) {
				a.Equal(uint64(10000000000000000), totalStake)
			} else { // richNode should be offline by now
				a.Greater(uint64(10000000000000000), totalStake)
			}

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		} else {
			a.True(blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight == basics.MicroAlgos{})
		}

		for lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound &&
			lastStateProofBlock.Round() != 0 {
			nextStateProofRound := lastStateProofBlock.Round() + basics.Round(consensusParams.StateProofInterval)

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())
			// Find the state proof transaction
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(a, &fixture, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	a.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}

// TestSPWithTXPoolFull makes sure a SP txn goes into the pool when the pool is full
func TestSPWithTXPoolFull(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	configurableConsensus := make(config.ConsensusProtocols)
	consensusParams := getDefaultStateProofConsensusParams()
	consensusParams.StateProofInterval = 4
	configurableConsensus[protocol.ConsensusFuture] = consensusParams

	fixture.SetConsensus(configurableConsensus)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))

	dir, err := fixture.GetNodeDir("Primary")
	a.NoError(err)

	cfg, err := config.LoadConfigFromDisk(dir)
	a.NoError(err)
	cfg.TxPoolSize = 0
	cfg.SaveToDisk(dir)

	dir, err = fixture.GetNodeDir("Node")
	a.NoError(err)
	cfg.SaveToDisk(dir)

	fixture.Start()
	defer fixture.Shutdown()

	relay := fixture.GetLibGoalClientForNamedNode("Primary")

	params, err := relay.SuggestedParams()
	require.NoError(t, err)

	var genesisHash crypto.Digest
	copy(genesisHash[:], params.GenesisHash)

	round := basics.Round(0)
	for round = range 20 {
		params, err = relay.SuggestedParams()
		require.NoError(t, err)

		round = params.LastRound
		err = fixture.WaitForRound(round+1, 6*time.Second)
		require.NoError(t, err)

		b, err := relay.BookkeepingBlock(round + 1)
		require.NoError(t, err)
		if len(b.Payset) == 0 {
			continue
		}
		require.Equal(t, protocol.StateProofTx, b.Payset[0].Txn.Type)
		require.EqualValues(t, 8, b.Payset[0].Txn.StateProofTxnFields.Message.LastAttestedRound)
		break
	}
	require.Less(t, round, basics.Round(20))
}

// TestAtMostOneSPFullPool tests that there is at most one SP txn is admitted to the pool per roound
// when the pool is full. Note that the test sets TxPoolSize to 0 to simulate a full pool, which
// guarantees that no more than 1 SP txn get into a block. In normal configuration, it is
// possible to have multiple SPs getting into the same block when the pool is full.
func TestAtMostOneSPFullPool(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	configurableConsensus := make(config.ConsensusProtocols)
	consensusParams := getDefaultStateProofConsensusParams()
	consensusParams.StateProofInterval = 4
	configurableConsensus[protocol.ConsensusFuture] = consensusParams

	fixture.SetConsensus(configurableConsensus)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "OneNodeFuture.json"))

	dir, err := fixture.GetNodeDir("Primary")
	a.NoError(err)

	cfg, err := config.LoadConfigFromDisk(dir)
	a.NoError(err)
	cfg.TxPoolSize = 0
	cfg.SaveToDisk(dir)

	fixture.Start()
	defer fixture.Shutdown()

	relay := fixture.GetLibGoalClientForNamedNode("Primary")

	params, err := relay.SuggestedParams()
	require.NoError(t, err)

	// Check that the first 2 stateproofs are added to the blockchain in different rounds
	round := basics.Round(0)
	expectedSPRound := basics.Round(consensusParams.StateProofInterval) * 2
	for round < basics.Round(consensusParams.StateProofInterval)*10 {
		round = params.LastRound

		err := fixture.WaitForRound(round+1, 6*time.Second)
		require.NoError(t, err)

		b, err := relay.BookkeepingBlock(round + 1)
		require.NoError(t, err)

		params, err = relay.SuggestedParams()
		require.NoError(t, err)
		if len(b.Payset) == 0 {
			continue
		}
		tid := 0
		// Find a SP transaction in the block. The SP should be for StateProofIntervalLatestRound expectedSPRound
		// Since the pool is full, only one additional SP transaction is allowed in. So only one SP can be added to be block
		// break after finding it, and look for the next one in a subsequent block
		// In case two SP transactions get into the same block, the following loop will not find the second one, and fail the test
		for ; tid < len(b.Payset); tid++ {
			if string(b.Payset[tid].Txn.Type) == string(protocol.StateProofTx) {
				require.Equal(t, protocol.StateProofTx, b.Payset[tid].Txn.Type)

				require.Equal(t, int(expectedSPRound), int(b.Payset[tid].Txn.StateProofTxnFields.Message.LastAttestedRound))

				expectedSPRound = expectedSPRound + basics.Round(consensusParams.StateProofInterval)
				break
			}
		}
		if expectedSPRound == basics.Round(consensusParams.StateProofInterval*4) {
			break
		}
	}
	// If waited till round 20 and did not yet get the stateproof with last round 12, fail the test
	require.Less(t, round, consensusParams.StateProofInterval*10)
}

type specialAddr string

func (a specialAddr) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.SpecialAddr, []byte(a)
}

// TestSPWithCounterReset tests if the state proof transaction is getting into the pool and eventually
// at most one SP is getting into the block when the transaction pool is full.
// Bad SP and payment transaction traffic is added to increase the odds of getting SP txn into the pool
// in the same round.
func TestAtMostOneSPFullPoolWithLoad(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	configurableConsensus := make(config.ConsensusProtocols)
	consensusParams := getDefaultStateProofConsensusParams()
	consensusParams.StateProofInterval = 4
	configurableConsensus[protocol.ConsensusFuture] = consensusParams

	fixture.SetConsensus(configurableConsensus)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "OneNodeFuture.json"))

	dir, err := fixture.GetNodeDir("Primary")
	a.NoError(err)

	cfg, err := config.LoadConfigFromDisk(dir)
	a.NoError(err)
	cfg.TxPoolSize = 0
	cfg.SaveToDisk(dir)

	fixture.Start()
	defer fixture.Shutdown()

	relay := fixture.GetLibGoalClientForNamedNode("Primary")

	params, err := relay.SuggestedParams()
	require.NoError(t, err)

	var genesisHash crypto.Digest
	copy(genesisHash[:], params.GenesisHash)

	wg := sync.WaitGroup{}
	var done uint32

	defer func() {
		atomic.StoreUint32(&done, uint32(1))
		wg.Wait()
	}()

	stxn := getWellformedSPTransaction(params.LastRound+1, genesisHash, consensusParams, t)

	// Send well formed but bad stateproof transactions from two goroutines
	for spSpam := 0; spSpam < 2; spSpam++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for atomic.LoadUint32(&done) != 1 {
				_, err := relay.BroadcastTransaction(stxn)
				// The pool is full, and only one SP transaction will be admitted in per round. Otherwise, pool is full error will be returned
				// However, if this is the lucky SP transaction to get into the pool, it will eventually be rejected by ValidateStateProof and a different
				// error will be returned
				require.Error(t, err)
				time.Sleep(25 * time.Millisecond)
			}
		}()
	}

	// Send payment transactions from two goroutines
	for txnSpam := 0; txnSpam < 2; txnSpam++ {
		wg.Add(1)
		go func(amt uint64) {
			defer wg.Done()
			cntr := uint64(1)
			params, err := relay.SuggestedParams()
			require.NoError(t, err)

			ps := paymentSender{
				from:   accountFetcher{nodeName: "Primary", accountNumber: 0},
				amount: amt,
			}
			account0 := ps.from.getAccount(a, &fixture)

			for atomic.LoadUint32(&done) != 1 {
				ps.amount = cntr
				cntr = cntr + 1
				// ignore the returned error (most of the time will be error)
				_, err := relay.SendPaymentFromUnencryptedWallet(account0, account0, params.Fee, ps.amount, []byte{byte(params.LastRound)})
				require.Error(t, err)
				require.Equal(t, "HTTP 400 Bad Request: TransactionPool.checkPendingQueueSize: transaction pool have reached capacity", err.Error())
				time.Sleep(25 * time.Millisecond)
			}
		}(uint64(txnSpam + 1))
	}

	// Check that the first 2 stateproofs are added to the blockchain
	round := basics.Round(0)
	expectedSPRound := consensusParams.StateProofInterval * 2
	for round < basics.Round(consensusParams.StateProofInterval)*10 {
		round = params.LastRound

		err := fixture.WaitForRound(round+1, 6*time.Second)
		require.NoError(t, err)

		b, err := relay.BookkeepingBlock(round + 1)
		require.NoError(t, err)

		params, err = relay.SuggestedParams()
		require.NoError(t, err)
		if len(b.Payset) == 0 {
			continue
		}
		tid := 0
		// Find a SP transaction in the block. The SP should be for StateProofIntervalLatestRound expectedSPRound
		// Since the pool is full, only one additional SP transaction is allowed in. So only one SP can be added to be block
		// break after finding it, and look for the next one in a subsequent block
		// In case two SP transactions get into the same block, the following loop will not find the second one, and fail the test
		for ; tid < len(b.Payset); tid++ {
			if string(b.Payset[tid].Txn.Type) == string(protocol.StateProofTx) {
				require.Equal(t, protocol.StateProofTx, b.Payset[tid].Txn.Type)

				require.Equal(t, int(expectedSPRound), int(b.Payset[tid].Txn.StateProofTxnFields.Message.LastAttestedRound))

				expectedSPRound = expectedSPRound + consensusParams.StateProofInterval
				break
			}
		}
		if expectedSPRound == consensusParams.StateProofInterval*4 {
			break
		}
	}
	// Do not check if the SPs were added to the block. TestAtMostOneSPFullPool checks it.
	// In some environments (ARM) the high load may prevent it.
}

func getWellformedSPTransaction(round basics.Round, genesisHash crypto.Digest, consensusParams config.ConsensusParams, t *testing.T) (stxn transactions.SignedTxn) {

	msg := stateproofmsg.Message{}
	proof := &sp.StateProof{}
	proto := consensusParams

	stxn.Txn.Type = protocol.StateProofTx
	stxn.Txn.Sender = transactions.StateProofSender
	stxn.Txn.FirstValid = basics.Round(round)
	stxn.Txn.LastValid = basics.Round(round + 1000)
	stxn.Txn.GenesisHash = genesisHash
	stxn.Txn.StateProofType = protocol.StateProofBasic
	stxn.Txn.StateProof = *proof
	stxn.Txn.Message = msg

	err := stxn.Txn.WellFormed(transactions.SpecialAddresses{}, proto)
	require.NoError(t, err)

	return stxn
}

func TestStateProofCheckTotalStake(t *testing.T) {
	partitiontest.PartitionTest(t)

	if strings.ToUpper(os.Getenv("CIRCLECI")) == "TRUE" {
		t.Skip()
	}

	defer fixtures.ShutdownSynchronizedTest(t)

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
	pNodes := 5
	const expectedNumberOfStateProofs = 4
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "StateProof.json"))

	defer fixture.Shutdown()

	// Get node libgoal clients in order to update their participation keys
	libgoalNodeClients := make([]libgoal.Client, pNodes, pNodes)
	accountsAddresses := make([]string, pNodes, pNodes)
	for i := 0; i < pNodes; i++ {
		nodeName := fmt.Sprintf("Node%d", i)
		libgoalNodeClients[i] = fixture.GetLibGoalClientForNamedNode(nodeName)
		parts, err := libgoalNodeClients[i].GetParticipationKeys()
		r.NoError(err)
		accountsAddresses[i] = parts[0].Address
	}

	participations := make([]account.Participation, pNodes, pNodes)
	var lastStateProofBlock bookkeeping.Block
	libgoalClient := fixture.LibGoalClient

	var totalSupplyAtRound [1000]model.SupplyResponse
	var accountSnapshotAtRound [1000][]model.Account

	for rnd := basics.Round(1); rnd <= basics.Round(consensusParams.StateProofInterval)*(expectedNumberOfStateProofs+1); rnd++ {
		if rnd == basics.Round(consensusParams.StateProofInterval+consensusParams.StateProofVotersLookback) { // here we register the keys of address 0 so it won't be able the sign a state proof (its stake would be removed for the total)
			_, part, err := installParticipationKey(t, libgoalNodeClients[0], accountsAddresses[0], 0, basics.Round(consensusParams.StateProofInterval*2-1))
			r.NoError(err)
			participations[0] = part
			registerParticipationAndWait(t, libgoalNodeClients[0], participations[0])
		}

		//send a dummy payment transaction.
		paymentSender{
			from:   accountFetcher{nodeName: "Node3", accountNumber: 0},
			to:     accountFetcher{nodeName: "Node4", accountNumber: 0},
			amount: 1,
		}.sendPayment(r, &fixture, rnd)

		err := fixture.WaitForRound(rnd, timeoutUntilNextRound)
		r.NoError(err)

		// this is the round in we take a snapshot of the account balances.
		// We would use this snapshot later on to compare the weights on the state proof, and to make sure that
		// the totalWeight commitment is correct
		if ((rnd + 2) % basics.Round(consensusParams.StateProofInterval)) == 0 {
			totalSupply, err := libgoalClient.LedgerSupply()
			r.NoError(err)

			r.Equal(rnd, totalSupply.CurrentRound, "could not capture total stake at the target round. The machine might be too slow for this test")
			totalSupplyAtRound[rnd] = totalSupply

			accountSnapshotAtRound[rnd] = make([]model.Account, pNodes, pNodes)
			for i := 0; i < pNodes; i++ {
				accountSnapshotAtRound[rnd][i], err = libgoalClient.AccountInformation(accountsAddresses[i], false)
				r.NoError(err)
				r.NotEqual(accountSnapshotAtRound[rnd][i].Amount, uint64(0))
				r.Equal(rnd, accountSnapshotAtRound[rnd][i].Round, "could not capture the account at the target round. The machine might be too slow for this test")
			}
		}

		blk, err := libgoalClient.BookkeepingBlock(rnd)
		r.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		if (rnd % basics.Round(consensusParams.StateProofInterval)) == 0 {
			if rnd >= basics.Round(consensusParams.StateProofInterval)*2 {
				// since account 0 would no longer be able to sign the state proof, its stake should
				// be removed from the total stake in the commitment
				total := totalSupplyAtRound[rnd-basics.Round(consensusParams.StateProofVotersLookback)].OnlineMoney
				total = total - accountSnapshotAtRound[rnd-basics.Round(consensusParams.StateProofVotersLookback)][0].Amount
				r.Equal(total, blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight.Raw)
			} else {
				r.Equal(totalSupplyAtRound[rnd-basics.Round(consensusParams.StateProofVotersLookback)].OnlineMoney, blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight.Raw)
			}

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastStateProofBlock.Round() == 0 {
				lastStateProofBlock = blk
			}
		}

		for lastStateProofBlock.Round() != 0 && lastStateProofBlock.Round()+basics.Round(consensusParams.StateProofInterval) < blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound {
			nextStateProofRound := lastStateProofBlock.Round() + basics.Round(consensusParams.StateProofInterval)

			t.Logf("found a state proof for round %d at round %d", nextStateProofRound, blk.Round())

			stateProof, stateProofMsg := getStateProofByLastRound(r, &fixture, nextStateProofRound)

			accountSnapshot := accountSnapshotAtRound[stateProofMsg.LastAttestedRound-basics.Round(consensusParams.StateProofInterval-consensusParams.StateProofVotersLookback)]

			// once the state proof is accepted we want to make sure that the weight
			for _, v := range stateProof.Reveals {
				found := false
				for i := 0; i < len(accountSnapshot); i++ {
					if bytes.Compare(v.Part.PK.Commitment[:], *accountSnapshot[i].Participation.StateProofKey) == 0 {
						r.Equal(v.Part.Weight, accountSnapshot[i].Amount)
						found = true
						break
					}
				}
				r.True(found)
			}
			nextStateProofBlock, err := fixture.LibGoalClient.BookkeepingBlock(nextStateProofRound)
			r.NoError(err)
			lastStateProofBlock = nextStateProofBlock
		}
	}

	r.Equalf(int(consensusParams.StateProofInterval*expectedNumberOfStateProofs), int(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
}
