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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	sp "github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const expectedNumberOfStateProofs = uint64(4)

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
	consensusParams.StateProofRecoveryInterval = 10
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
	for rnd := uint64(1); rnd <= consensusParams.StateProofInterval*(expectedNumberOfStateProofs+1); rnd++ {
		// send a dummy payment transaction.
		sendPayment(r, &fixture, rnd)

		err = fixture.WaitForRound(rnd, 30*time.Second)
		r.NoError(err)

		blk, err := libgoal.BookkeepingBlock(rnd)
		r.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		//t.Logf("Round %d, block %v\n", rnd, blk)

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
			stateProofMessage, nextStateProofBlock := verifyStateProofForRound(r, libgoal, restClient, nextStateProofRound, lastStateProofMessage, lastStateProofBlock, consensusParams)
			lastStateProofMessage = stateProofMessage
			lastStateProofBlock = nextStateProofBlock
		}
	}

	r.Equalf(consensusParams.StateProofInterval*expectedNumberOfStateProofs, uint64(lastStateProofBlock.Round()), "the expected last state proof block wasn't the one that was observed")
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

func verifyStateProofForRound(r *require.Assertions, libgoal libgoal.Client, restClient client.RestClient, nextStateProofRound uint64, prevStateProofMessage stateproofmsg.Message, lastStateProofBlock bookkeeping.Block, consensusParams config.ConsensusParams) (stateproofmsg.Message, bookkeeping.Block) {
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
