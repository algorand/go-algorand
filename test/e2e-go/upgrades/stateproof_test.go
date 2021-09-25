// Copyright (C) 2019-2021 Algorand, Inc.
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

package upgrades

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/stretchr/testify/require"
)

func TestKeysWithoutStateProofKeyCannotRegister(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := getStateProofConcensus()

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesWithoutStateProofPartkeys.json"))
	defer fixture.Shutdown()
	lastValid := uint64(1000 * 5)

	a.NoError(registerKey(&fixture, a, lastValid, protocol.ConsensusV29))
	a.Error(registerKey(&fixture, a, lastValid+1, protocol.ConsensusFuture))

	runUntilProtocolUpgrades(a, &fixture)

	a.Error(registerKey(&fixture, a, lastValid+2, protocol.ConsensusV29))
	a.NoError(registerKey(&fixture, a, lastValid+3, protocol.ConsensusFuture))
}

func registerKey(fixture *fixtures.RestClientFixture, a *require.Assertions, lastValid uint64, ver protocol.ConsensusVersion) error {
	_, err := registerKeyInto("Node", fixture, a, lastValid, ver)
	return err
}

func registerKeyInto(nodeName string, fixture *fixtures.RestClientFixture, a *require.Assertions, lastValid uint64, ver protocol.ConsensusVersion) (string, error) {
	client := fixture.GetLibGoalClientForNamedNode(nodeName)
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)
	actList, err := client.ListAddresses(wh)
	a.NoError(err)
	addr := actList[0]

	pongBalance, err := client.GetBalance(addr)
	a.NoError(err)
	a.Greater(pongBalance, uint64(10000))

	partKey, _, err := client.GenParticipationKeys(addr, 1, lastValid, 1000)
	a.NoError(err)

	cparams := config.Consensus[ver]

	tx := partKey.GenerateRegistrationTransaction(
		basics.MicroAlgos{Raw: 1000},
		0,
		100,
		[32]byte{},
		cparams,
	)

	if cparams.SupportGenesisHash {
		prms, err := client.SuggestedParams()
		a.NoError(err)

		var genHash crypto.Digest
		copy(genHash[:], prms.GenesisHash)
		tx.GenesisHash = genHash
	}

	return client.SignAndBroadcastTransaction(wh, nil, tx)
}

func getStateProofConcensus() config.ConsensusProtocols {
	consensus := generateFastUpgradeConsensus()

	// TODO: set inside concensus file!
	consensus[consensusTestFastUpgrade(protocol.ConsensusV29)].
		ApprovedUpgrades[consensusTestFastUpgrade(protocol.ConsensusFuture)] = 0
	return consensus
}

//TODO: copied code from other test: onlineOfflineParticipation_test.go.
//  consider how to avoid duplication
func waitForAccountToProposeBlock(a *require.Assertions, fixture *fixtures.RestClientFixture, account string, window int) bool {
	client := fixture.AlgodClient

	curStatus, err := client.Status()
	a.NoError(err)
	curRound := curStatus.LastRound

	// the below window controls the likelihood a block will be proposed by the account under test
	// since block proposer selection is probabilistic, it is not guaranteed that the account will be chosen
	// it is a trade-off between test flakiness and test duration
	for window > 0 {
		window--
		curRound++
		err := fixture.WaitForRoundWithTimeout(curRound)
		a.NoErrorf(err, "fixture failed waiting for round %d", curRound)

		// See if account was participating by looking at block proposers
		blockWasProposed := fixture.VerifyBlockProposed(account, 1)
		if blockWasProposed {
			return blockWasProposed
		}
	}
	return false
}

// This test starts with participation keys in Version29, then attempts to let the richest user participate even after
//  consensus upgrade.
func TestParticipationWithoutStateProofKeys(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := getStateProofConcensus()

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesWithoutStateProofPartkeys.json"))
	defer fixture.Shutdown()
	// Want someone to start with a key to participate with...

	act, err := fixture.GetRichestAccount()
	a.NoError(err)

	var address = act.Address

	runUntilProtocolUpgrades(a, &fixture)

	a.NotEmpty(address)

	proposalWindow := 50 // giving 50 rounds to participate, should be able to participate every second round.
	blockWasProposedByPartkeyOnlyAccountRecently := waitForAccountToProposeBlock(a, &fixture, address, proposalWindow)
	a.True(blockWasProposedByPartkeyOnlyAccountRecently, "partkey-only account should be proposing blocks")
}

func TestLargeKeyRegistration(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := getStateProofConcensus()

	tmp := config.Consensus[protocol.ConsensusFuture]
	newVer := config.Consensus[protocol.ConsensusFuture]
	newVer.CompactCertRounds = 64
	config.Consensus[protocol.ConsensusFuture] = newVer
	defer func() { config.Consensus[protocol.ConsensusFuture] = tmp }()

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesWithoutStateProofPartkeys.json"))
	defer fixture.Shutdown()

	runUntilProtocolUpgrades(a, &fixture)

	txid, err := registerKeyInto("Node", &fixture, a, 300000, protocol.ConsensusFuture)
	a.NoError(err)

	client := fixture.LibGoalClient

	for {
		// Check if we know about the transaction yet
		txn, err := client.PendingTransactionInformation(txid)
		a.NoError(err)

		if txn.ConfirmedRound > 0 {
			break
		}

		a.Empty(txn.PoolError)
	}
}

func TestCompactCertificatesAreCreatedAfterVersionUpgrade(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := getStateProofConcensus()
	verName := consensusTestFastUpgrade(protocol.ConsensusFuture)

	consensusParams := consensus[verName]

	// params taken from compactCert e2e test.
	consensusParams.CompactCertRounds = 16
	consensusParams.CompactCertTopVoters = 1024
	consensusParams.CompactCertVotersLookback = 2
	consensusParams.CompactCertWeightThreshold = (1 << 32) * 30 / 100
	consensusParams.CompactCertSecKQ = 128
	consensus[verName] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "UpgradeIntoCompactCert.json"))
	defer fixture.Shutdown()

	runUntilProtocolUpgrades(a, &fixture)
	// inspect whether there are, or not... compact certificates..

	node0Client := fixture.GetLibGoalClientForNamedNode("Primary")
	node0Wallet, err := node0Client.GetUnencryptedWalletHandle()
	a.NoError(err)
	node0AccountList, err := node0Client.ListAddresses(node0Wallet)
	a.NoError(err)
	node0Account := node0AccountList[0]

	node1Client := fixture.GetLibGoalClientForNamedNode("Node")
	node1Wallet, err := node1Client.GetUnencryptedWalletHandle()
	a.NoError(err)
	node1AccountList, err := node1Client.ListAddresses(node1Wallet)
	a.NoError(err)
	node1Account := node1AccountList[0]

	var lastCertBlock v1.Block
	libgoal := fixture.LibGoalClient
	for rnd := uint64(1); rnd <= consensusParams.CompactCertRounds*3; rnd++ {
		// send a dummy payment transaction.
		minTxnFee, _, err := fixture.CurrentMinFeeAndBalance()
		a.NoError(err)

		_, err = node0Client.SendPaymentFromUnencryptedWallet(node0Account, node1Account, minTxnFee, rnd, nil)
		a.NoError(err)

		a.NoError(fixture.WaitForRound(rnd, 30*time.Second))

		blk, err := libgoal.Block(rnd)
		a.NoErrorf(err, "failed to retrieve block from algod on round %d", rnd)

		t.Logf("Round %d, block %v\n", rnd, blk)

		if (rnd % consensusParams.CompactCertRounds) == 0 {
			// Must have a merkle commitment for participants
			a.True(len(blk.CompactCertVoters) > 0)
			a.True(blk.CompactCertVotersTotal != 0)

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastCertBlock.Round == 0 {
				lastCertBlock = blk
			}
		}
	}
}
