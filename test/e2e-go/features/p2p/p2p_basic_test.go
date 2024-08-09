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

package p2p

import (
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func testP2PWithConfig(t *testing.T, templateName string) *fixtures.RestClientFixture {
	r := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture

	// Make protocol faster for shorter tests
	consensus := make(config.ConsensusProtocols)
	fastProtocol := config.Consensus[protocol.ConsensusCurrentVersion]
	fastProtocol.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	fastProtocol.AgreementFilterTimeoutPeriod0 = 400 * time.Millisecond
	fastProtocol.AgreementFilterTimeout = 400 * time.Millisecond
	consensus[protocol.ConsensusCurrentVersion] = fastProtocol
	fixture.SetConsensus(consensus)

	fixture.Setup(t, filepath.Join("nettemplates", templateName))
	_, err := fixture.NC.AlgodClient()
	r.NoError(err)

	err = fixture.WaitForRound(10, 30*time.Second)
	r.NoError(err)

	return &fixture
}

func TestP2PTwoNodes(t *testing.T) {
	partitiontest.PartitionTest(t)
	fixture := testP2PWithConfig(t, "TwoNodes50EachP2P.json")
	defer fixture.Shutdown()

	// ensure transaction propagation on both directions
	pingClient := fixture.LibGoalClient
	pingAccountList, err := fixture.GetWalletsSortedByBalance()
	require.NoError(t, err)
	pingAccount := pingAccountList[0].Address

	pongClient := fixture.GetLibGoalClientForNamedNode("Node")
	pongAccounts, err := fixture.GetNodeWalletsSortedByBalance(pongClient)
	require.NoError(t, err)
	pongAccount := pongAccounts[0].Address

	pingBalance, err := pingClient.GetBalance(pingAccount)
	require.NoError(t, err)
	pongBalance, err := pingClient.GetBalance(pongAccount)
	require.NoError(t, err)

	require.Equal(t, pingBalance, pongBalance)

	expectedPingBalance := pingBalance
	expectedPongBalance := pongBalance

	minTxnFee, minAcctBalance, err := fixture.CurrentMinFeeAndBalance()
	require.NoError(t, err)

	transactionFee := minTxnFee + 5
	amountPongSendsPing := minAcctBalance
	amountPingSendsPong := minAcctBalance * 3 / 2

	pongTxidsToAddresses := make(map[string]string)
	pingTxidsToAddresses := make(map[string]string)

	randNote := func(tb testing.TB) []byte {
		b := make([]byte, 8)
		_, err := rand.Read(b)
		require.NoError(tb, err)
		return b
	}

	for i := 0; i < 5; i++ {
		pongTx, err := pongClient.SendPaymentFromUnencryptedWallet(pongAccount, pingAccount, transactionFee, amountPongSendsPing, randNote(t))
		pongTxidsToAddresses[pongTx.ID().String()] = pongAccount
		require.NoError(t, err)
		pingTx, err := pingClient.SendPaymentFromUnencryptedWallet(pingAccount, pongAccount, transactionFee, amountPingSendsPong, randNote(t))
		pingTxidsToAddresses[pingTx.ID().String()] = pingAccount
		require.NoError(t, err)
		expectedPingBalance = expectedPingBalance - transactionFee - amountPingSendsPong + amountPongSendsPing
		expectedPongBalance = expectedPongBalance - transactionFee - amountPongSendsPing + amountPingSendsPong
	}
	curStatus, _ := pongClient.Status()
	curRound := curStatus.LastRound

	fixture.AlgodClient = fixture.GetAlgodClientForController(fixture.GetNodeControllerForDataDir(pongClient.DataDir()))
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+uint64(5), pingTxidsToAddresses)
	require.True(t, confirmed, "failed to see confirmed ping transaction by round %v", curRound+uint64(5))
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+uint64(5), pongTxidsToAddresses)
	require.True(t, confirmed, "failed to see confirmed pong transaction by round %v", curRound+uint64(5))

	pingBalance, err = pongClient.GetBalance(pingAccount)
	require.NoError(t, err)
	pongBalance, err = pongClient.GetBalance(pongAccount)
	require.NoError(t, err)
	require.True(t, expectedPingBalance <= pingBalance, "ping balance is different than expected.")
	require.True(t, expectedPongBalance <= pongBalance, "pong balance is different than expected.")
}

func TestP2PFiveNodes(t *testing.T) {
	partitiontest.PartitionTest(t)
	fixture := testP2PWithConfig(t, "FiveNodesP2P.json")
	defer fixture.Shutdown()
}
