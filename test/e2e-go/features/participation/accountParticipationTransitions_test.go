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

package participation

// Tests in this file are focused on testing how a specific account uses and
// manages its participation keys. DevMode is used to make things more
// deterministic.

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

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
	txParams, err := client.SuggestedParams()
	require.NoError(t, err)
	sAccount := part.Address().String()
	sWH, err := client.GetUnencryptedWalletHandle()
	require.NoError(t, err)
	goOnlineTx, err := client.MakeUnsignedGoOnlineTx(sAccount, &part, txParams.LastRound+1, txParams.LastRound+1, txParams.Fee, [32]byte{})
	require.NoError(t, err)
	require.Equal(t, sAccount, goOnlineTx.Src().String())
	onlineTxID, err := client.SignAndBroadcastTransaction(sWH, nil, goOnlineTx)
	require.NoError(t, err)
	require.NotEmpty(t, onlineTxID)
	status, err := client.WaitForRound(txParams.LastRound)
	require.NoError(t, err)
	return status
}

func TestKeyRegistration(t *testing.T) {
	partitiontest.PartitionTest(t)

	if testing.Short() {
		t.Skip()
	}

	t.Parallel()

	// Start devmode network and initialize things for the test.
	var fixture fixtures.RestClientFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "DevModeOneWallet.json"))
	fixture.Start()
	sClient := fixture.GetLibGoalClientForNamedNode("Node")
	minTxnFee, _, err := fixture.MinFeeAndBalance(0)
	require.NoError(t, err)
	accountResponse, err := fixture.GetRichestAccount()
	require.NoError(t, err)
	sAccount := accountResponse.Address

	// Add an overlapping participation keys for the account on round 1 and 2
	last := uint64(6_000_000)
	numNew := 2
	for i := 0; i < numNew; i++ {
		response, part, err := installParticipationKey(t, sClient, sAccount, 0, last)
		require.NoError(t, err)
		require.NotNil(t, response)
		registerParticipationAndWait(t, sClient, part)
	}

	// Make sure the new keys are installed.
	keys, err := fixture.LibGoalClient.GetParticipationKeys()
	require.NoError(t, err)
	require.Len(t, keys, numNew+1)

	// Zip ahead MaxBalLookback.
	params, err := fixture.CurrentConsensusParams()
	require.NoError(t, err)
	lookback := params.MaxBalLookback
	for i := uint64(1); i < lookback; i++ {
		fixture.SendMoneyAndWait(2+i, 0, minTxnFee, sAccount, sAccount, "")
	}

	keys, err = fixture.LibGoalClient.GetParticipationKeys()
	require.Equal(t, *(keys[0].EffectiveFirstValid), uint64(1))
	require.Equal(t, *(keys[0].EffectiveLastValid), lookback)
	require.Equal(t, *(keys[0].LastBlockProposal), lookback)

	require.Equal(t, *(keys[1].EffectiveFirstValid), lookback+1)
	require.Equal(t, *(keys[1].EffectiveLastValid), lookback+1)
	require.Equal(t, *(keys[1].LastBlockProposal), lookback+1)

	require.Equal(t, *(keys[2].EffectiveFirstValid), lookback+2)
	require.Equal(t, *(keys[2].EffectiveLastValid), last)
	require.Equal(t, *(keys[2].LastBlockProposal), lookback+2)
}
