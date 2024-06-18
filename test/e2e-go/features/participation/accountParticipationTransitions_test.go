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

package participation

// Tests in this file are focused on testing how a specific account uses and
// manages its participation keys. DevMode is used to make things more
// deterministic.

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/libgoal/participation"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// installParticipationKey generates a new key for a given account and installs it with the client.
func installParticipationKey(t *testing.T, client libgoal.Client, addr string, firstValid, lastValid uint64) (resp model.PostParticipationResponse, part account.Participation, err error) {
	// Install overlapping participation keys...
	installFunc := func(keyPath string) error {
		return errors.New("the install directory is provided, so keys should not be installed")
	}
	part, filePath, err := participation.GenParticipationKeysTo(addr, firstValid, lastValid, 100, t.TempDir(), installFunc)
	require.NoError(t, err)
	require.NotNil(t, filePath)
	require.Equal(t, addr, part.Parent.String())

	resp, err = client.AddParticipationKey(filePath)
	return
}

func registerParticipationAndWait(t *testing.T, client libgoal.Client, part account.Participation) model.NodeStatusResponse {
	txParams, err := client.SuggestedParams()
	require.NoError(t, err)
	sAccount := part.Address().String()
	sWH, err := client.GetUnencryptedWalletHandle()
	require.NoError(t, err)
	goOnlineTx, err := client.MakeRegistrationTransactionWithGenesisID(part, txParams.Fee, txParams.LastRound+1, txParams.LastRound+1, [32]byte{}, true)
	assert.NoError(t, err)
	require.Equal(t, sAccount, goOnlineTx.Src().String())
	onlineTxID, err := client.SignAndBroadcastTransaction(sWH, nil, goOnlineTx)
	require.NoError(t, err)
	require.NotEmpty(t, onlineTxID)
	status, err := client.WaitForRound(txParams.LastRound)
	require.NoError(t, err)
	return status
}

// TODO: figure out what's the purpose of this test and fix it
func TestKeyRegistration(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Skipf("Skipping flaky test. Re-enable with #3255")

	if testing.Short() {
		t.Skip()
	}

	checkKey := func(key model.ParticipationKey, firstValid, lastValid, lastProposal uint64, msg string) {
		require.NotNil(t, key.EffectiveFirstValid, fmt.Sprintf("%s.EffectiveFirstValid", msg))
		require.NotNil(t, key.EffectiveLastValid, fmt.Sprintf("%s.EffectiveLastValid", msg))
		require.NotNil(t, key.LastBlockProposal, fmt.Sprintf("%s.LastBlockProposal", msg))

		assert.Equal(t, int(*(key.EffectiveFirstValid)), int(firstValid), fmt.Sprintf("%s.EffectiveFirstValid", msg))
		assert.Equal(t, int(*(key.EffectiveLastValid)), int(lastValid), fmt.Sprintf("%s.EffectiveLastValid", msg))
		assert.Equal(t, int(*(key.LastBlockProposal)), int(lastProposal), fmt.Sprintf("%s.LastBlockProposal", msg))
	}

	// Start devmode network and initialize things for the test.
	var fixture fixtures.RestClientFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "DevModeOneWallet.json"))
	fixture.Start()
	defer fixture.Shutdown()
	sClient := fixture.GetLibGoalClientForNamedNode("Node")
	minTxnFee, _, err := fixture.MinFeeAndBalance(0)
	require.NoError(t, err)
	accountResponse, err := fixture.GetRichestAccount()
	require.NoError(t, err)
	sAccount := accountResponse.Address

	// Add an overlapping participation keys for the account on round 1 and 2
	last := uint64(3_000)
	numNew := 2
	for i := 0; i < numNew; i++ {
		response, part, err := installParticipationKey(t, sClient, sAccount, 0, last+uint64(i))
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

	// Wait until data has been persisted
	ready := false
	waitfor := time.After(1 * time.Minute)
	for !ready {
		select {
		case <-waitfor:
			ready = true
		default:
			keys, err = fixture.LibGoalClient.GetParticipationKeys()
			ready = (len(keys) >= 3) &&
				(keys[2].LastBlockProposal != nil) &&
				(keys[2].EffectiveFirstValid != nil) &&
				(keys[2].EffectiveLastValid != nil) &&
				(keys[1].LastBlockProposal != nil) &&
				(keys[1].EffectiveFirstValid != nil) &&
				(keys[1].EffectiveLastValid != nil) &&
				(keys[0].LastBlockProposal != nil) &&
				(keys[0].EffectiveFirstValid != nil) &&
				(keys[0].EffectiveLastValid != nil)
			if !ready {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	// Verify results, order may vary, key off of the last valid field
	require.Len(t, keys, 3)
	for _, k := range keys {
		switch k.Key.VoteLastValid {
		case 1_500:
			checkKey(k, 1, lookback, lookback, "keys[0]")
		case last:
			checkKey(k, lookback+1, lookback+1, lookback+1, "keys[1]")
		case last + 1:
			checkKey(k, lookback+2, last+1, lookback+2, "keys[2]")
		}
	}
}
