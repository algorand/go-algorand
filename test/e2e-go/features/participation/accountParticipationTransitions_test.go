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

	// Add an overlapping participation key for the account
	response, part, err := installParticipationKey(t, sClient, sAccount, 0, 6000000)
	require.NoError(t, err)
	require.NotNil(t, response)

	// Make sure the second set of keys has been installed.
	keys, err := fixture.LibGoalClient.GetParticipationKeys()
	require.NoError(t, err)
	require.Len(t, keys, 2)

	// Register the new key on round 1
	sWH, err := sClient.GetUnencryptedWalletHandle()
	require.NoError(t, err)
	goOnlineTx, err := sClient.MakeUnsignedGoOnlineTx(sAccount, &part, 1, 1, minTxnFee, [32]byte{})
	require.NoError(t, err)
	require.Equal(t, sAccount, goOnlineTx.Src().String())
	onlineTxID, err := sClient.SignAndBroadcastTransaction(sWH, nil, goOnlineTx)
	require.NoError(t, err)
	require.NotEmpty(t, onlineTxID)
	txn, err := fixture.WaitForConfirmedTxn(2, sAccount, onlineTxID)
	require.NoError(t, err)
	require.NotNil(t, txn)

	// Zip ahead MaxBalLookback for the next key to become valid.
	params, err := fixture.CurrentConsensusParams()
	require.NoError(t, err)
	for i := uint64(0); i < params.MaxBalLookback; i++ {
		fixture.SendMoneyAndWait(2 + i, 0, minTxnFee, sAccount, sAccount, "")
	}

	keys, err = fixture.LibGoalClient.GetParticipationKeys()
	require.Equal(t, keys[0].EffectiveFirstValid, 1)
	require.Equal(t, keys[0].EffectiveLastValid, 320)
	require.Equal(t, keys[0].LastBlockProposal, 320)
	require.Equal(t, keys[1].EffectiveFirstValid, 321)
	require.Equal(t, keys[1].EffectiveLastValid, 6000000)
	require.Equal(t, keys[1].LastBlockProposal, 321)
}
