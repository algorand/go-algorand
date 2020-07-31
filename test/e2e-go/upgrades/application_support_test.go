// Copyright (C) 2019-2020 Algorand, Inc.
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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

// consensusTestUnupgradedProtocol is a version of ConsensusCurrentVersion
// that allows the control of the upgrade from consensusTestUnupgradedProtocol to
// consensusTestUnupgradedProtocol
const consensusTestUnupgradedProtocol = protocol.ConsensusVersion("test-unupgraded-protocol")

func makeApplicationUpgradeConsensus(t *testing.T) (appConsensus config.ConsensusProtocols) {
	appConsensus = generateFastUpgradeConsensus()
	// make sure that the "current" version does not support application and that the "future" version *does* support applications.
	currentProtocolParams, ok := appConsensus[consensusTestFastUpgrade(protocol.ConsensusCurrentVersion)]
	require.True(t, ok)
	futureProtocolParams, ok := appConsensus[consensusTestFastUpgrade(protocol.ConsensusFuture)]
	require.True(t, ok)

	// ensure it's disabled.
	currentProtocolParams.Application = false

	// verify that the future protocol supports applications.
	require.True(t, futureProtocolParams.Application)

	// add an upgrade path from current to future.
	currentProtocolParams.ApprovedUpgrades = make(map[protocol.ConsensusVersion]uint64)
	currentProtocolParams.ApprovedUpgrades[consensusTestFastUpgrade(protocol.ConsensusFuture)] = 0

	appConsensus[consensusTestUnupgradedProtocol] = currentProtocolParams
	appConsensus[consensusTestFastUpgrade(protocol.ConsensusFuture)] = futureProtocolParams

	return
}

// TestApplicationsUpgrade tests that we can safely upgrade from a version that doesn't support applications
// to a version that supports applications. It verify that prior to supporting applications, the node would not accept
// any application transaction and after the upgrade is complete, it would support that.
func TestApplicationsUpgradeOverREST(t *testing.T) {
	// set the small lambda to 500 for the duration of this test.
	roundTimeMs := 500
	lambda := os.Getenv("ALGOSMALLLAMBDAMSEC")
	os.Setenv("ALGOSMALLLAMBDAMSEC", fmt.Sprintf("%d", roundTimeMs))
	defer func() {
		if lambda == "" {
			os.Unsetenv("ALGOSMALLLAMBDAMSEC")
		} else {
			os.Setenv("ALGOSMALLLAMBDAMSEC", lambda)
		}
	}()

	consensus := makeApplicationUpgradeConsensus(t)

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100SecondTestUnupgradedProtocol.json"))
	defer fixture.Shutdown()

	secondaryClient := fixture.GetLibGoalClientForNamedNode("Node")
	accountList, err := fixture.GetNodeWalletsSortedByBalance(secondaryClient.DataDir())
	require.NoError(t, err)

	creator := accountList[0].Address
	wh, err := secondaryClient.GetUnencryptedWalletHandle()
	require.NoError(t, err)

	user, err := secondaryClient.GenerateAddress(wh)
	require.NoError(t, err)

	fee := uint64(1000)

	round, err := secondaryClient.CurrentRound()
	require.NoError(t, err)

	// Fund the manager, so it can issue transactions later on
	_, err = secondaryClient.SendPaymentFromUnencryptedWallet(creator, user, fee, 10000000000, nil)
	require.NoError(t, err)
	secondaryClient.WaitForRound(round + 2)

	// There should be no apps to start with
	ad, err := secondaryClient.AccountData(creator)
	require.NoError(t, err)
	require.Zero(t, len(ad.AppParams))

	ad, err = secondaryClient.AccountData(user)
	require.NoError(t, err)
	require.Zero(t, len(ad.AppParams))
	require.Equal(t, basics.MicroAlgos{Raw: 10000000000}, ad.MicroAlgos)

	counter := `#pragma version 2
// a simple global and local calls counter app
byte b64 Y291bnRlcg== // counter
dup
app_global_get
int 1
+
app_global_put  // update the counter
int 0
int 0
app_opted_in
bnz opted_in
err
opted_in:
int 0  // account idx for app_local_put
byte b64 Y291bnRlcg== // counter
int 0
byte b64 Y291bnRlcg==
app_local_get
int 1  // increment
+
app_local_put
int 1
`
	approval, err := logic.AssembleString(counter)
	require.NoError(t, err)
	clearstate, err := logic.AssembleString("int 1")
	require.NoError(t, err)
	schema := basics.StateSchema{
		NumUint: 1,
	}

	// create the app
	tx, err := secondaryClient.MakeUnsignedAppCreateTx(
		transactions.OptInOC, approval, clearstate, schema, schema, nil, nil, nil,
	)
	require.NoError(t, err)
	tx, err = secondaryClient.FillUnsignedTxTemplate(creator, 0, 0, fee, tx)
	require.NoError(t, err)
	signedTxn, err := secondaryClient.SignTransactionWithWallet(wh, nil, tx)
	require.NoError(t, err)
	round, err = secondaryClient.CurrentRound()
	require.NoError(t, err)

	_, err = secondaryClient.BroadcastTransaction(signedTxn)
	require.Error(t, err)
	require.Contains(t, err.Error(), "application transaction not supported")

	curStatus, err := secondaryClient.Status()
	require.NoError(t, err)
	initialStatus := curStatus

	startLoopTime := time.Now()

	// wait until the network upgrade : this can take a while.
	for curStatus.LastVersion == initialStatus.LastVersion {
		curStatus, err = secondaryClient.Status()
		require.NoError(t, err)

		require.Less(t, int64(time.Now().Sub(startLoopTime)), int64(3*time.Minute))
		time.Sleep(time.Duration(roundTimeMs) * time.Millisecond)
	}

	// now, that we have upgraded to the new protocol which supports applications, try again.
	_, err = secondaryClient.BroadcastTransaction(signedTxn)
	require.NoError(t, err)

	return
}
