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
// test-fast-upgrade-future
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
	currentProtocolParams.SupportRekeying = false

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
	smallLambdaMs := 500
	consensus := makeApplicationUpgradeConsensus(t)

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100SecondTestUnupgradedProtocol.json"))
	defer fixture.Shutdown()

	client := fixture.GetLibGoalClientForNamedNode("Node")
	accountList, err := fixture.GetNodeWalletsSortedByBalance(client.DataDir())
	require.NoError(t, err)

	creator := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	require.NoError(t, err)

	user, err := client.GenerateAddress(wh)
	require.NoError(t, err)

	fee := uint64(1000)

	round, err := client.CurrentRound()
	require.NoError(t, err)

	// Fund the manager, so it can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(creator, user, fee, 10000000000, nil)
	require.NoError(t, err)
	client.WaitForRound(round + 2)

	// There should be no apps to start with
	ad, err := client.AccountData(creator)
	require.NoError(t, err)
	require.Zero(t, len(ad.AppParams))

	ad, err = client.AccountData(user)
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
	clearstate, err := logic.AssembleString("#pragma version 2\nint 1")
	require.NoError(t, err)
	schema := basics.StateSchema{
		NumUint: 1,
	}

	// create the app
	tx, err := client.MakeUnsignedAppCreateTx(
		transactions.OptInOC, approval, clearstate, schema, schema, nil, nil, nil, nil,
	)
	require.NoError(t, err)
	tx, err = client.FillUnsignedTxTemplate(creator, 0, 0, fee, tx)
	require.NoError(t, err)
	signedTxn, err := client.SignTransactionWithWallet(wh, nil, tx)
	require.NoError(t, err)
	round, err = client.CurrentRound()
	require.NoError(t, err)

	_, err = client.BroadcastTransaction(signedTxn)
	require.Error(t, err)
	require.Contains(t, err.Error(), "application transaction not supported")

	curStatus, err := client.Status()
	require.NoError(t, err)
	initialStatus := curStatus

	startLoopTime := time.Now()

	// wait until the network upgrade : this can take a while.
	for curStatus.LastVersion == initialStatus.LastVersion {
		curStatus, err = client.Status()
		require.NoError(t, err)

		require.Less(t, int64(time.Now().Sub(startLoopTime)), int64(3*time.Minute))
		time.Sleep(time.Duration(smallLambdaMs) * time.Millisecond)
		round = curStatus.LastRound
	}

	// now, that we have upgraded to the new protocol which supports applications, try again.
	_, err = client.BroadcastTransaction(signedTxn)
	require.NoError(t, err)

	curStatus, err = client.Status()
	require.NoError(t, err)

	round = curStatus.LastRound

	client.WaitForRound(round + 2)
	pendingTx, err := client.GetPendingTransactions(1)
	require.NoError(t, err)
	require.Equal(t, uint64(0), pendingTx.TotalTxns)

	// check creator's balance record for the app entry and the state changes
	ad, err = client.AccountData(creator)
	require.NoError(t, err)
	require.Equal(t, 1, len(ad.AppParams))
	var appIdx basics.AppIndex
	var params basics.AppParams
	for i, p := range ad.AppParams {
		appIdx = i
		params = p
		break
	}
	require.Equal(t, approval, params.ApprovalProgram)
	require.Equal(t, clearstate, params.ClearStateProgram)
	require.Equal(t, schema, params.LocalStateSchema)
	require.Equal(t, schema, params.GlobalStateSchema)
	require.Equal(t, 1, len(params.GlobalState))
	value, ok := params.GlobalState["counter"]
	require.True(t, ok)
	require.Equal(t, uint64(1), value.Uint)

	require.Equal(t, 1, len(ad.AppLocalStates))
	state, ok := ad.AppLocalStates[appIdx]
	require.True(t, ok)
	require.Equal(t, schema, state.Schema)
	require.Equal(t, 1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	require.True(t, ok)
	require.Equal(t, uint64(1), value.Uint)

	// call the app
	tx, err = client.MakeUnsignedAppOptInTx(uint64(appIdx), nil, nil, nil, nil)
	require.NoError(t, err)
	tx, err = client.FillUnsignedTxTemplate(user, 0, 0, fee, tx)
	require.NoError(t, err)
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	require.NoError(t, err)
	round, err = client.CurrentRound()
	require.NoError(t, err)
	_, err = client.BroadcastTransaction(signedTxn)
	require.NoError(t, err)

	client.WaitForRound(round + 2)

	// check creator's balance record for the app entry and the state changes
	ad, err = client.AccountData(creator)
	require.NoError(t, err)
	require.Equal(t, 1, len(ad.AppParams))
	params, ok = ad.AppParams[appIdx]
	require.True(t, ok)
	require.Equal(t, approval, params.ApprovalProgram)
	require.Equal(t, clearstate, params.ClearStateProgram)
	require.Equal(t, schema, params.LocalStateSchema)
	require.Equal(t, schema, params.GlobalStateSchema)
	require.Equal(t, 1, len(params.GlobalState))
	value, ok = params.GlobalState["counter"]
	require.True(t, ok)
	require.Equal(t, uint64(2), value.Uint)

	require.Equal(t, 1, len(ad.AppLocalStates))
	state, ok = ad.AppLocalStates[appIdx]
	require.True(t, ok)
	require.Equal(t, schema, state.Schema)
	require.Equal(t, 1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	require.True(t, ok)
	require.Equal(t, uint64(1), value.Uint)

	require.Equal(t, uint64(2), ad.TotalAppSchema.NumUint)

	// check user's balance record for the app entry and the state changes
	ad, err = client.AccountData(user)
	require.NoError(t, err)
	require.Equal(t, 0, len(ad.AppParams))

	require.Equal(t, 1, len(ad.AppLocalStates))
	state, ok = ad.AppLocalStates[appIdx]
	require.True(t, ok)
	require.Equal(t, schema, state.Schema)
	require.Equal(t, 1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	require.True(t, ok)
	require.Equal(t, uint64(1), value.Uint)

	require.Equal(t, basics.MicroAlgos{Raw: 10000000000 - fee}, ad.MicroAlgos)

	app, err := client.ApplicationInformation(uint64(appIdx))
	require.NoError(t, err)
	require.Equal(t, uint64(appIdx), app.Id)
	require.Equal(t, creator, app.Params.Creator)
	return
}

// TestApplicationsUpgrade tests that we can safely upgrade from a version that doesn't support applications
// to a version that supports applications. It verify that prior to supporting applications, the node would not accept
// any application transaction and after the upgrade is complete, it would support that.
func TestApplicationsUpgradeOverGossip(t *testing.T) {
	smallLambdaMs := 500
	consensus := makeApplicationUpgradeConsensus(t)

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodes100SecondTestUnupgradedProtocol.json"))

	// for the primary node, we want to have a different consensus which always enables applications.
	primaryNodeUnupgradedProtocol := consensus[consensusTestFastUpgrade(protocol.ConsensusFuture)]
	primaryNodeUnupgradedProtocol.ApprovedUpgrades = make(map[protocol.ConsensusVersion]uint64)
	primaryNodeUnupgradedProtocol.ApprovedUpgrades[consensusTestFastUpgrade(protocol.ConsensusFuture)] = 0
	consensus[consensusTestUnupgradedProtocol] = primaryNodeUnupgradedProtocol

	client := fixture.GetLibGoalClientForNamedNode("Primary")
	secondary := fixture.GetLibGoalClientForNamedNode("Node")
	err := config.SaveConfigurableConsensus(client.DataDir(), consensus)
	require.NoError(t, err)

	fixture.Start()

	defer fixture.Shutdown()

	accountList, err := fixture.GetNodeWalletsSortedByBalance(client.DataDir())
	require.NoError(t, err)

	creator := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	require.NoError(t, err)

	user, err := client.GenerateAddress(wh)
	require.NoError(t, err)

	fee := uint64(1000)

	round, err := client.CurrentRound()
	require.NoError(t, err)

	// Fund the manager, so it can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(creator, user, fee, 10000000000, nil)
	require.NoError(t, err)
	client.WaitForRound(round + 2)

	round, err = client.CurrentRound()
	require.NoError(t, err)

	// There should be no apps to start with
	ad, err := client.AccountData(creator)
	require.NoError(t, err)
	require.Zero(t, len(ad.AppParams))

	ad, err = client.AccountData(user)
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
	clearstate, err := logic.AssembleString("#pragma version 2\nint 1")
	require.NoError(t, err)
	schema := basics.StateSchema{
		NumUint: 1,
	}

	// create the app
	tx, err := client.MakeUnsignedAppCreateTx(
		transactions.OptInOC, approval, clearstate, schema, schema, nil, nil, nil, nil,
	)
	require.NoError(t, err)
	tx, err = client.FillUnsignedTxTemplate(creator, round, round+primaryNodeUnupgradedProtocol.DefaultUpgradeWaitRounds, fee, tx)
	require.NoError(t, err)
	signedTxn, err := client.SignTransactionWithWallet(wh, nil, tx)
	require.NoError(t, err)
	round, err = client.CurrentRound()
	require.NoError(t, err)

	_, err = client.BroadcastTransaction(signedTxn)
	require.NoError(t, err)

	// this transaction is expect to reach the first node ( primary ), but to be rejected by the second node when transmitted over gossip.
	client.WaitForRound(round + 2)

	// check that the primary node still has this transaction in it's transaction pool.
	pendingTx, err := client.GetPendingTransactions(1)
	require.NoError(t, err)

	round, err = client.CurrentRound()
	require.NoError(t, err)
	if round > round+primaryNodeUnupgradedProtocol.DefaultUpgradeWaitRounds {
		t.Skip("Test platform is too slow for this test")
	}

	require.Equal(t, uint64(1), pendingTx.TotalTxns)

	// check that the secondary node doesn't have that transaction in it's transaction pool.
	pendingTx, err = secondary.GetPendingTransactions(1)
	require.NoError(t, err)
	require.Equal(t, uint64(0), pendingTx.TotalTxns)

	curStatus, err := client.Status()
	require.NoError(t, err)
	initialStatus := curStatus

	startLoopTime := time.Now()

	// wait until the network upgrade : this can take a while.
	for curStatus.LastVersion == initialStatus.LastVersion {
		curStatus, err = client.Status()
		require.NoError(t, err)

		require.Less(t, int64(time.Now().Sub(startLoopTime)), int64(3*time.Minute))
		time.Sleep(time.Duration(smallLambdaMs) * time.Millisecond)
		round = curStatus.LastRound
	}

	// now, that we have upgraded to the new protocol which supports applications, try again.
	tx, err = client.FillUnsignedTxTemplate(creator, round, round+100, fee, tx)
	require.NoError(t, err)
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	require.NoError(t, err)
	_, err = client.BroadcastTransaction(signedTxn)
	require.NoError(t, err)

	curStatus, err = client.Status()
	require.NoError(t, err)

	round = curStatus.LastRound

	client.WaitForRound(round + 2)
	pendingTx, err = client.GetPendingTransactions(1)
	require.NoError(t, err)
	require.Equal(t, uint64(0), pendingTx.TotalTxns)

	// check creator's balance record for the app entry and the state changes
	ad, err = client.AccountData(creator)
	require.NoError(t, err)
	require.Equal(t, 1, len(ad.AppParams))
	var appIdx basics.AppIndex
	var params basics.AppParams
	for i, p := range ad.AppParams {
		appIdx = i
		params = p
		break
	}
	require.Equal(t, approval, params.ApprovalProgram)
	require.Equal(t, clearstate, params.ClearStateProgram)
	require.Equal(t, schema, params.LocalStateSchema)
	require.Equal(t, schema, params.GlobalStateSchema)
	require.Equal(t, 1, len(params.GlobalState))
	value, ok := params.GlobalState["counter"]
	require.True(t, ok)
	require.Equal(t, uint64(1), value.Uint)

	require.Equal(t, 1, len(ad.AppLocalStates))
	state, ok := ad.AppLocalStates[appIdx]
	require.True(t, ok)
	require.Equal(t, schema, state.Schema)
	require.Equal(t, 1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	require.True(t, ok)
	require.Equal(t, uint64(1), value.Uint)

	// call the app
	tx, err = client.MakeUnsignedAppOptInTx(uint64(appIdx), nil, nil, nil, nil)
	require.NoError(t, err)
	tx, err = client.FillUnsignedTxTemplate(user, 0, 0, fee, tx)
	require.NoError(t, err)
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	require.NoError(t, err)
	round, err = client.CurrentRound()
	require.NoError(t, err)
	_, err = client.BroadcastTransaction(signedTxn)
	require.NoError(t, err)

	client.WaitForRound(round + 2)

	// check creator's balance record for the app entry and the state changes
	ad, err = client.AccountData(creator)
	require.NoError(t, err)
	require.Equal(t, 1, len(ad.AppParams))
	params, ok = ad.AppParams[appIdx]
	require.True(t, ok)
	require.Equal(t, approval, params.ApprovalProgram)
	require.Equal(t, clearstate, params.ClearStateProgram)
	require.Equal(t, schema, params.LocalStateSchema)
	require.Equal(t, schema, params.GlobalStateSchema)
	require.Equal(t, 1, len(params.GlobalState))
	value, ok = params.GlobalState["counter"]
	require.True(t, ok)
	require.Equal(t, uint64(2), value.Uint)

	require.Equal(t, 1, len(ad.AppLocalStates))
	state, ok = ad.AppLocalStates[appIdx]
	require.True(t, ok)
	require.Equal(t, schema, state.Schema)
	require.Equal(t, 1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	require.True(t, ok)
	require.Equal(t, uint64(1), value.Uint)

	require.Equal(t, uint64(2), ad.TotalAppSchema.NumUint)

	// check user's balance record for the app entry and the state changes
	ad, err = client.AccountData(user)
	require.NoError(t, err)
	require.Equal(t, 0, len(ad.AppParams))

	require.Equal(t, 1, len(ad.AppLocalStates))
	state, ok = ad.AppLocalStates[appIdx]
	require.True(t, ok)
	require.Equal(t, schema, state.Schema)
	require.Equal(t, 1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	require.True(t, ok)
	require.Equal(t, uint64(1), value.Uint)

	require.Equal(t, basics.MicroAlgos{Raw: 10000000000 - fee}, ad.MicroAlgos)

	app, err := client.ApplicationInformation(uint64(appIdx))
	require.NoError(t, err)
	require.Equal(t, uint64(appIdx), app.Id)
	require.Equal(t, creator, app.Params.Creator)
	return
}
