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
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// consensusTestUnupgradedProtocol is a version of ConsensusCurrentVersion
// that allows the control of the upgrade from consensusTestUnupgradedProtocol to
// test-fast-upgrade-future
const consensusTestUnupgradedProtocol = protocol.ConsensusVersion("test-unupgraded-protocol")

// given that consensus version are constant and only growing forward, we can safely refer to them here:
const lastProtocolBeforeApplicationSupport = protocol.ConsensusV23
const firstProtocolWithApplicationSupport = protocol.ConsensusV24

func makeApplicationUpgradeConsensus(t *testing.T) (appConsensus config.ConsensusProtocols) {
	a := require.New(fixtures.SynchronizedTest(t))
	appConsensus = generateFastUpgradeConsensus()
	// make sure that the "current" version does not support application and that the "future" version *does* support applications.
	currentProtocolParams, ok := appConsensus[consensusTestFastUpgrade(lastProtocolBeforeApplicationSupport)]
	a.True(ok)
	futureProtocolParams, ok := appConsensus[consensusTestFastUpgrade(firstProtocolWithApplicationSupport)]
	a.True(ok)

	// ensure it's disabled.
	a.False(currentProtocolParams.Application)
	a.False(currentProtocolParams.SupportRekeying)

	// verify that the future protocol supports applications.
	a.True(futureProtocolParams.Application)

	// add an upgrade path from current to future.
	currentProtocolParams.ApprovedUpgrades = make(map[protocol.ConsensusVersion]uint64)
	currentProtocolParams.ApprovedUpgrades[consensusTestFastUpgrade(firstProtocolWithApplicationSupport)] = 0

	appConsensus[consensusTestUnupgradedProtocol] = currentProtocolParams
	appConsensus[consensusTestFastUpgrade(firstProtocolWithApplicationSupport)] = futureProtocolParams

	return
}

// TestApplicationsUpgrade tests that we can safely upgrade from a version that doesn't support applications
// to a version that supports applications. It verify that prior to supporting applications, the node would not accept
// any application transaction and after the upgrade is complete, it would support that.
func TestApplicationsUpgradeOverREST(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	smallLambdaMs := 500
	consensus := makeApplicationUpgradeConsensus(t)

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes100SecondTestUnupgradedProtocol.json"))
	defer fixture.Shutdown()

	a := require.New(fixtures.SynchronizedTest(t))

	client := fixture.GetLibGoalClientForNamedNode("Node")
	accountList, err := fixture.GetNodeWalletsSortedByBalance(client)
	a.NoError(err)

	creator := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	user, err := client.GenerateAddress(wh)
	a.NoError(err)

	fee := uint64(1000)

	round, err := client.CurrentRound()
	a.NoError(err)

	// Fund the manager, so it can issue transactions later on
	tx0, err := client.SendPaymentFromUnencryptedWallet(creator, user, fee, 10000000000, nil)
	a.NoError(err)
	isCommitted := fixture.WaitForTxnConfirmation(round+10, tx0.ID().String())
	a.True(isCommitted)

	// There should be no apps to start with
	ad, err := client.AccountData(creator)
	a.NoError(err)
	a.Zero(len(ad.AppParams))

	ad, err = client.AccountData(user)
	a.NoError(err)
	a.Zero(len(ad.AppParams))
	a.Equal(basics.MicroAlgos{Raw: 10000000000}, ad.MicroAlgos)

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
	approvalOps, err := logic.AssembleString(counter)
	a.NoError(err)
	clearstateOps, err := logic.AssembleString("#pragma version 2\nint 1")
	a.NoError(err)
	schema := basics.StateSchema{
		NumUint: 1,
	}

	// create the app
	tx, err := client.MakeUnsignedAppCreateTx(
		transactions.OptInOC, approvalOps.Program, clearstateOps.Program, schema, schema, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(creator, 0, 0, fee, tx)
	a.NoError(err)
	signedTxn, err := client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)

	successfullBroadcastCount := 0
	_, err = client.BroadcastTransaction(signedTxn)
	if err != nil {
		a.Contains(err.Error(), "application transaction not supported")
	} else {
		// if we had no error it must mean that we've upgraded already. Verify that.
		curStatus, err := client.Status()
		a.NoError(err)
		require.NotEqual(t, consensusTestUnupgradedProtocol, protocol.ConsensusVersion(curStatus.LastVersion))
		successfullBroadcastCount++
	}

	curStatus, err := client.Status()
	a.NoError(err)

	startLoopTime := time.Now()

	// wait until the network upgrade : this can take a while.
	for protocol.ConsensusVersion(curStatus.LastVersion) == consensusTestUnupgradedProtocol {
		curStatus, err = client.Status()
		a.NoError(err)

		a.Less(int64(time.Since(startLoopTime)), int64(3*time.Minute))
		time.Sleep(time.Duration(smallLambdaMs) * time.Millisecond)
	}

	// make a change to the node field to ensure we're not broadcasting the same transaction as we tried before.
	tx.Note = []byte{1, 2, 3}
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)

	// now, that we have upgraded to the new protocol which supports applications, try again.
	_, err = client.BroadcastTransaction(signedTxn)
	a.NoError(err)
	successfullBroadcastCount++

	curStatus, err = client.Status()
	a.NoError(err)

	round = curStatus.LastRound

	client.WaitForRound(round + 2)
	pendingTx, err := client.GetPendingTransactions(1)
	a.NoError(err)
	a.Zero(pendingTx.TotalTransactions)

	// check creator's balance record for the app entry and the state changes
	ad, err = client.AccountData(creator)
	a.NoError(err)
	a.Equal(successfullBroadcastCount, len(ad.AppParams))
	var appIdx basics.AppIndex
	var params basics.AppParams
	for i, p := range ad.AppParams {
		appIdx = i
		params = p
		break
	}
	a.Equal(approvalOps.Program, params.ApprovalProgram)
	a.Equal(clearstateOps.Program, params.ClearStateProgram)
	a.Equal(schema, params.LocalStateSchema)
	a.Equal(schema, params.GlobalStateSchema)
	a.Equal(1, len(params.GlobalState))
	value, ok := params.GlobalState["counter"]
	a.True(ok)
	a.Equal(uint64(1), value.Uint)

	a.Equal(successfullBroadcastCount, len(ad.AppLocalStates))
	state, ok := ad.AppLocalStates[appIdx]
	a.True(ok)
	a.Equal(schema, state.Schema)
	a.Equal(1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	a.True(ok)
	a.Equal(uint64(1), value.Uint)

	// call the app
	tx, err = client.MakeUnsignedAppOptInTx(appIdx, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(user, 0, 0, fee, tx)
	a.NoError(err)
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	round, err = client.CurrentRound()
	a.NoError(err)
	txid, err := client.BroadcastTransaction(signedTxn)
	a.NoError(err)

	client.WaitForConfirmedTxn(round+10, txid)

	// check creator's balance record for the app entry and the state changes
	ad, err = client.AccountData(creator)
	a.NoError(err)
	a.Equal(successfullBroadcastCount, len(ad.AppParams))
	params, ok = ad.AppParams[appIdx]
	a.True(ok)
	a.Equal(approvalOps.Program, params.ApprovalProgram)
	a.Equal(clearstateOps.Program, params.ClearStateProgram)
	a.Equal(schema, params.LocalStateSchema)
	a.Equal(schema, params.GlobalStateSchema)
	a.Equal(1, len(params.GlobalState))
	value, ok = params.GlobalState["counter"]
	a.True(ok)
	a.Equal(uint64(2), value.Uint)

	a.Equal(successfullBroadcastCount, len(ad.AppLocalStates))
	state, ok = ad.AppLocalStates[appIdx]
	a.True(ok)
	a.Equal(schema, state.Schema)
	a.Equal(1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	a.True(ok)
	a.Equal(uint64(1), value.Uint)

	a.Equal(uint64(2*successfullBroadcastCount), ad.TotalAppSchema.NumUint)

	// check user's balance record for the app entry and the state changes
	ad, err = client.AccountData(user)
	a.NoError(err)
	a.Equal(0, len(ad.AppParams))

	a.Equal(1, len(ad.AppLocalStates))
	state, ok = ad.AppLocalStates[appIdx]
	a.True(ok)
	a.Equal(schema, state.Schema)
	a.Equal(1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	a.True(ok)
	a.Equal(uint64(1), value.Uint)

	a.Equal(basics.MicroAlgos{Raw: 10000000000 - fee}, ad.MicroAlgos)

	app, err := client.ApplicationInformation(appIdx)
	a.NoError(err)
	a.Equal(appIdx, app.Id)
	a.Equal(creator, app.Params.Creator)
}

// TestApplicationsUpgrade tests that we can safely upgrade from a version that doesn't support applications
// to a version that supports applications. It verify that prior to supporting applications, the node would not accept
// any application transaction and after the upgrade is complete, it would support that.
func TestApplicationsUpgradeOverGossip(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	smallLambdaMs := 500
	consensus := makeApplicationUpgradeConsensus(t)

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodes100SecondTestUnupgradedProtocol.json"))

	// for the primary node, we want to have a different consensus which always enables applications.
	primaryNodeUnupgradedProtocol := consensus[consensusTestFastUpgrade(firstProtocolWithApplicationSupport)]
	primaryNodeUnupgradedProtocol.ApprovedUpgrades = make(map[protocol.ConsensusVersion]uint64)
	primaryNodeUnupgradedProtocol.ApprovedUpgrades[consensusTestFastUpgrade(firstProtocolWithApplicationSupport)] = 0
	consensus[consensusTestUnupgradedProtocol] = primaryNodeUnupgradedProtocol

	client := fixture.GetLibGoalClientForNamedNode("Primary")
	secondary := fixture.GetLibGoalClientForNamedNode("Node")
	err := config.SaveConfigurableConsensus(client.DataDir(), consensus)
	a.NoError(err)

	fixture.Start()

	defer fixture.Shutdown()

	accountList, err := fixture.GetNodeWalletsSortedByBalance(client)
	a.NoError(err)

	creator := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	user, err := client.GenerateAddress(wh)
	a.NoError(err)

	fee := uint64(1000)

	round, err := client.CurrentRound()
	a.NoError(err)

	// Fund the manager, so it can issue transactions later on
	tx0, err := client.SendPaymentFromUnencryptedWallet(creator, user, fee, 10000000000, nil)
	a.NoError(err)
	isCommitted := fixture.WaitForTxnConfirmation(round+10, tx0.ID().String())
	a.True(isCommitted)

	round, err = client.CurrentRound()
	a.NoError(err)

	// There should be no apps to start with
	ad, err := client.AccountData(creator)
	a.NoError(err)
	a.Zero(len(ad.AppParams))

	ad, err = client.AccountData(user)
	a.NoError(err)
	a.Zero(len(ad.AppParams))
	a.Equal(basics.MicroAlgos{Raw: 10000000000}, ad.MicroAlgos)

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
	approvalOps, err := logic.AssembleString(counter)
	a.NoError(err)
	clearstateOps, err := logic.AssembleString("#pragma version 2\nint 1")
	a.NoError(err)
	schema := basics.StateSchema{
		NumUint: 1,
	}

	// create the app
	tx, err := client.MakeUnsignedAppCreateTx(
		transactions.OptInOC, approvalOps.Program, clearstateOps.Program, schema, schema, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(creator, round, round+basics.Round(primaryNodeUnupgradedProtocol.DefaultUpgradeWaitRounds), fee, tx)
	a.NoError(err)
	signedTxn, err := client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	round, err = client.CurrentRound()
	a.NoError(err)

	_, err = client.BroadcastTransaction(signedTxn)
	a.NoError(err)

	// this transaction is expect to reach the first node ( primary ), but to be rejected by the second node when transmitted over gossip.
	client.WaitForRound(round + 2)

	// check that the primary node still has this transaction in it's transaction pool.
	pendingTx, err := client.GetPendingTransactions(1)
	a.NoError(err)

	round, err = client.CurrentRound()
	a.NoError(err)
	if round > round+basics.Round(primaryNodeUnupgradedProtocol.DefaultUpgradeWaitRounds) {
		t.Skip("Test platform is too slow for this test")
	}

	a.Equal(1, pendingTx.TotalTransactions)

	// check that the secondary node doesn't have that transaction in it's transaction pool.
	pendingTx, err = secondary.GetPendingTransactions(1)
	a.NoError(err)
	a.Zero(pendingTx.TotalTransactions)

	curStatus, err := client.Status()
	a.NoError(err)
	initialStatus := curStatus

	startLoopTime := time.Now()

	// wait until the network upgrade : this can take a while.
	for curStatus.LastVersion == initialStatus.LastVersion {
		curStatus, err = client.Status()
		a.NoError(err)

		a.Less(int64(time.Since(startLoopTime)), int64(3*time.Minute))
		time.Sleep(time.Duration(smallLambdaMs) * time.Millisecond)
		round = curStatus.LastRound
	}

	// now, that we have upgraded to the new protocol which supports applications, try again.
	tx, err = client.FillUnsignedTxTemplate(creator, round, round+100, fee, tx)
	a.NoError(err)
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	txid, err := client.BroadcastTransaction(signedTxn)
	a.NoError(err)

	// Try polling 10 rounds to ensure txn is committed.
	round, err = client.CurrentRound()
	a.NoError(err)
	isCommitted = fixture.WaitForTxnConfirmation(round+10, txid)
	a.True(isCommitted)

	// check creator's balance record for the app entry and the state changes
	ad, err = client.AccountData(creator)
	a.NoError(err)
	a.Equal(1, len(ad.AppParams))
	var appIdx basics.AppIndex
	var params basics.AppParams
	for i, p := range ad.AppParams {
		appIdx = i
		params = p
		break
	}
	a.Equal(approvalOps.Program, params.ApprovalProgram)
	a.Equal(clearstateOps.Program, params.ClearStateProgram)
	a.Equal(schema, params.LocalStateSchema)
	a.Equal(schema, params.GlobalStateSchema)
	a.Equal(1, len(params.GlobalState))
	value, ok := params.GlobalState["counter"]
	a.True(ok)
	a.Equal(uint64(1), value.Uint)

	a.Equal(1, len(ad.AppLocalStates))
	state, ok := ad.AppLocalStates[appIdx]
	a.True(ok)
	a.Equal(schema, state.Schema)
	a.Equal(1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	a.True(ok)
	a.Equal(uint64(1), value.Uint)

	// call the app
	tx, err = client.MakeUnsignedAppOptInTx(appIdx, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(user, 0, 0, fee, tx)
	a.NoError(err)
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	round, err = client.CurrentRound()
	a.NoError(err)
	_, err = client.BroadcastTransaction(signedTxn)
	a.NoError(err)

	client.WaitForRound(round + 2)

	// check creator's balance record for the app entry and the state changes
	ad, err = client.AccountData(creator)
	a.NoError(err)
	a.Equal(1, len(ad.AppParams))
	params, ok = ad.AppParams[appIdx]
	a.True(ok)
	a.Equal(approvalOps.Program, params.ApprovalProgram)
	a.Equal(clearstateOps.Program, params.ClearStateProgram)
	a.Equal(schema, params.LocalStateSchema)
	a.Equal(schema, params.GlobalStateSchema)
	a.Equal(1, len(params.GlobalState))
	value, ok = params.GlobalState["counter"]
	a.True(ok)
	a.Equal(uint64(2), value.Uint)

	a.Equal(1, len(ad.AppLocalStates))
	state, ok = ad.AppLocalStates[appIdx]
	a.True(ok)
	a.Equal(schema, state.Schema)
	a.Equal(1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	a.True(ok)
	a.Equal(uint64(1), value.Uint)

	a.Equal(uint64(2), ad.TotalAppSchema.NumUint)

	// check user's balance record for the app entry and the state changes
	ad, err = client.AccountData(user)
	a.NoError(err)
	a.Equal(0, len(ad.AppParams))

	a.Equal(1, len(ad.AppLocalStates))
	state, ok = ad.AppLocalStates[appIdx]
	a.True(ok)
	a.Equal(schema, state.Schema)
	a.Equal(1, len(state.KeyValue))
	value, ok = state.KeyValue["counter"]
	a.True(ok)
	a.Equal(uint64(1), value.Uint)

	a.Equal(basics.MicroAlgos{Raw: 10000000000 - fee}, ad.MicroAlgos)

	app, err := client.ApplicationInformation(appIdx)
	a.NoError(err)
	a.Equal(appIdx, app.Id)
	a.Equal(creator, app.Params.Creator)
}
