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

package transactions

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func checkEvalDelta(t *testing.T, client *libgoal.Client, startRnd, endRnd basics.Round, gval uint64, lval uint64) {
	a := require.New(fixtures.SynchronizedTest(t))

	foundGlobal := false
	foundLocal := false
	for r := startRnd; r < endRnd; r++ {
		lastRound, err := client.CurrentRound()
		a.NoError(err)
		if r > lastRound {
			break
		}
		b, err := client.BookkeepingBlock(r)
		a.NoError(err)
		for _, ps := range b.Payset {
			ed, ok := ps.ApplyData.EvalDelta.GlobalDelta["counter"]
			if ok && foundGlobal {
				a.Fail("Duplicate entry for global counter: %#v", ed)
			}
			if ok {
				foundGlobal = true
				a.Equal(basics.SetUintAction, ed.Action)
				a.Equal(gval, ed.Uint)
			}
			sd, ok := ps.ApplyData.EvalDelta.LocalDeltas[0]
			if ok {
				ed, ok := sd["counter"]
				if ok && foundLocal {
					a.Fail("Duplicate entry for local counter: %#v", ed)
				}
				if ok {
					foundLocal = true
					a.Equal(basics.SetUintAction, ed.Action)
					a.Equal(lval, ed.Uint)
				}
			}
		}
	}
	a.True(foundGlobal, fmt.Sprintf("global delta not found in rounds %d-%d", startRnd, endRnd))
	a.True(foundLocal, fmt.Sprintf("local delta not found in rounds %d-%d", startRnd, endRnd))
}

func TestAccountInformationV2(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	proto, ok := config.Consensus[protocol.ConsensusFuture]
	a.True(ok)
	proto.AgreementFilterTimeoutPeriod0 = 400 * time.Millisecond
	proto.AgreementFilterTimeout = 400 * time.Millisecond
	fixture.SetConsensus(config.ConsensusProtocols{protocol.ConsensusFuture: proto})

	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachV26.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)

	creator := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	user, err := client.GenerateAddress(wh)
	a.NoError(err)

	fee := uint64(1000)

	var txn transactions.Transaction

	// Fund the manager, so it can issue transactions later on
	txn, err = client.SendPaymentFromUnencryptedWallet(creator, user, fee, 10000000000, nil)
	a.NoError(err)

	round, err := client.CurrentRound()
	a.NoError(err)
	fixture.WaitForConfirmedTxn(round+4, txn.ID().String())

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
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)
	signedTxn, err := client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	txid, err := client.BroadcastTransaction(signedTxn)
	a.NoError(err)
	round, err = client.CurrentRound()
	a.NoError(err)
	// ensure transaction is accepted into a block within 5 rounds.
	confirmed := fixture.WaitForAllTxnsToConfirm(round+5, map[string]string{txid: signedTxn.Txn.Sender.String()})
	a.True(confirmed)

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

	txInfo, err := fixture.LibGoalClient.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(txInfo.ConfirmedRound)
	a.NotZero(*txInfo.ConfirmedRound)
	txnRound := *txInfo.ConfirmedRound

	// 1 global state update in total, 1 local state updates
	checkEvalDelta(t, &client, txnRound, txnRound+1, 1, 1)

	// call the app
	tx, err = client.MakeUnsignedAppOptInTx(appIdx, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(user, 0, 0, fee, tx)
	a.NoError(err)
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	txid, err = client.BroadcastTransaction(signedTxn)
	a.NoError(err)
	round, err = client.CurrentRound()
	a.NoError(err)
	_, err = client.WaitForRound(round + 3)
	a.NoError(err)
	// Ensure the txn committed
	resp, err := client.GetPendingTransactions(2)
	a.NoError(err)
	a.Zero(resp.TotalTransactions)
	txinfo, err := client.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(txinfo.ConfirmedRound)
	a.True(*txinfo.ConfirmedRound != 0)

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

	txInfo, err = fixture.LibGoalClient.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(txInfo.ConfirmedRound)
	a.NotZero(*txInfo.ConfirmedRound)
	txnRound = *txInfo.ConfirmedRound

	// 2 global state update in total, 1 local state updates
	checkEvalDelta(t, &client, txnRound, txnRound+1, 2, 1)

	a.Equal(basics.MicroAlgos{Raw: 10000000000 - fee}, ad.MicroAlgos)

	app, err := client.ApplicationInformation(appIdx)
	a.NoError(err)
	a.Equal(appIdx, app.Id)
	a.Equal(creator, app.Params.Creator)

	// call the app
	tx, err = client.MakeUnsignedAppNoOpTx(appIdx, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(user, 0, 0, fee, tx)
	a.NoError(err)
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	txid, err = client.BroadcastTransaction(signedTxn)
	a.NoError(err)
	for {
		round, err = client.CurrentRound()
		a.NoError(err)
		_, err = client.WaitForRound(round + 1)
		a.NoError(err)
		// Ensure the txn committed
		resp, err := client.GetParsedPendingTransactions(2)
		a.NoError(err)
		if resp.TotalTransactions == 1 {
			a.Equal(resp.TopTransactions[0].Txn.ID().String(), txid)
			continue
		}
		a.Zero(resp.TotalTransactions)
		break
	}

	ad, err = client.AccountData(creator)
	a.NoError(err)
	a.Equal(1, len(ad.AppParams))
	params, ok = ad.AppParams[appIdx]
	a.True(ok)
	value, ok = params.GlobalState["counter"]
	a.True(ok)
	a.Equal(uint64(3), value.Uint)

	txInfo, err = fixture.LibGoalClient.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(txInfo.ConfirmedRound)
	a.NotZero(*txInfo.ConfirmedRound)
	txnRound = *txInfo.ConfirmedRound

	// 3 global state update in total, 2 local state updates
	checkEvalDelta(t, &client, txnRound, txnRound+1, 3, 2)
}

// Add offending asset index greater than uint64
func TestAccountInformationWithBadAssetIdx(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	accountInformationCheckWithOffendingFields(t, []basics.AssetIndex{12181853637140359511}, nil, nil)
}

// Add missing asset index
func TestAccountInformationWithMissingAssetIdx(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	accountInformationCheckWithOffendingFields(t, []basics.AssetIndex{121818}, nil, nil)
}

// Add offending app index greater than uint64
func TestAccountInformationWithBadAppIdx(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	accountInformationCheckWithOffendingFields(t, nil, []basics.AppIndex{12181853637140359511}, nil)
}

// Add missing app index
func TestAccountInformationWithMissingApp(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	accountInformationCheckWithOffendingFields(t, nil, []basics.AppIndex{121818}, nil)
}

// Add missing account address
func TestAccountInformationWithMissingAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	randAddr := basics.Address{}
	crypto.RandBytes(randAddr[:])
	accountInformationCheckWithOffendingFields(t, nil, nil, []basics.Address{randAddr})
}

func accountInformationCheckWithOffendingFields(t *testing.T,
	foreignAssets []basics.AssetIndex,
	foreignApps []basics.AppIndex,
	accounts []basics.Address) {

	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	proto, ok := config.Consensus[protocol.ConsensusFuture]
	a.True(ok)
	proto.AgreementFilterTimeoutPeriod0 = 400 * time.Millisecond
	proto.AgreementFilterTimeout = 400 * time.Millisecond
	fixture.SetConsensus(config.ConsensusProtocols{protocol.ConsensusFuture: proto})

	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachV26.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)

	creator := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	user, err := client.GenerateAddress(wh)
	a.NoError(err)

	fee := uint64(1000)

	var txn transactions.Transaction

	// Fund the manager, so it can issue transactions later on
	txn, err = client.SendPaymentFromUnencryptedWallet(creator, user, fee, 10000000000, nil)
	a.NoError(err)

	round, err := client.CurrentRound()
	a.NoError(err)
	fixture.WaitForConfirmedTxn(round+4, txn.ID().String())

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
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)
	signedTxn, err := client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	txid, err := client.BroadcastTransaction(signedTxn)
	a.NoError(err)
	round, err = client.CurrentRound()
	a.NoError(err)
	// ensure transaction is accepted into a block within 5 rounds.
	confirmed := fixture.WaitForAllTxnsToConfirm(round+5, map[string]string{txid: signedTxn.Txn.Sender.String()})
	a.True(confirmed)

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

	txInfo, err := fixture.LibGoalClient.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(txInfo.ConfirmedRound)
	a.NotZero(*txInfo.ConfirmedRound)
	txnRound := *txInfo.ConfirmedRound

	// 1 global state update in total, 1 local state updates
	checkEvalDelta(t, &client, txnRound, txnRound+1, 1, 1)

	// call the app
	tx, err = client.MakeUnsignedAppOptInTx(appIdx, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	if foreignAssets != nil {
		tx.ForeignAssets = foreignAssets
	}
	if foreignApps != nil {
		tx.ForeignApps = foreignApps
	}
	if accounts != nil {
		tx.Accounts = accounts
	}
	tx, err = client.FillUnsignedTxTemplate(user, 0, 0, fee, tx)
	a.NoError(err)
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	txid, err = client.BroadcastTransaction(signedTxn)
	a.NoError(err)
	round, err = client.CurrentRound()
	a.NoError(err)
	_, err = client.WaitForRound(round + 3)
	a.NoError(err)

	// Ensure the txn committed
	resp, err := client.GetPendingTransactions(2)
	a.NoError(err)
	a.Zero(resp.TotalTransactions)
	txinfo, err := client.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(txinfo.ConfirmedRound)
	a.NotZero(*txInfo.ConfirmedRound)

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

	txInfo, err = fixture.LibGoalClient.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(txInfo.ConfirmedRound)
	a.NotZero(*txInfo.ConfirmedRound)
	txnRound = *txInfo.ConfirmedRound

	// 2 global state update in total, 1 local state updates
	checkEvalDelta(t, &client, txnRound, txnRound+1, 2, 1)

	a.Equal(basics.MicroAlgos{Raw: 10000000000 - fee}, ad.MicroAlgos)

	app, err := client.ApplicationInformation(appIdx)
	a.NoError(err)
	a.Equal(appIdx, app.Id)
	a.Equal(creator, app.Params.Creator)

	// call the app
	tx, err = client.MakeUnsignedAppNoOpTx(appIdx, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(user, 0, 0, fee, tx)
	a.NoError(err)
	signedTxn, err = client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	txid, err = client.BroadcastTransaction(signedTxn)
	a.NoError(err)
	for {
		round, err = client.CurrentRound()
		a.NoError(err)
		_, err = client.WaitForRound(round + 1)
		a.NoError(err)
		// Ensure the txn committed
		resp, err := client.GetParsedPendingTransactions(2)
		a.NoError(err)
		if resp.TotalTransactions == 1 {
			pendingTxn := resp.TopTransactions[0]
			a.Equal(pendingTxn.Txn.ID().String(), txid)
			continue
		}
		a.Zero(resp.TotalTransactions)
		break
	}

	ad, err = client.AccountData(creator)
	a.NoError(err)
	a.Equal(1, len(ad.AppParams))
	params, ok = ad.AppParams[appIdx]
	a.True(ok)
	value, ok = params.GlobalState["counter"]
	a.True(ok)
	a.Equal(uint64(3), value.Uint)

	txInfo, err = fixture.LibGoalClient.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(txInfo.ConfirmedRound)
	a.NotZero(*txInfo.ConfirmedRound)
	txnRound = *txInfo.ConfirmedRound

	// 3 global state update in total, 2 local state updates
	checkEvalDelta(t, &client, txnRound, txnRound+1, 3, 2)
}
