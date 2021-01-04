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

package transactions

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

func TestAccountInformationV2(t *testing.T) {
	t.Parallel()
	a := require.New(t)

	var fixture fixtures.RestClientFixture
	proto, ok := config.Consensus[protocol.ConsensusFuture]
	a.True(ok)
	proto.AgreementFilterTimeoutPeriod0 = 400 * time.Millisecond
	proto.AgreementFilterTimeout = 400 * time.Millisecond
	fixture.SetConsensus(config.ConsensusProtocols{protocol.ConsensusFuture: proto})

	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
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

	round, err := client.CurrentRound()
	a.NoError(err)

	// Fund the manager, so it can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(creator, user, fee, 10000000000, nil)
	a.NoError(err)
	client.WaitForRound(round + 4)

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
		transactions.OptInOC, approvalOps.Program, clearstateOps.Program, schema, schema, nil, nil, nil, nil,
	)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(creator, 0, 0, fee, tx)
	a.NoError(err)
	signedTxn, err := client.SignTransactionWithWallet(wh, nil, tx)
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
	tx, err = client.MakeUnsignedAppOptInTx(uint64(appIdx), nil, nil, nil, nil)
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

	app, err := client.ApplicationInformation(uint64(appIdx))
	a.NoError(err)
	a.Equal(uint64(appIdx), app.Id)
	a.Equal(creator, app.Params.Creator)
}
