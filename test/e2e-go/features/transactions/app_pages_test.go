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
	"encoding/base64"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestExtraProgramPages(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer fixture.Shutdown()
	client := fixture.LibGoalClient

	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	baseAcct := accountList[0].Address

	walletHandle, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	accountInfo, err := client.AccountInformation(baseAcct, false)
	a.NoError(err)
	if accountInfo.AppsTotalExtraPages != nil {
		a.Equal(*accountInfo.AppsTotalExtraPages, uint64(0))
	}

	var inconsequentialBytes [2048]byte
	srcBigProgram := fmt.Sprintf(`#pragma version 4
byte base64(%s)
pop
int 1
return
`, base64.StdEncoding.EncodeToString(inconsequentialBytes[:]))

	srcSmallProgram := `#pragma version 4
int 1
return
`

	bigProgramOps, err := logic.AssembleString(srcBigProgram)
	a.NoError(err)
	bigProgram := bigProgramOps.Program

	smallProgramOps, err := logic.AssembleString(srcSmallProgram)
	a.NoError(err)
	smallProgram := smallProgramOps.Program

	globalSchema := basics.StateSchema{
		NumByteSlice: 1,
	}
	localSchema := basics.StateSchema{
		NumByteSlice: 1,
	}

	status, err := client.Status()
	a.NoError(err)

	// create app 1 with 1 extra page
	app1ExtraPages := uint32(1)
	tx, err := client.MakeUnsignedAppCreateTx(transactions.NoOpOC, smallProgram, smallProgram, globalSchema, localSchema, nil, libgoal.RefBundle{}, app1ExtraPages)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(baseAcct, 0, 0, 0, tx)
	a.NoError(err)
	txid, err := client.SignAndBroadcastTransaction(walletHandle, nil, tx)
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(status.LastRound+5, txid)
	a.NoError(err)

	app1CreateTxn, err := client.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(app1CreateTxn.ConfirmedRound)
	a.NotNil(app1CreateTxn.ApplicationIndex)
	app1ID := *app1CreateTxn.ApplicationIndex

	accountInfo, err = client.AccountInformation(baseAcct, false)
	a.NoError(err)
	a.NotNil(accountInfo.AppsTotalExtraPages)
	a.Equal(*accountInfo.AppsTotalExtraPages, uint64(app1ExtraPages))

	// update app 1 and ensure the extra page still works
	tx, err = client.MakeUnsignedAppUpdateTx(app1ID, nil, bigProgram, smallProgram, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(baseAcct, 0, 0, 0, tx)
	a.NoError(err)
	txid, err = client.SignAndBroadcastTransaction(walletHandle, nil, tx)
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(*app1CreateTxn.ConfirmedRound+5, txid)
	a.NoError(err)

	app1UpdateTxn, err := client.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(app1CreateTxn.ConfirmedRound)

	accountInfo, err = client.AccountInformation(baseAcct, false)
	a.NoError(err)
	a.NotNil(accountInfo.AppsTotalExtraPages)
	a.Equal(*accountInfo.AppsTotalExtraPages, uint64(app1ExtraPages))

	// create app 2 with 2 extra pages
	app2ExtraPages := uint32(2)
	tx, err = client.MakeUnsignedAppCreateTx(transactions.NoOpOC, bigProgram, smallProgram, globalSchema, localSchema, nil, libgoal.RefBundle{}, app2ExtraPages)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(baseAcct, 0, 0, 0, tx)
	a.NoError(err)
	txid, err = client.SignAndBroadcastTransaction(walletHandle, nil, tx)
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(*app1UpdateTxn.ConfirmedRound+5, txid)
	a.NoError(err)

	app2CreateTxn, err := client.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(app2CreateTxn.ConfirmedRound)
	a.NotNil(app2CreateTxn.ApplicationIndex)
	app2ID := *app2CreateTxn.ApplicationIndex

	accountInfo, err = client.AccountInformation(baseAcct, false)
	a.NoError(err)
	a.NotNil(accountInfo.AppsTotalExtraPages)
	a.Equal(*accountInfo.AppsTotalExtraPages, uint64(app1ExtraPages+app2ExtraPages))

	// delete app 1
	tx, err = client.MakeUnsignedAppDeleteTx(app1ID, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(baseAcct, 0, 0, 0, tx)
	a.NoError(err)
	txid, err = client.SignAndBroadcastTransaction(walletHandle, nil, tx)
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(*app2CreateTxn.ConfirmedRound+5, txid)
	a.NoError(err)

	app1DeleteTxn, err := client.PendingTransactionInformation(txid)
	a.NoError(err)
	a.NotNil(app1DeleteTxn.ConfirmedRound)

	accountInfo, err = client.AccountInformation(baseAcct, false)
	a.NoError(err)
	a.NotNil(accountInfo.AppsTotalExtraPages)
	a.Equal(*accountInfo.AppsTotalExtraPages, uint64(app2ExtraPages))

	// delete app 2
	tx, err = client.MakeUnsignedAppDeleteTx(app2ID, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(baseAcct, 0, 0, 0, tx)
	a.NoError(err)
	txid, err = client.SignAndBroadcastTransaction(walletHandle, nil, tx)
	a.NoError(err)
	_, err = fixture.WaitForConfirmedTxn(*app1DeleteTxn.ConfirmedRound+5, txid)
	a.NoError(err)

	accountInfo, err = client.AccountInformation(baseAcct, false)
	a.NoError(err)
	if accountInfo.AppsTotalExtraPages != nil {
		a.Equal(*accountInfo.AppsTotalExtraPages, uint64(0))
	}
}
