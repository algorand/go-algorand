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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type assetIDParams struct {
	idx    basics.AssetIndex
	params model.AssetParams
}

func helperFillSignBroadcast(client libgoal.Client, wh []byte, sender string, tx transactions.Transaction, err error) (string, error) {
	if err != nil {
		return "", err
	}

	// we're sending many txns, so might need to raise the fee
	tx, err = client.FillUnsignedTxTemplate(sender, 0, 0, 1000000, tx)
	if err != nil {
		return "", err
	}

	return client.SignAndBroadcastTransaction(wh, nil, tx)
}

func TestAssetValidRounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient

	// First, test valid rounds to last valid conversion
	var firstValid, lastValid, lastRound, validRounds basics.Round

	params, err := client.SuggestedParams()
	a.NoError(err)
	cparams, ok := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	a.True(ok)
	maxTxnLife := basics.Round(cparams.MaxTxnLife)
	firstValid = 0
	lastValid = 0
	validRounds = maxTxnLife + 1
	firstValid, lastValid, lastRound, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.NoError(err)
	a.True(firstValid == 1 || firstValid == lastRound)
	a.Equal(firstValid+maxTxnLife, lastValid)

	firstValid = 0
	lastValid = 0
	validRounds = maxTxnLife + 2
	_, _, _, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.ErrorContains(err, "cannot construct transaction: txn validity period")

	firstValid = 0
	lastValid = 0
	validRounds = 1
	firstValid, lastValid, _, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.NoError(err)
	a.Equal(firstValid, lastValid)

	firstValid = 1
	lastValid = 0
	validRounds = 1
	firstValid, lastValid, _, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.NoError(err)
	a.EqualValues(1, firstValid)
	a.Equal(firstValid, lastValid)

	firstValid = 1
	lastValid = 0
	validRounds = maxTxnLife
	firstValid, lastValid, _, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.NoError(err)
	a.EqualValues(1, firstValid)
	a.Equal(maxTxnLife, lastValid)

	firstValid = 100
	lastValid = 0
	validRounds = maxTxnLife
	firstValid, lastValid, _, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.NoError(err)
	a.EqualValues(100, firstValid)
	a.Equal(firstValid+maxTxnLife-1, lastValid)

	// Second, test transaction creation
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	account0 := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	manager, err := client.GenerateAddress(wh)
	a.NoError(err)

	reserve := manager
	freeze := manager
	clawback := manager

	// Fund the manager, so it can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(account0, manager, 0, 10000000000, nil)
	a.NoError(err)

	tx, err := client.MakeUnsignedAssetCreateTx(100, false, manager, reserve, freeze, clawback, "test1", "testname1", "foo://bar", nil, 0)
	a.NoError(err)

	fee := uint64(1000)
	firstValid = 0
	lastValid = 0

	params, err = client.SuggestedParams()
	a.NoError(err)
	lastRoundBefore := params.LastRound

	tx, err = client.FillUnsignedTxTemplate(account0, firstValid, lastValid, fee, tx)
	a.NoError(err)
	// zeros are special cases
	// first valid never should be zero
	a.NotZero(tx.FirstValid)

	params, err = client.SuggestedParams()
	a.NoError(err)
	lastRoundAfter := params.LastRound

	// ledger may advance between SuggestedParams and FillUnsignedTxTemplate calls
	// expect validity sequence
	var firstValidRange, lastValidRange []basics.Round
	for i := lastRoundBefore; i <= lastRoundAfter+1; i++ {
		firstValidRange = append(firstValidRange, i)
		lastValidRange = append(lastValidRange, i+maxTxnLife)
	}
	a.Contains(firstValidRange, tx.FirstValid)
	a.Contains(lastValidRange, tx.LastValid)

	firstValid = 1
	lastValid = 1
	tx, err = client.FillUnsignedTxTemplate(account0, firstValid, lastValid, fee, tx)
	a.NoError(err)
	a.Equal(basics.Round(1), tx.FirstValid)
	a.Equal(basics.Round(1), tx.LastValid)

	firstValid = 1
	lastValid = 0
	tx, err = client.FillUnsignedTxTemplate(account0, firstValid, lastValid, fee, tx)
	a.NoError(err)
	a.Equal(basics.Round(1), tx.FirstValid)
	a.Equal(maxTxnLife+1, tx.LastValid)
}

func TestAssetConfig(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	account0 := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	manager, err := client.GenerateAddress(wh)
	a.NoError(err)

	reserve, err := client.GenerateAddress(wh)
	a.NoError(err)

	freeze, err := client.GenerateAddress(wh)
	a.NoError(err)

	clawback, err := client.GenerateAddress(wh)
	a.NoError(err)

	assetURL := "foo://bar"
	assetMetadataHash := []byte("ISTHISTHEREALLIFEISTHISJUSTFANTA")

	// Fund the manager, so it can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(account0, manager, 0, 10000000000, nil)
	a.NoError(err)

	// There should be no assets to start with
	info, err := client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(len(*info.CreatedAssets), 0)

	// Create max number of assets, or 1000 if the number of assets are unlimitd.
	maxAssetsCount := config.Consensus[protocol.ConsensusFuture].MaxAssetsPerAccount
	if maxAssetsCount == 0 {
		maxAssetsCount = config.Consensus[protocol.ConsensusV30].MaxAssetsPerAccount
	}

	txids := make(map[string]string)
	for i := 0; i < maxAssetsCount; i++ {
		// re-generate wh, since this test takes a while and sometimes
		// the wallet handle expires.
		wh, err = client.GetUnencryptedWalletHandle()
		a.NoError(err)

		tx, err := client.MakeUnsignedAssetCreateTx(1+uint64(i), false, manager, reserve, freeze, clawback, fmt.Sprintf("test%d", i), fmt.Sprintf("testname%d", i), assetURL, assetMetadataHash, 0)
		txid, err := helperFillSignBroadcast(client, wh, account0, tx, err)
		a.NoError(err)
		txids[txid] = account0
	}

	status, err := fixture.AlgodClient.Status()
	a.NoError(err)
	confirmed := fixture.WaitForAllTxnsToConfirm(status.LastRound+20, txids)
	a.True(confirmed, "creating max number of assets")

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)

	var tx transactions.Transaction
	if config.Consensus[protocol.ConsensusFuture].MaxAssetsPerAccount != 0 {
		// Creating more assets should return an error
		tx, err = client.MakeUnsignedAssetCreateTx(1, false, manager, reserve, freeze, clawback, "toomany", "toomany", assetURL, assetMetadataHash, 0)
		_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
		a.Error(err)
		a.True(strings.Contains(err.Error(), "too many assets in account:"))
	}

	// Helper methods for dereferencing asset fields
	derefString := func(sp *string) string {
		if sp != nil {
			return *sp
		}
		return ""
	}
	derefByteArray := func(ba *[]byte) []byte {
		if ba != nil {
			return *ba
		}
		return []byte{}
	}

	// Check that assets are visible
	info, err = client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.Assets)
	a.Equal(maxAssetsCount, len(*info.CreatedAssets))
	var assets []assetIDParams
	for _, asset := range *info.CreatedAssets {
		idx := asset.Index
		cp := asset.Params
		assets = append(assets, assetIDParams{idx, cp})
		a.Equal(derefString(cp.UnitName), fmt.Sprintf("test%d", cp.Total-1))
		a.Equal(derefString(cp.Name), fmt.Sprintf("testname%d", cp.Total-1))
		a.Equal(derefString(cp.Manager), manager)
		a.Equal(derefString(cp.Reserve), reserve)
		a.Equal(derefString(cp.Freeze), freeze)
		a.Equal(derefString(cp.Clawback), clawback)
		a.Equal(derefByteArray(cp.MetadataHash), assetMetadataHash)
		a.Equal(derefString(cp.Url), assetURL)
	}

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)

	// Test changing various keys
	var empty string
	txids = make(map[string]string)

	tx, err = client.MakeUnsignedAssetConfigTx(account0, assets[0].idx, &account0, nil, nil, nil)
	txid, err := helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedAssetConfigTx(account0, assets[1].idx, nil, &account0, nil, nil)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedAssetConfigTx(account0, assets[2].idx, nil, nil, &account0, nil)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedAssetConfigTx(account0, assets[3].idx, nil, nil, nil, &account0)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedAssetConfigTx(account0, assets[4].idx, nil, &empty, nil, nil)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedAssetConfigTx(account0, assets[5].idx, nil, nil, &empty, nil)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	tx, err = client.MakeUnsignedAssetConfigTx(account0, assets[6].idx, nil, nil, nil, &empty)
	txid, err = helperFillSignBroadcast(client, wh, manager, tx, err)
	a.NoError(err)
	txids[txid] = manager

	status, err = fixture.AlgodClient.Status()
	a.NoError(err)
	confirmed = fixture.WaitForAllTxnsToConfirm(status.LastRound+20, txids)
	a.True(confirmed, "changing keys")

	info, err = client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(maxAssetsCount, len(*info.CreatedAssets))
	for _, asset := range *info.CreatedAssets {
		idx := asset.Index
		cp := asset.Params
		a.Equal(derefString(cp.UnitName), fmt.Sprintf("test%d", cp.Total-1))
		a.Equal(derefString(cp.Name), fmt.Sprintf("testname%d", cp.Total-1))

		if idx == assets[0].idx {
			a.Equal(derefString(cp.Manager), account0)
		} else {
			a.Equal(derefString(cp.Manager), manager)
		}

		if idx == assets[1].idx {
			a.Equal(derefString(cp.Reserve), account0)
		} else if idx == assets[4].idx {
			a.Equal(derefString(cp.Reserve), "")
		} else {
			a.Equal(derefString(cp.Reserve), reserve)
		}

		if idx == assets[2].idx {
			a.Equal(derefString(cp.Freeze), account0)
		} else if idx == assets[5].idx {
			a.Equal(derefString(cp.Freeze), "")
		} else {
			a.Equal(derefString(cp.Freeze), freeze)
		}

		if idx == assets[3].idx {
			a.Equal(derefString(cp.Clawback), account0)
		} else if idx == assets[6].idx {
			a.Equal(derefString(cp.Clawback), "")
		} else {
			a.Equal(derefString(cp.Clawback), clawback)
		}
	}

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)

	// Should not be able to close account before destroying assets
	_, err = client.SendPaymentFromWallet(wh, nil, account0, "", 0, 0, nil, reserve, 0, 0)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "cannot close:"))
	a.True(strings.Contains(err.Error(), "outstanding assets"))

	// Destroy assets
	txids = make(map[string]string)
	for _, asset := range *info.CreatedAssets {
		idx := asset.Index
		// re-generate wh, since this test takes a while and sometimes
		// the wallet handle expires.
		wh, err = client.GetUnencryptedWalletHandle()
		a.NoError(err)

		tx, err := client.MakeUnsignedAssetDestroyTx(idx)
		sender := manager
		if idx == assets[0].idx {
			sender = account0
		}
		txid, err := helperFillSignBroadcast(client, wh, sender, tx, err)
		a.NoError(err)
		txids[txid] = sender
	}

	status, err = fixture.AlgodClient.Status()
	a.NoError(err)
	confirmed = fixture.WaitForAllTxnsToConfirm(status.LastRound+20, txids)
	a.True(confirmed, "destroying assets")

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)

	// Should be able to close now
	_, err = client.SendPaymentFromWallet(wh, nil, account0, "", 0, 0, nil, reserve, 0, 0)
	a.NoError(err)
}

func TestAssetInformation(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachV24.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	account0 := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	manager, err := client.GenerateAddress(wh)
	a.NoError(err)

	reserve, err := client.GenerateAddress(wh)
	a.NoError(err)

	freeze, err := client.GenerateAddress(wh)
	a.NoError(err)

	clawback, err := client.GenerateAddress(wh)
	a.NoError(err)

	// Fund the manager, so it can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(account0, manager, 0, 10000000000, nil)
	a.NoError(err)

	// There should be no assets to start with
	info2, err := client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info2.CreatedAssets)
	a.Equal(len(*info2.CreatedAssets), 0)

	// Create some assets
	txids := make(map[string]string)
	for i := 0; i < 16; i++ {
		tx, err := client.MakeUnsignedAssetCreateTx(1+uint64(i), false, manager, reserve, freeze, clawback, fmt.Sprintf("test%d", i), fmt.Sprintf("testname%d", i), "foo://bar", nil, 0)
		txid, err := helperFillSignBroadcast(client, wh, account0, tx, err)
		a.NoError(err)
		txids[txid] = account0
	}

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "creating assets")

	// Check that AssetInformation returns the correct AssetParams
	info2, err = client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info2.CreatedAssets)
	for _, cp := range *info2.CreatedAssets {
		asset, err := client.AssetInformation(cp.Index)
		a.NoError(err)
		a.Equal(cp, asset)
	}

	// Destroy assets
	txids = make(map[string]string)
	for _, asset := range *info2.CreatedAssets {
		idx := asset.Index
		tx, err := client.MakeUnsignedAssetDestroyTx(idx)
		txid, err := helperFillSignBroadcast(client, wh, manager, tx, err)
		a.NoError(err)
		txids[txid] = manager
	}

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "destroying assets")

	// Close account
	_, err = client.SendPaymentFromWallet(wh, nil, account0, "", 0, 0, nil, reserve, 0, 0)
	a.NoError(err)
}

func TestAssetGroupCreateSendDestroy(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer fixture.Shutdown()

	client0 := fixture.GetLibGoalClientForNamedNode("Primary")
	client1 := fixture.GetLibGoalClientForNamedNode("Node")

	wh0, err := client0.GetUnencryptedWalletHandle()
	a.NoError(err)
	wh1, err := client1.GetUnencryptedWalletHandle()
	a.NoError(err)

	client0.ListAddresses(wh0)
	accountList, err := client0.ListAddresses(wh0)
	a.NoError(err)
	account0 := accountList[0]

	client1.ListAddresses(wh0)
	accountList, err = client1.ListAddresses(wh1)
	a.NoError(err)
	account1 := accountList[0]

	txCount := uint64(1000) // starting with v38 tx count is initialized to 1000
	fee := uint64(1000000)

	manager := account0
	reserve := account0
	freeze := account0
	clawback := account0

	txids := make(map[string]string)
	assetTotal := uint64(100)

	// Create and Send in the same group
	assetName1 := "testassetname1"
	assetUnitName1 := "unit1"
	txCreate1, err := client0.MakeUnsignedAssetCreateTx(assetTotal, false, manager, reserve, freeze, clawback, assetUnitName1, assetName1, "foo://bar", nil, 0)
	a.NoError(err)
	txCreate1, err = client0.FillUnsignedTxTemplate(account0, 0, 0, fee, txCreate1)
	a.NoError(err)

	assetID1 := basics.AssetIndex(txCount + 1)
	txSend, err := client1.MakeUnsignedAssetSendTx(assetID1, 0, account1, "", "")
	a.NoError(err)
	txSend, err = client1.FillUnsignedTxTemplate(account1, 0, 0, fee, txSend)
	a.NoError(err)

	gid, err := client0.GroupID([]transactions.Transaction{txCreate1, txSend})
	a.NoError(err)

	var stxns []transactions.SignedTxn

	txCreate1.Group = gid
	stxn, err := client0.SignTransactionWithWallet(wh0, nil, txCreate1)
	a.NoError(err)
	stxns = append(stxns, stxn)
	txids[txCreate1.ID().String()] = account0

	txSend.Group = gid
	stxn, err = client1.SignTransactionWithWallet(wh1, nil, txSend)
	a.NoError(err)
	stxns = append(stxns, stxn)
	txids[txSend.ID().String()] = account1

	txCount += uint64(len(stxns))

	// broadcasting group should succeed
	err = client0.BroadcastTransactionGroup(stxns)
	a.NoError(err)

	// Create and Destroy in the same group
	assetName2 := "testassetname2"
	assetUnitName2 := "unit2"
	txCreate2, err := client0.MakeUnsignedAssetCreateTx(assetTotal, false, manager, reserve, freeze, clawback, assetUnitName2, assetName2, "foo://bar", nil, 0)
	a.NoError(err)
	txCreate2, err = client0.FillUnsignedTxTemplate(account0, 0, 0, fee, txCreate2)
	a.NoError(err)

	assetID3 := basics.AssetIndex(txCount + 1)
	txDestroy, err := client0.MakeUnsignedAssetDestroyTx(assetID3)
	a.NoError(err)
	txDestroy, err = client0.FillUnsignedTxTemplate(account0, 0, 0, fee, txDestroy)
	a.NoError(err)

	gid, err = client0.GroupID([]transactions.Transaction{txCreate2, txDestroy})
	a.NoError(err)

	stxns = []transactions.SignedTxn{}

	txCreate2.Group = gid
	stxn, err = client0.SignTransactionWithWallet(wh0, nil, txCreate2)
	a.NoError(err)
	stxns = append(stxns, stxn)
	txids[txCreate2.ID().String()] = account0

	txDestroy.Group = gid
	stxn, err = client0.SignTransactionWithWallet(wh0, nil, txDestroy)
	a.NoError(err)
	stxns = append(stxns, stxn)
	txids[txDestroy.ID().String()] = account0

	// broadcasting group should succeed
	err = client0.BroadcastTransactionGroup(stxns)
	a.NoError(err)

	status0, err := client0.Status()
	a.NoError(err)

	confirmed := fixture.WaitForAllTxnsToConfirm(status0.LastRound+5, txids)
	a.True(confirmed)

	status0, err = client0.Status()
	a.NoError(err)

	// wait for client1 to reach the same round as client0
	_, err = client1.WaitForRound(status0.LastRound)
	a.NoError(err)

	txids = make(map[string]string)

	// asset 1 (create + send) exists and available
	asset, err := client1.AssetInformation(assetID1)
	assetParams := asset.Params
	a.NoError(err)
	a.NotNil(assetParams.Name)
	a.Equal(assetName1, *assetParams.Name)
	a.NotNil(*assetParams.UnitName)
	a.Equal(assetUnitName1, *assetParams.UnitName)
	a.Equal(account0, assetParams.Creator)
	a.Equal(assetTotal, assetParams.Total)
	// sending it should succeed
	txSend, err = client0.MakeUnsignedAssetSendTx(assetID1, 1, account1, "", "")
	txid, err := helperFillSignBroadcast(client0, wh0, account0, txSend, err)
	a.NoError(err)
	txids[txid] = account0

	status0, err = client0.Status()
	a.NoError(err)
	confirmed = fixture.WaitForAllTxnsToConfirm(status0.LastRound+5, txids)
	a.True(confirmed)

	status0, err = client0.Status()
	a.NoError(err)

	// wait for client1 to reach the same round as client0
	_, err = client1.WaitForRound(status0.LastRound)
	a.NoError(err)

	// asset 3 (create + destroy) not available
	_, err = client1.AssetInformation(assetID3)
	a.Error(err)
	// sending it should fail
	txSend, err = client1.MakeUnsignedAssetSendTx(assetID3, 0, account1, "", "")
	_, err = helperFillSignBroadcast(client1, wh1, account1, txSend, err)
	a.Error(err)
}

func TestAssetSend(t *testing.T) {
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
	account0 := accountList[0].Address
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	manager, err := client.GenerateAddress(wh)
	a.NoError(err)

	reserve, err := client.GenerateAddress(wh)
	a.NoError(err)

	freeze, err := client.GenerateAddress(wh)
	a.NoError(err)

	clawback, err := client.GenerateAddress(wh)
	a.NoError(err)

	extra, err := client.GenerateAddress(wh)
	a.NoError(err)

	// Fund the manager, freeze, clawback, and extra, so they can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(account0, manager, 0, 10000000000, nil)
	a.NoError(err)
	_, err = client.SendPaymentFromUnencryptedWallet(account0, freeze, 0, 10000000000, nil)
	a.NoError(err)
	_, err = client.SendPaymentFromUnencryptedWallet(account0, clawback, 0, 10000000000, nil)
	a.NoError(err)

	// Create two assets: one with default-freeze, and one without default-freeze
	txids := make(map[string]string)

	tx, err := client.MakeUnsignedAssetCreateTx(100, false, manager, reserve, freeze, clawback, "nofreeze", "xx", "foo://bar", nil, 0)
	txid, err := helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)
	txids[txid] = account0

	tx, err = client.MakeUnsignedAssetCreateTx(100, true, manager, reserve, freeze, clawback, "frozen", "xx", "foo://bar", nil, 0)
	txid, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)
	txids[txid] = account0

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "creating assets")

	info, err := client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(len(*info.CreatedAssets), 2)
	var frozenIdx, nonFrozenIdx basics.AssetIndex
	for _, asset := range *info.CreatedAssets {
		idx := asset.Index
		cp := asset.Params
		if cp.UnitName != nil && *cp.UnitName == "frozen" {
			frozenIdx = idx
		}

		if cp.UnitName != nil && *cp.UnitName == "nofreeze" {
			nonFrozenIdx = idx
		}
	}

	// An account with no algos should not be able to accept assets
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 0, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)

	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 0, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "overspend"))
	a.True(strings.Contains(err.Error(), "tried to spend"))

	// Fund the account: extra
	tx, err = client.SendPaymentFromUnencryptedWallet(account0, extra, 0, 10000000000, nil)
	a.NoError(err)
	_, curRound = fixture.GetBalanceAndRound(account0)
	fixture.WaitForConfirmedTxn(curRound+20, tx.ID().String())

	// Sending assets to account that hasn't opted in should fail, but
	// after opting in, should succeed for non-frozen asset.
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 1, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "asset"))
	a.True(strings.Contains(err.Error(), "missing from"))

	// Clawback assets to an account that hasn't opted in should fail
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 1, extra, "", account0)
	_, err = helperFillSignBroadcast(client, wh, clawback, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "asset"))
	a.True(strings.Contains(err.Error(), "missing from"))

	// opting in should be signed by the opting in account not sender
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 0, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)

	// Account hasn't opted in yet. sending will fail
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 1, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "asset"))
	a.True(strings.Contains(err.Error(), "missing from"))

	// Account hasn't opted in yet. clawback to will fail
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 1, extra, "", account0)
	_, err = helperFillSignBroadcast(client, wh, clawback, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "asset"))
	a.True(strings.Contains(err.Error(), "missing from"))

	txids = make(map[string]string)
	tx, err = client.MakeUnsignedAssetSendTx(frozenIdx, 0, extra, "", "")
	txid, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)
	txids[txid] = extra

	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 0, extra, "", "")
	txid, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)
	txids[txid] = extra

	tx, err = client.MakeUnsignedAssetSendTx(frozenIdx, 1, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "asset frozen in recipient"))

	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 10, extra, "", "")
	txid, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)
	txids[txid] = account0

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "creating asset slots")

	info, err = client.AccountInformation(extra, true)
	a.NoError(err)
	a.NotNil(info.Assets)
	a.Equal(len(*info.Assets), 2)
	for _, asset := range *info.Assets {
		if asset.AssetID == frozenIdx {
			a.Equal(asset.Amount, uint64(0))
			a.Equal(asset.IsFrozen, true)
		} else if asset.AssetID == nonFrozenIdx {
			a.Equal(asset.Amount, uint64(10))
			a.Equal(asset.IsFrozen, false)
		}
	}

	// Should not be able to send more than is available
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 11, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "underflow on subtracting 11 from sender amount 10"))

	// Should not be able to clawback more than is available
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 11, account0, "", extra)
	_, err = helperFillSignBroadcast(client, wh, clawback, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "underflow on subtracting 11 from sender amount 10"))

	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 10, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)

	// Swap frozen status on the extra account (and the wrong address should not
	// be able to change frozen status)
	tx, err = client.MakeUnsignedAssetFreezeTx(nonFrozenIdx, extra, true)
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "freeze not allowed: sender"))

	tx, err = client.MakeUnsignedAssetFreezeTx(nonFrozenIdx, extra, true)
	_, err = helperFillSignBroadcast(client, wh, freeze, tx, err)
	a.NoError(err)

	tx, err = client.MakeUnsignedAssetFreezeTx(frozenIdx, extra, false)
	_, err = helperFillSignBroadcast(client, wh, freeze, tx, err)
	a.NoError(err)

	// Should be able to send money to the now-unfrozen account,
	// but should not be able to send money from the now-frozen account.
	tx, err = client.MakeUnsignedAssetSendTx(frozenIdx, 10, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)

	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 1, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "frozen in"))

	// Clawback should be able to claim money out of both frozen and non-frozen accounts,
	// and the wrong address should not be able to clawback.
	txids = make(map[string]string)
	tx, err = client.MakeUnsignedAssetSendTx(frozenIdx, 5, account0, "", extra)
	txid, err = helperFillSignBroadcast(client, wh, clawback, tx, err)
	a.NoError(err)
	txids[txid] = clawback

	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 5, account0, "", extra)
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "clawback not allowed: sender"))

	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 5, account0, "", extra)
	txid, err = helperFillSignBroadcast(client, wh, clawback, tx, err)
	a.NoError(err)
	txids[txid] = clawback

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "clawback")

	// Check that the asset balances are correct
	info, err = client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.Assets)
	a.Equal(len(*info.Assets), 2)
	for _, asset := range *info.Assets {
		if asset.AssetID == frozenIdx {
			a.Equal(asset.Amount, uint64(95))
		} else if asset.AssetID == nonFrozenIdx {
			a.Equal(asset.Amount, uint64(95))
		}
	}

	info, err = client.AccountInformation(extra, true)
	a.NoError(err)
	a.NotNil(info.Assets)
	a.Equal(len(*info.Assets), 2)
	for _, asset := range *info.Assets {
		if asset.AssetID == frozenIdx {
			a.Equal(asset.Amount, uint64(5))
		} else if asset.AssetID == nonFrozenIdx {
			a.Equal(asset.Amount, uint64(5))
		}
	}

	// Should be able to close out asset slots and close entire account.
	tx, err = client.MakeUnsignedAssetFreezeTx(nonFrozenIdx, extra, false)
	_, err = helperFillSignBroadcast(client, wh, freeze, tx, err)
	a.NoError(err)

	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 0, "", account0, "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)

	tx, err = client.MakeUnsignedAssetSendTx(frozenIdx, 0, "", account0, "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)

	_, err = client.SendPaymentFromWallet(wh, nil, extra, "", 0, 0, nil, account0, 0, 0)
	a.NoError(err)
}

func TestAssetCreateWaitRestartDelete(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a, fixture, client, account0 := setupTestAndNetwork(t, "", nil)
	defer fixture.Shutdown()

	// There should be no assets to start with
	info, err := client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(len(*info.CreatedAssets), 0)

	manager, reserve, freeze, clawback := setupActors(account0, client, a)
	createAsset("test", account0, manager, reserve, freeze, clawback, client, fixture, a)

	// Check that asset is visible
	info, err = client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(len(*info.CreatedAssets), 1)
	var asset model.AssetParams
	var assetIndex basics.AssetIndex
	for _, cp := range *info.CreatedAssets {
		asset = cp.Params
		assetIndex = cp.Index
	}

	assetURL := "foo://bar"
	assetMetadataHash := []byte("ISTHISTHEREALLIFEISTHISJUSTFANTA")

	verifyAssetParameters(asset, "test", "testunit", manager, reserve, freeze, clawback,
		assetMetadataHash, assetURL, a)

	// restart the node
	fixture.ShutdownImpl(true) // shutdown but preserve the data
	fixture.Start()
	fixture.AlgodClient = fixture.GetAlgodClientForController(fixture.NC)
	client = &fixture.LibGoalClient

	// Check again that asset is visible
	info, err = client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(len(*info.CreatedAssets), 1)
	for _, cp := range *info.CreatedAssets {
		asset = cp.Params
		assetIndex = cp.Index
	}
	verifyAssetParameters(asset, "test", "testunit", manager, reserve, freeze, clawback,
		assetMetadataHash, assetURL, a)

	// Ensure manager is funded before submitting any transactions
	currentRound, err := client.CurrentRound()
	a.NoError(err)

	err = fixture.WaitForAccountFunded(currentRound+5, manager)
	a.NoError(err)

	// Destroy the asset
	tx, err := client.MakeUnsignedAssetDestroyTx(assetIndex)
	a.NoError(err)
	submitAndWaitForTransaction(manager, tx, "destroying assets", client, fixture, a)

	// Check again that asset is destroyed
	info, err = client.AccountInformation(account0, true)
	a.NoError(err)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(len(*info.CreatedAssets), 0)

	// Should be able to close now
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)
	_, err = client.SendPaymentFromWallet(wh, nil, account0, "", 0, 0, nil, reserve, 0, 0)
	a.NoError(err)
}

func TestAssetCreateWaitBalLookbackDelete(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	configurableConsensus := make(config.ConsensusProtocols)

	consensusVersion := protocol.ConsensusVersion("test-shorter-lookback")

	// Setting the testShorterLookback parameters derived from ConsensusCurrentVersion
	// Will result in MaxBalLookback = 32
	// Used to run tests faster where past MaxBalLookback values are checked
	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	consensusParams.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	// MaxBalLookback  =  2 x SeedRefreshInterval x SeedLookback
	// ref. https://github.com/algorandfoundation/specs/blob/master/dev/abft.md
	consensusParams.SeedLookback = 2
	consensusParams.SeedRefreshInterval = 8
	consensusParams.MaxBalLookback = 2 * consensusParams.SeedLookback * consensusParams.SeedRefreshInterval // 32
	consensusParams.AgreementFilterTimeoutPeriod0 = 400 * time.Millisecond
	consensusParams.AgreementFilterTimeout = 400 * time.Millisecond

	configurableConsensus[consensusVersion] = consensusParams

	a, fixture, client, account0 := setupTestAndNetwork(t, "TwoNodes50EachTestShorterLookback.json", configurableConsensus)
	defer fixture.Shutdown()

	// There should be no assets to start with
	info, err := client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(len(*info.CreatedAssets), 0)

	manager, reserve, freeze, clawback := setupActors(account0, client, a)
	createAsset("test", account0, manager, reserve, freeze, clawback, client, fixture, a)

	// Check that asset is visible
	info, err = client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(len(*info.CreatedAssets), 1)
	var asset model.AssetParams
	var assetIndex basics.AssetIndex
	for _, cp := range *info.CreatedAssets {
		asset = cp.Params
		assetIndex = cp.Index
	}

	assetURL := "foo://bar"
	assetMetadataHash := []byte("ISTHISTHEREALLIFEISTHISJUSTFANTA")

	verifyAssetParameters(asset, "test", "testunit", manager, reserve, freeze, clawback,
		assetMetadataHash, assetURL, a)

	//  Wait more than lookback rounds
	_, curRound := fixture.GetBalanceAndRound(account0)
	nodeStatus, _ := client.Status()
	consParams, err := client.ConsensusParams(nodeStatus.LastRound)
	a.NoError(err)
	err = fixture.WaitForRoundWithTimeout(curRound + basics.Round(consParams.MaxBalLookback) + 1)
	a.NoError(err)

	// Check again that asset is visible
	info, err = client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(len(*info.CreatedAssets), 1)
	for _, cp := range *info.CreatedAssets {
		asset = cp.Params
		assetIndex = cp.Index
	}
	verifyAssetParameters(asset, "test", "testunit", manager, reserve, freeze, clawback,
		assetMetadataHash, assetURL, a)

	// Ensure manager is funded before submitting any transactions
	currentRound, err := client.CurrentRound()
	a.NoError(err)

	err = fixture.WaitForAccountFunded(currentRound+5, manager)
	a.NoError(err)

	// Destroy the asset
	tx, err := client.MakeUnsignedAssetDestroyTx(assetIndex)
	a.NoError(err)
	submitAndWaitForTransaction(manager, tx, "destroying assets", client, fixture, a)

	// Check again that asset is destroyed
	info, err = client.AccountInformation(account0, true)
	a.NoError(err)
	a.NotNil(info.CreatedAssets)
	a.Equal(len(*info.CreatedAssets), 0)

	// Should be able to close now
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)
	_, err = client.SendPaymentFromWallet(wh, nil, account0, "", 0, 0, nil, reserve, 0, 0)
	a.NoError(err)
}

/** Helper functions **/

// Setup the test and the network
func setupTestAndNetwork(t *testing.T, networkTemplate string, consensus config.ConsensusProtocols) (
	Assertions *require.Assertions, Fixture *fixtures.RestClientFixture, Client *libgoal.Client, Account0 string) {

	t.Parallel()
	asser := require.New(fixtures.SynchronizedTest(t))
	if len(networkTemplate) == 0 {
		// If the  networkTemplate is not specified, used the default one
		networkTemplate = "TwoNodes50Each.json"
	}
	var fixture fixtures.RestClientFixture
	if consensus != nil {
		fixture.SetConsensus(consensus)
	}
	fixture.Setup(t, filepath.Join("nettemplates", networkTemplate))
	accountList, err := fixture.GetWalletsSortedByBalance()
	asser.NoError(err)
	account0 := accountList[0].Address

	client := &fixture.LibGoalClient
	return asser, &fixture, client, account0
}

// Create an asset
func createAsset(assetName, account0, manager, reserve, freeze, clawback string,
	client *libgoal.Client,
	fixture *fixtures.RestClientFixture,
	asser *require.Assertions) {

	assetURL := "foo://bar"
	assetMetadataHash := []byte("ISTHISTHEREALLIFEISTHISJUSTFANTA")

	// Create two assets: one with default-freeze, and one without default-freeze
	txids := make(map[string]string)
	wh, err := client.GetUnencryptedWalletHandle()
	asser.NoError(err)
	tx, err := client.MakeUnsignedAssetCreateTx(100, false, manager, reserve, freeze, clawback, assetName, "testunit", assetURL, assetMetadataHash, 0)
	txid, err := helperFillSignBroadcast(*client, wh, account0, tx, err)
	asser.NoError(err)
	txids[txid] = account0

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	asser.True(confirmed, "created the assets")
}

// Setup the actors
func setupActors(account0 string, client *libgoal.Client, asser *require.Assertions) (manager, reserve, freeze, clawback string) {
	// Setup the actors

	wh, err := client.GetUnencryptedWalletHandle()
	asser.NoError(err)
	manager, err = client.GenerateAddress(wh)
	asser.NoError(err)
	reserve, err = client.GenerateAddress(wh)
	asser.NoError(err)
	freeze, err = client.GenerateAddress(wh)
	asser.NoError(err)
	clawback, err = client.GenerateAddress(wh)
	asser.NoError(err)

	// Fund the manager, freeze, clawback, and extra, so they can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(account0, manager, 0, 10000000000, nil)
	asser.NoError(err)
	return
}

func submitAndWaitForTransaction(sender string, tx transactions.Transaction, message string,
	client *libgoal.Client,
	fixture *fixtures.RestClientFixture,
	asser *require.Assertions) {

	txids := make(map[string]string)

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err := client.GetUnencryptedWalletHandle()

	txid, err := helperFillSignBroadcast(*client, wh, sender, tx, err)
	asser.NoError(err)
	txids[txid] = sender

	nodeStatus, _ := client.Status()
	confirmed := fixture.WaitForAllTxnsToConfirm(nodeStatus.LastRound+20, txids)
	asser.True(confirmed, message)
}

func verifyAssetParameters(asset model.AssetParams,
	unitName, assetName, manager, reserve, freeze, clawback string,
	metadataHash []byte, assetURL string, asser *require.Assertions) {

	asser.Equal(*asset.UnitName, unitName)
	asser.Equal(*asset.Name, assetName)
	asser.Equal(*asset.Manager, manager)
	asser.Equal(*asset.Reserve, reserve)
	asser.Equal(*asset.Freeze, freeze)
	asser.Equal(*asset.Clawback, clawback)
	asser.Equal(*asset.MetadataHash, metadataHash)
	asser.Equal(*asset.Url, assetURL)
}
