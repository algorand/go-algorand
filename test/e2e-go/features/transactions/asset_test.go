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
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
   "github.com/algorand/go-algorand/testPartitioning"
)

type assetIDParams struct {
	idx    uint64
	params v1.AssetParams
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
   testPartitioning.PartitionTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient

	// First, test valid rounds to last valid conversion
	var firstValid, lastValid, validRounds uint64
	firstValid = 0
	lastValid = 0
	validRounds = 0

	params, err := client.SuggestedParams()
	a.NoError(err)
	cparams, ok := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
	a.True(ok)

	firstValid = 0
	lastValid = 0
	validRounds = cparams.MaxTxnLife + 1
	firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.NoError(err)
	a.Equal(params.LastRound+1, firstValid)
	a.Equal(firstValid+cparams.MaxTxnLife, lastValid)

	firstValid = 0
	lastValid = 0
	validRounds = cparams.MaxTxnLife + 2
	firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "cannot construct transaction: txn validity period"))

	firstValid = 0
	lastValid = 0
	validRounds = 1
	firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.NoError(err)
	a.Equal(firstValid, lastValid)

	firstValid = 1
	lastValid = 0
	validRounds = 1
	firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.NoError(err)
	a.Equal(uint64(1), firstValid)
	a.Equal(firstValid, lastValid)

	firstValid = 1
	lastValid = 0
	validRounds = cparams.MaxTxnLife
	firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.NoError(err)
	a.Equal(uint64(1), firstValid)
	a.Equal(cparams.MaxTxnLife, lastValid)

	firstValid = 100
	lastValid = 0
	validRounds = cparams.MaxTxnLife
	firstValid, lastValid, err = client.ComputeValidityRounds(firstValid, lastValid, validRounds)
	a.NoError(err)
	a.Equal(uint64(100), firstValid)
	a.Equal(firstValid+cparams.MaxTxnLife-1, lastValid)

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
	a.NotEqual(basics.Round(0), tx.FirstValid)

	params, err = client.SuggestedParams()
	a.NoError(err)
	lastRoundAfter := params.LastRound

	// ledger may advance between SuggestedParams and FillUnsignedTxTemplate calls
	// expect validity sequence
	var firstValidRange, lastValidRange []uint64
	for i := lastRoundBefore + 1; i <= lastRoundAfter+1; i++ {
		firstValidRange = append(firstValidRange, i)
		lastValidRange = append(lastValidRange, i+cparams.MaxTxnLife)
	}
	a.Contains(firstValidRange, uint64(tx.FirstValid))
	a.Contains(lastValidRange, uint64(tx.LastValid))

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
	a.Equal(basics.Round(cparams.MaxTxnLife+1), tx.LastValid)
}

func TestAssetConfig(t *testing.T) {
   testPartitioning.PartitionTest(t)

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
	info, err := client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 0)

	// Create max number of assets
	txids := make(map[string]string)
	for i := 0; i < config.Consensus[protocol.ConsensusFuture].MaxAssetsPerAccount; i++ {
		// re-generate wh, since this test takes a while and sometimes
		// the wallet handle expires.
		wh, err = client.GetUnencryptedWalletHandle()
		a.NoError(err)

		tx, err := client.MakeUnsignedAssetCreateTx(1+uint64(i), false, manager, reserve, freeze, clawback, fmt.Sprintf("test%d", i), fmt.Sprintf("testname%d", i), assetURL, assetMetadataHash, 0)
		txid, err := helperFillSignBroadcast(client, wh, account0, tx, err)
		a.NoError(err)
		txids[txid] = account0

		// Travis is slow, so help it along by waiting every once in a while
		// for these transactions to commit..
		if (i % 50) == 0 {
			_, curRound := fixture.GetBalanceAndRound(account0)
			confirmed := fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
			a.True(confirmed)
			txids = make(map[string]string)
		}
	}

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "creating max number of assets")

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)

	// Creating more assets should return an error
	tx, err := client.MakeUnsignedAssetCreateTx(1, false, manager, reserve, freeze, clawback, fmt.Sprintf("toomany"), fmt.Sprintf("toomany"), assetURL, assetMetadataHash, 0)
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "too many assets in account:"))

	// Check that assets are visible
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), config.Consensus[protocol.ConsensusFuture].MaxAssetsPerAccount)
	var assets []assetIDParams
	for idx, cp := range info.AssetParams {
		assets = append(assets, assetIDParams{idx, cp})
		a.Equal(cp.UnitName, fmt.Sprintf("test%d", cp.Total-1))
		a.Equal(cp.AssetName, fmt.Sprintf("testname%d", cp.Total-1))
		a.Equal(cp.ManagerAddr, manager)
		a.Equal(cp.ReserveAddr, reserve)
		a.Equal(cp.FreezeAddr, freeze)
		a.Equal(cp.ClawbackAddr, clawback)
		a.Equal(cp.MetadataHash, assetMetadataHash)
		a.Equal(cp.URL, assetURL)
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

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "changing keys")

	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), config.Consensus[protocol.ConsensusFuture].MaxAssetsPerAccount)
	for idx, cp := range info.AssetParams {
		a.Equal(cp.UnitName, fmt.Sprintf("test%d", cp.Total-1))
		a.Equal(cp.AssetName, fmt.Sprintf("testname%d", cp.Total-1))

		if idx == assets[0].idx {
			a.Equal(cp.ManagerAddr, account0)
		} else {
			a.Equal(cp.ManagerAddr, manager)
		}

		if idx == assets[1].idx {
			a.Equal(cp.ReserveAddr, account0)
		} else if idx == assets[4].idx {
			a.Equal(cp.ReserveAddr, "")
		} else {
			a.Equal(cp.ReserveAddr, reserve)
		}

		if idx == assets[2].idx {
			a.Equal(cp.FreezeAddr, account0)
		} else if idx == assets[5].idx {
			a.Equal(cp.FreezeAddr, "")
		} else {
			a.Equal(cp.FreezeAddr, freeze)
		}

		if idx == assets[3].idx {
			a.Equal(cp.ClawbackAddr, account0)
		} else if idx == assets[6].idx {
			a.Equal(cp.ClawbackAddr, "")
		} else {
			a.Equal(cp.ClawbackAddr, clawback)
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
	for idx := range info.AssetParams {
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

		// Travis is slow, so help it along by waiting every once in a while
		// for these transactions to commit..
		if (idx % 50) == 0 {
			_, curRound = fixture.GetBalanceAndRound(account0)
			confirmed = fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
			a.True(confirmed)
			txids = make(map[string]string)
		}
	}

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
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
   testPartitioning.PartitionTest(t)

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

	// Fund the manager, so it can issue transactions later on
	_, err = client.SendPaymentFromUnencryptedWallet(account0, manager, 0, 10000000000, nil)
	a.NoError(err)

	// There should be no assets to start with
	info, err := client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 0)

	// There should be no assets to start with
	info2, err := client.AccountInformationV2(account0)
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
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	for idx, cp := range info.AssetParams {
		assetInfo, err := client.AssetInformation(idx)
		a.NoError(err)
		a.Equal(cp, assetInfo)
	}

	// Check that AssetInformationV2 returns the correct AssetParams
	info2, err = client.AccountInformationV2(account0)
	a.NoError(err)
	a.NotNil(info2.CreatedAssets)
	for _, cp := range *info2.CreatedAssets {
		asset, err := client.AssetInformationV2(cp.Index)
		a.NoError(err)
		a.Equal(cp, asset)
	}

	// Destroy assets
	txids = make(map[string]string)
	for idx := range info.AssetParams {
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
   testPartitioning.PartitionTest(t)

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

	txCount := uint64(0)
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

	assetID1 := txCount + 1
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

	assetID3 := txCount + 1
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

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed)

	txids = make(map[string]string)

	// asset 1 (create + send) exists and available
	assetParams, err := client1.AssetInformation(assetID1)
	a.NoError(err)
	a.Equal(assetName1, assetParams.AssetName)
	a.Equal(assetUnitName1, assetParams.UnitName)
	a.Equal(account0, assetParams.Creator)
	a.Equal(assetTotal, assetParams.Total)
	// sending it should succeed
	txSend, err = client0.MakeUnsignedAssetSendTx(assetID1, 1, account1, "", "")
	txid, err := helperFillSignBroadcast(client0, wh0, account0, txSend, err)
	a.NoError(err)
	txids[txid] = account0

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+5, txids)
	a.True(confirmed)

	// asset 3 (create + destroy) not available
	_, err = client1.AssetInformation(assetID3)
	a.Error(err)
	// sending it should fail
	txSend, err = client1.MakeUnsignedAssetSendTx(assetID3, 0, account1, "", "")
	txid, err = helperFillSignBroadcast(client1, wh1, account1, txSend, err)
	a.Error(err)
}

func TestAssetSend(t *testing.T) {
   testPartitioning.PartitionTest(t)

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

	info, err := client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 2)
	var frozenIdx, nonFrozenIdx uint64
	for idx, cp := range info.AssetParams {
		if cp.UnitName == "frozen" {
			frozenIdx = idx
		}

		if cp.UnitName == "nofreeze" {
			nonFrozenIdx = idx
		}
	}

	// An account with no algos should not be able to accept assets
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 0, extra, "", "")
	txid, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)

	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 0, extra, "", "")
	txid, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "overspend"))
	a.True(strings.Contains(err.Error(), "tried to spend"))

	// Fund the account: extra
	tx, err = client.SendPaymentFromUnencryptedWallet(account0, extra, 0, 10000000000, nil)
	a.NoError(err)
	_, curRound = fixture.GetBalanceAndRound(account0)
	fixture.WaitForConfirmedTxn(curRound+20, account0, tx.ID().String())

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

	info, err = client.AccountInformation(extra)
	a.NoError(err)
	a.Equal(len(info.Assets), 2)
	a.Equal(info.Assets[frozenIdx].Amount, uint64(0))
	a.Equal(info.Assets[frozenIdx].Frozen, true)
	a.Equal(info.Assets[nonFrozenIdx].Amount, uint64(10))
	a.Equal(info.Assets[nonFrozenIdx].Frozen, false)

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
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.Assets), 2)
	a.Equal(info.Assets[frozenIdx].Amount, uint64(95))
	a.Equal(info.Assets[nonFrozenIdx].Amount, uint64(95))

	info, err = client.AccountInformation(extra)
	a.NoError(err)
	a.Equal(len(info.Assets), 2)
	a.Equal(info.Assets[frozenIdx].Amount, uint64(5))
	a.Equal(info.Assets[nonFrozenIdx].Amount, uint64(5))

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
   testPartitioning.PartitionTest(t)

	a, fixture, client, account0 := setupTestAndNetwork(t, "", nil)
	defer fixture.Shutdown()

	// There should be no assets to start with
	info, err := client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 0)

	manager, reserve, freeze, clawback := setupActors(account0, client, a)
	createAsset("test", account0, manager, reserve, freeze, clawback, client, fixture, a)

	// Check that asset is visible
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 1)
	var asset v1.AssetParams
	var assetIndex uint64
	for idx, cp := range info.AssetParams {
		asset = cp
		assetIndex = idx
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
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 1)
	for idx, cp := range info.AssetParams {
		asset = cp
		assetIndex = idx
	}
	verifyAssetParameters(asset, "test", "testunit", manager, reserve, freeze, clawback,
		assetMetadataHash, assetURL, a)

	// Destroy the asset
	tx, err := client.MakeUnsignedAssetDestroyTx(assetIndex)
	submitAndWaitForTransaction(manager, tx, "destroying assets", client, fixture, a)

	// Check again that asset is destroyed
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 0)

	// Should be able to close now
	wh, err := client.GetUnencryptedWalletHandle()
	_, err = client.SendPaymentFromWallet(wh, nil, account0, "", 0, 0, nil, reserve, 0, 0)
	a.NoError(err)
}

func TestAssetCreateWaitBalLookbackDelete(t *testing.T) {
   testPartitioning.PartitionTest(t)

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

	configurableConsensus[consensusVersion] = consensusParams

	a, fixture, client, account0 := setupTestAndNetwork(t, "TwoNodes50EachTestShorterLookback.json", configurableConsensus)
	defer fixture.Shutdown()

	// There should be no assets to start with
	info, err := client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 0)

	manager, reserve, freeze, clawback := setupActors(account0, client, a)
	createAsset("test", account0, manager, reserve, freeze, clawback, client, fixture, a)

	// Check that asset is visible
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 1)
	var asset v1.AssetParams
	var assetIndex uint64
	for idx, cp := range info.AssetParams {
		asset = cp
		assetIndex = idx
	}

	assetURL := "foo://bar"
	assetMetadataHash := []byte("ISTHISTHEREALLIFEISTHISJUSTFANTA")

	verifyAssetParameters(asset, "test", "testunit", manager, reserve, freeze, clawback,
		assetMetadataHash, assetURL, a)

	//  Wait more than lookback rounds
	_, curRound := fixture.GetBalanceAndRound(account0)
	nodeStatus, _ := client.Status()
	consParams, err := client.ConsensusParams(nodeStatus.LastRound)
	err = fixture.WaitForRoundWithTimeout(curRound + consParams.MaxBalLookback + 1)
	a.NoError(err)

	// Check again that asset is visible
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 1)
	for idx, cp := range info.AssetParams {
		asset = cp
		assetIndex = idx
	}
	verifyAssetParameters(asset, "test", "testunit", manager, reserve, freeze, clawback,
		assetMetadataHash, assetURL, a)

	// Destroy the asset
	tx, err := client.MakeUnsignedAssetDestroyTx(assetIndex)
	submitAndWaitForTransaction(manager, tx, "destroying assets", client, fixture, a)

	// Check again that asset is destroyed
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 0)

	// Should be able to close now
	wh, err := client.GetUnencryptedWalletHandle()
	_, err = client.SendPaymentFromWallet(wh, nil, account0, "", 0, 0, nil, reserve, 0, 0)
	a.NoError(err)
}

/** Helper functions **/

// Setup the test and the network
func setupTestAndNetwork(t *testing.T, networkTemplate string, consensus config.ConsensusProtocols) (
	Assertions *require.Assertions, Fixture *fixtures.RestClientFixture, Client *libgoal.Client, Account0 string) {

	t.Parallel()
	asser := require.New(fixtures.SynchronizedTest(t))
	if 0 == len(networkTemplate) {
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

func verifyAssetParameters(asset v1.AssetParams,
	unitName, assetName, manager, reserve, freeze, clawback string,
	metadataHash []byte, assetURL string, asser *require.Assertions) {

	asser.Equal(asset.UnitName, "test")
	asser.Equal(asset.AssetName, "testunit")
	asser.Equal(asset.ManagerAddr, manager)
	asser.Equal(asset.ReserveAddr, reserve)
	asser.Equal(asset.FreezeAddr, freeze)
	asser.Equal(asset.ClawbackAddr, clawback)
	asser.Equal(asset.MetadataHash, metadataHash)
	asser.Equal(asset.URL, assetURL)
}
