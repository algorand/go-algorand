// Copyright (C) 2019 Algorand, Inc.
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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
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

func TestAssetConfig(t *testing.T) {
	t.Parallel()
	a := require.New(t)

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

		tx, err := client.MakeUnsignedAssetCreateTx(1+uint64(i), false, manager, reserve, freeze, clawback, fmt.Sprintf("test%d", i), fmt.Sprintf("testname%d", i), assetURL, assetMetadataHash)
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
	tx, err := client.MakeUnsignedAssetCreateTx(1, false, manager, reserve, freeze, clawback, fmt.Sprintf("toomany"), fmt.Sprintf("toomany"), assetURL, assetMetadataHash)
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)

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
	t.Parallel()
	a := require.New(t)

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

	// Create some assets
	txids := make(map[string]string)
	for i := 0; i < 16; i++ {
		tx, err := client.MakeUnsignedAssetCreateTx(1+uint64(i), false, manager, reserve, freeze, clawback, fmt.Sprintf("test%d", i), fmt.Sprintf("testname%d", i), "foo://bar", nil)
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

func TestAssetSend(t *testing.T) {
	t.Parallel()
	a := require.New(t)

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

	tx, err := client.MakeUnsignedAssetCreateTx(100, false, manager, reserve, freeze, clawback, "nofreeze", "xx", "foo://bar", nil)
	txid, err := helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)
	txids[txid] = account0

	tx, err = client.MakeUnsignedAssetCreateTx(100, true, manager, reserve, freeze, clawback, "frozen", "xx", "foo://bar", nil)
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
	txid, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.Error(err)

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

	// Clawback assets to an account that hasn't opted in should fail
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 1, extra, "", account0)
	_, err = helperFillSignBroadcast(client, wh, clawback, tx, err)
	a.Error(err)

	// opting in should be signed by the opting in account not sender
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 0, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)

	// Account hasn't opted in yet. sending will fail
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 1, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)

	// Account hasn't opted in yet. clawback to will fail
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 1, extra, "", account0)
	_, err = helperFillSignBroadcast(client, wh, clawback, tx, err)
	a.Error(err)

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

	// Should not be able to clawback more than is available
	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 11, account0, "", extra)
	_, err = helperFillSignBroadcast(client, wh, clawback, tx, err)
	a.Error(err)

	tx, err = client.MakeUnsignedAssetSendTx(nonFrozenIdx, 10, extra, "", "")
	_, err = helperFillSignBroadcast(client, wh, extra, tx, err)
	a.NoError(err)

	// Swap frozen status on the extra account (and the wrong address should not
	// be able to change frozen status)
	tx, err = client.MakeUnsignedAssetFreezeTx(nonFrozenIdx, extra, true)
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)

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
	t.Parallel()
	a := require.New(t)

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

	// Create the asset
	tx, err := client.MakeUnsignedAssetCreateTx(
		100,
		false,
		manager,
		reserve,
		freeze,
		clawback,
		"test",
		"testname", //%d",
		assetURL,
		assetMetadataHash)
	txid, err := helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)
	txids := make(map[string]string)
	txids[txid] = account0
	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "created the asset")

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
	a.Equal(asset.UnitName, "test")
	a.Equal(asset.AssetName, "testname")
	a.Equal(asset.ManagerAddr, manager)
	a.Equal(asset.ReserveAddr, reserve)
	a.Equal(asset.FreezeAddr, freeze)
	a.Equal(asset.ClawbackAddr, clawback)
	a.Equal(asset.MetadataHash, assetMetadataHash)
	a.Equal(asset.URL, assetURL)

	// restart the node
	fixture.ShutdownImpl(true) // shutdown but preserve the data
	fixture.Start()
	fixture.AlgodClient = fixture.GetAlgodClientForController(fixture.NC)
	client = fixture.LibGoalClient

	// Check again that asset is visible
	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), 1)
	for idx, cp := range info.AssetParams {
		asset = cp
		assetIndex = idx
	}
	a.Equal(asset.UnitName, "test")
	a.Equal(asset.AssetName, "testname")
	a.Equal(asset.ManagerAddr, manager)
	a.Equal(asset.ReserveAddr, reserve)
	a.Equal(asset.FreezeAddr, freeze)
	a.Equal(asset.ClawbackAddr, clawback)
	a.Equal(asset.MetadataHash, assetMetadataHash)
	a.Equal(asset.URL, assetURL)

	// Destroy the asset
	txids = make(map[string]string)
	tx, err = client.MakeUnsignedAssetDestroyTx(assetIndex)
	sender := manager

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err = client.GetUnencryptedWalletHandle()

	txid, err = helperFillSignBroadcast(client, wh, sender, tx, err)
	a.NoError(err)
	txids[txid] = sender

	_, curRound = fixture.GetBalanceAndRound(account0)
	confirmed = fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "destroying assets")

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err = client.GetUnencryptedWalletHandle()

	// Should be able to close now
	_, err = client.SendPaymentFromWallet(wh, nil, account0, "", 0, 0, nil, reserve, 0, 0)
	a.NoError(err)
}
