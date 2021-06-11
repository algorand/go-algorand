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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
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

func TestAssetValidRounds(t *testing.T) {
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// createTestAssets creates MaxAssetsPerAccount assets
func createTestAssets(a *require.Assertions, fixture *fixtures.RestClientFixture, numAssets int, account0 string, manager string, reserve string, freeze string, clawback string, assetURL string, assetMetadataHash []byte, maxTxnGroupSize int, totals uint64) {
	txids := make(map[string]string)
	client := fixture.LibGoalClient
	i := 1
	for i <= numAssets {
		// re-generate wh, since this test takes a while and sometimes
		// the wallet handle expires.
		wh, err := client.GetUnencryptedWalletHandle()
		a.NoError(err)

		groupSize := min(maxTxnGroupSize, numAssets+1-i)

		if groupSize == 1 {
			total := uint64(i)
			unitName := fmt.Sprintf("test%d", i)
			assetName := fmt.Sprintf("testname%d", i)
			if totals != 0 {
				total = totals
			}

			tx, err := client.MakeUnsignedAssetCreateTx(total, false, manager, reserve, freeze, clawback, unitName, assetName, assetURL, assetMetadataHash, 0)
			a.NoError(err)
			txid, err := helperFillSignBroadcast(client, wh, account0, tx, err)
			a.NoError(err)
			txids[txid] = account0
		} else {
			txns := make([]transactions.Transaction, 0, groupSize)
			stxns := make([]transactions.SignedTxn, 0, groupSize)
			for j := 0; j < groupSize; j++ {
				total := uint64(i + j)
				unitName := fmt.Sprintf("test%d", i+j)
				assetName := fmt.Sprintf("testname%d", i+j)
				if totals != 0 {
					total = totals
				}
				tx, err := client.MakeUnsignedAssetCreateTx(total, false, manager, reserve, freeze, clawback, unitName, assetName, assetURL, assetMetadataHash, 0)
				a.NoError(err)
				tx, err = client.FillUnsignedTxTemplate(account0, 0, 0, 1000000, tx)
				a.NoError(err)
				txns = append(txns, tx)
			}
			gid, err := client.GroupID(txns)
			a.NoError(err)
			for j := 0; j < groupSize; j++ {
				txns[j].Group = gid
				stxn, err := client.SignTransactionWithWallet(wh, nil, txns[j])
				a.NoError(err)
				stxns = append(stxns, stxn)
				txids[stxn.ID().String()] = account0
			}
			err = client.BroadcastTransactionGroup(stxns)
			a.NoError(err)
		}
		// Travis is slow, so help it along by waiting every once in a while
		// for these transactions to commit..
		if (i % 50) == 0 {
			_, curRound := fixture.GetBalanceAndRound(account0)
			confirmed := fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
			a.True(confirmed)
			txids = make(map[string]string)
		}
		i += groupSize
	}

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "creating max number of assets")

	return
}

func checkTestAssets(a *require.Assertions, client *libgoal.Client, count int, account0 string, manager string, reserve string, freeze string, clawback string, assetURL string, assetMetadataHash []byte) (assets []assetIDParams) {
	info, err := client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(count, len(info.AssetParams))
	for idx, cp := range info.AssetParams {
		assets = append(assets, assetIDParams{idx, cp})
		a.Equal(cp.UnitName, fmt.Sprintf("test%d", cp.Total))
		a.Equal(cp.AssetName, fmt.Sprintf("testname%d", cp.Total))
		a.Equal(cp.ManagerAddr, manager)
		a.Equal(cp.ReserveAddr, reserve)
		a.Equal(cp.FreezeAddr, freeze)
		a.Equal(cp.ClawbackAddr, clawback)
		a.Equal(cp.MetadataHash, assetMetadataHash)
		a.Equal(cp.URL, assetURL)
	}
	return
}

func TestAssetConfig(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachV27.json"))
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
	numAssets := config.Consensus[protocol.ConsensusV27].MaxAssetsPerAccount
	createTestAssets(a, &fixture, numAssets, account0, manager, reserve, freeze, clawback, assetURL, assetMetadataHash, config.Consensus[protocol.ConsensusV27].MaxTxGroupSize, 0)

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)

	// Creating more assets should return an error
	tx, err := client.MakeUnsignedAssetCreateTx(1, false, manager, reserve, freeze, clawback, fmt.Sprintf("toomany"), fmt.Sprintf("toomany"), assetURL, assetMetadataHash, 0)
	a.NoError(err)
	_, err = helperFillSignBroadcast(client, wh, account0, tx, err)
	a.Error(err)
	a.True(strings.Contains(err.Error(), "too many assets in account:"))

	// Check that assets are visible
	assets := checkTestAssets(a, &client, config.Consensus[protocol.ConsensusV27].MaxAssetsPerAccount, account0, manager, reserve, freeze, clawback, assetURL, assetMetadataHash)

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)

	// Test changing various keys
	var empty string
	txids := make(map[string]string)

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

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
	a.True(confirmed, "changing keys")

	info, err = client.AccountInformation(account0)
	a.NoError(err)
	a.Equal(len(info.AssetParams), config.Consensus[protocol.ConsensusV27].MaxAssetsPerAccount)
	for idx, cp := range info.AssetParams {
		a.Equal(cp.UnitName, fmt.Sprintf("test%d", cp.Total))
		a.Equal(cp.AssetName, fmt.Sprintf("testname%d", cp.Total))

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
	txids = make(map[string]string, len(info.AssetParams))
	params := config.Consensus[protocol.ConsensusV27]
	// flatten in order to send in groups
	type flatten struct {
		idx    uint64
		params v1.AssetParams
	}
	assetParams := make([]flatten, 0, len(info.AssetParams))
	for idx, params := range info.AssetParams {
		assetParams = append(assetParams, flatten{idx, params})
	}
	i := 0
	for i < len(assetParams) {
		// re-generate wh, since this test takes a while and sometimes
		// the wallet handle expires.
		wh, err = client.GetUnencryptedWalletHandle()
		a.NoError(err)

		groupSize := min(params.MaxTxGroupSize, len(assetParams)-i)
		if groupSize == 1 {
			tx, err := client.MakeUnsignedAssetDestroyTx(assetParams[i].idx)
			sender := manager
			if assetParams[i].idx == assets[0].idx {
				sender = account0
			}
			txid, err := helperFillSignBroadcast(client, wh, sender, tx, err)
			a.NoError(err)
			txids[txid] = sender
		} else {
			txns := make([]transactions.Transaction, 0, groupSize)
			stxns := make([]transactions.SignedTxn, 0, groupSize)
			for j := 0; j < groupSize; j++ {
				tx, err := client.MakeUnsignedAssetDestroyTx(assetParams[i+j].idx)
				a.NoError(err)
				sender := manager
				if assetParams[i+j].idx == assets[0].idx {
					sender = account0
				}
				tx, err = client.FillUnsignedTxTemplate(sender, 0, 0, 1000000, tx)
				a.NoError(err)
				txns = append(txns, tx)
			}
			gid, err := client.GroupID(txns)
			a.NoError(err)
			for j := 0; j < groupSize; j++ {
				txns[j].Group = gid
				stxn, err := client.SignTransactionWithWallet(wh, nil, txns[j])
				a.NoError(err)
				stxns = append(stxns, stxn)
				txids[stxn.ID().String()] = stxn.Txn.Sender.String()
			}
			err = client.BroadcastTransactionGroup(stxns)
			a.NoError(err)
		}

		// Travis is slow, so help it along by waiting every once in a while
		// for these transactions to commit..
		if (i % 50) == 0 {
			_, curRound = fixture.GetBalanceAndRound(account0)
			confirmed = fixture.WaitForAllTxnsToConfirm(curRound+20, txids)
			a.True(confirmed)
			txids = make(map[string]string)
		}
		i += groupSize
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

// TestAssetConfigUnlimited is similar to TestAssetConfig
// and checks MaxAssetsPerAccount+1 are OK
func TestAssetConfigUnlimited(t *testing.T) {
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
	numAssets := config.Consensus[protocol.ConsensusFuture].MaxAssetsPerAccount
	createTestAssets(a, &fixture, numAssets, account0, manager, reserve, freeze, clawback, assetURL, assetMetadataHash, config.Consensus[protocol.ConsensusFuture].MaxTxGroupSize, 0)

	// re-generate wh, since this test takes a while and sometimes
	// the wallet handle expires.
	wh, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)

	// Creating more assets should not return an error
	tx, err := client.MakeUnsignedAssetCreateTx(uint64(numAssets+1), false, manager, reserve, freeze, clawback, fmt.Sprintf("test%d", numAssets+1), fmt.Sprintf("testname%d", numAssets+1), assetURL, assetMetadataHash, 0)
	a.NoError(err)
	txid, err := helperFillSignBroadcast(client, wh, account0, tx, err)
	a.NoError(err)

	_, curRound := fixture.GetBalanceAndRound(account0)
	confirmed := fixture.WaitForAllTxnsToConfirm(curRound+5, map[string]string{txid: account0})
	a.True(confirmed)

	// Check that assets are visible
	checkTestAssets(a, &client, numAssets+1, account0, manager, reserve, freeze, clawback, assetURL, assetMetadataHash)
}

func TestAssetInformation(t *testing.T) {
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

type logEntry struct {
	aidx   uint64
	amount uint64
	from   string
	to     string
}
type assetTxnGroupSenderInfo struct {
	a       *require.Assertions
	fixture *fixtures.RestClientFixture
	gs      int
}

type assetTxnGroupLogger struct {
	assetTxnGroupSenderInfo
	file    *os.File
	entries []logEntry
}

type assetTxnGroupSender struct {
	assetTxnGroupSenderInfo
	txns  []transactions.Transaction
	txids []map[string]string
	fee   uint64
}

func makeAssetTxnGroupSender(a *require.Assertions, f *fixtures.RestClientFixture, groupSize int) assetTxnGroupSender {
	sender := assetTxnGroupSender{
		assetTxnGroupSenderInfo: assetTxnGroupSenderInfo{
			a:       a,
			fixture: f,
			gs:      groupSize,
		},
		txns:  make([]transactions.Transaction, 0, groupSize),
		txids: []map[string]string{},
		fee:   100000,
	}

	return sender
}

func makeAssetTxnGroupLogger(a *require.Assertions, f *fixtures.RestClientFixture, groupSize int, logname string) assetTxnGroupLogger {
	file, err := os.OpenFile(logname, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	a.NoError(err)
	logger := assetTxnGroupLogger{
		assetTxnGroupSenderInfo: assetTxnGroupSenderInfo{
			a:       a,
			fixture: f,
			gs:      groupSize,
		},
		file:    file,
		entries: make([]logEntry, 0, groupSize),
	}

	return logger
}

type txnProcessor interface {
	addTxn(index uint64, amount uint64, from, to string)
	flush(wait bool)
}

func (s *assetTxnGroupSender) addTxn(index uint64, amount uint64, from, to string) {
	tx, err := s.fixture.LibGoalClient.MakeUnsignedAssetSendTx(index, amount, to, "", "")
	s.a.NoError(err)
	tx, err = s.fixture.LibGoalClient.FillUnsignedTxTemplate(from, 0, 0, s.fee, tx)
	s.a.NoError(err)

	var note [8]byte
	crypto.RandBytes(note[:])
	tx.Note = note[:]

	s.txns = append(s.txns, tx)

	if len(s.txns) >= s.gs {
		s.flush(false)
	}
}

func (s *assetTxnGroupSender) flush(wait bool) {
	wh, err := s.fixture.LibGoalClient.GetUnencryptedWalletHandle()
	s.a.NoError(err)
	flushThreshold := 48
	txids := make(map[string]string, flushThreshold)
	for len(s.txns) > 0 {
		groupSize := min(s.gs, len(s.txns))
		txns := s.txns[:groupSize]
		if groupSize == 1 {
			txid, err := s.fixture.LibGoalClient.SignAndBroadcastTransaction(wh, nil, txns[0])
			s.a.NoError(err)
			txids[txid] = txns[0].Sender.String()
		} else {
			gid, err := s.fixture.LibGoalClient.GroupID(txns)
			s.a.NoError(err)
			stxns := make([]transactions.SignedTxn, 0, groupSize)
			for j := 0; j < len(txns); j++ {
				txns[j].Group = gid
				stxn, err := s.fixture.LibGoalClient.SignTransactionWithWallet(wh, nil, txns[j])
				s.a.NoError(err)
				stxns = append(stxns, stxn)
				txids[stxn.ID().String()] = stxn.Txn.Sender.String()
			}
			err = s.fixture.LibGoalClient.BroadcastTransactionGroup(stxns)
			s.a.NoError(err, fmt.Sprintf("%d ids, group %d", len(s.txids), len(s.txns)))
		}
		s.txns = s.txns[groupSize:]

		if len(txids) >= flushThreshold {
			status, err := s.fixture.LibGoalClient.Status()
			s.a.NoError(err)
			confirmed := s.fixture.WaitForAllTxnsToConfirm(status.LastRound+20, txids)
			s.a.True(confirmed)
			wh, err = s.fixture.LibGoalClient.GetUnencryptedWalletHandle()
			s.a.NoError(err)
			txids = make(map[string]string)
		}
	}
	if len(txids) > 0 {
		s.txids = append(s.txids, txids)
	}

	const txnSize = 300
checkfee:
	feePerByte, err := s.fixture.LibGoalClient.SuggestedFee()
	s.a.NoError(err)
	feeTooHigh := feePerByte*txnSize >= uint64(float64(s.fee)*0.3)

	if len(s.txids) > 0 && (wait || feeTooHigh) {
		txids = s.txids[len(s.txids)-1]
		status, err := s.fixture.LibGoalClient.Status()
		s.a.NoError(err)

		timeoutRound := status.LastRound + 20
		for txid, addr := range txids {
			txn, err := s.fixture.WaitForConfirmedTxn(status.LastRound+20, addr, txid)
			if err != nil {
				fmt.Printf("Failed to confirm txn (%d, %d) at %d: %s", txn.FirstRound, txn.LastRound, timeoutRound, err.Error())
			}
		}
		s.txids = s.txids[:len(s.txids)-1]
		if feeTooHigh {
			goto checkfee
		}
		// all confirmed, clean
		s.txids = s.txids[:0]
	}
}

func (s *assetTxnGroupLogger) addTxn(index uint64, amount uint64, from, to string) {
	s.entries = append(s.entries, logEntry{index, amount, from, to})
	if len(s.entries) > s.gs {
		s.flush(false)
	}
}

func (s *assetTxnGroupLogger) flush(wait bool) {
	for _, entry := range s.entries {
		fmt.Fprintf(s.file, "%d %d %s %s\n", entry.aidx, entry.amount, entry.from, entry.to)
	}
	s.entries = s.entries[:0]
}

// performRandomTransfers runs asset transactions according to the algorithm:
// create maxAssets per account for a half of accounts
// opt-in all accounts into all created assets
// execute 10k * 1024 random transfers of these assets
func performRandomTransfers(a *require.Assertions, r *rand.Rand, groupSize int, maxIterations int, maxAssets int, f *fixtures.RestClientFixture, addresses []string, txnProcessor txnProcessor) {
	const (
		escapeCursorUp   = string("\033[A") // Cursor Up
		escapeDeleteLine = string("\033[M") // Delete Line
		escapeSquare     = string("▪")
		escapeDot        = string("·")

		barWidth = 50
	)

	printProgress := func(progress int, barLength int, dld int64, status string) {
		if barLength == 0 {
			fmt.Printf(escapeCursorUp+escapeDeleteLine+"[ Done %s ]\n\n", status)
			return
		}

		outString := "[" + strings.Repeat(escapeSquare, progress) + strings.Repeat(escapeDot, barLength-progress) + fmt.Sprintf("] %s...", status)
		if dld > 0 {
			outString = fmt.Sprintf(outString+" %d", dld)
		}
		fmt.Printf(escapeCursorUp + escapeDeleteLine + outString + "\n")
	}

	const numTransfers = 1024

	client := f.LibGoalClient

	for i := 0; i < len(addresses)/2; i++ {
		addr := addresses[i]
		createTestAssets(a, f, maxAssets, addr, addr, addr, addr, addr, "", []byte{}, groupSize, uint64(maxIterations*numTransfers*numTransfers))
	}

	assetCreators := make(map[uint64]string, maxAssets*len(addresses)/2)
	creators := make(map[string]map[uint64]bool, len(addresses)/2)
	holders := make(map[string]map[uint64]bool, len(addresses))
	assetHolders := make(map[uint64][]string, maxAssets*len(addresses)/2)
	assets := make([]uint64, 0, maxAssets*len(addresses)/2)

	for i := 0; i < len(addresses)/2; i++ {
		addr := addresses[i]
		info, err := client.AccountInformation(addr)
		a.NoError(err)
		a.Equal(maxAssets, len(info.AssetParams))
		a.Equal(maxAssets, len(info.Assets))
		creators[addr] = make(map[uint64]bool, maxAssets)
		for idx := range info.AssetParams {
			assetCreators[idx] = addr
			creators[addr][idx] = true
			assets = append(assets, uint64(idx))
		}
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i] < assets[j] })

	for i := len(addresses) / 2; i < len(addresses); i++ {
		addr := addresses[i]
		info, err := client.AccountInformation(addr)
		a.NoError(err)
		a.Equal(0, len(info.AssetParams))
		a.Equal(0, len(info.Assets))
	}

	// opt-in all to some assets
	for i := 0; i < len(addresses); i++ {
		addr := addresses[i]
		ownAssets := creators[addr]
		if len(ownAssets) >= maxAssets {
			// holding slots occupied by own holdings
			continue
		}
		optedInAssets := make(map[uint64]bool, maxAssets)
		s := makeAssetTxnGroupSender(a, f, groupSize)
		for j := 0; j < maxAssets; j++ {
		repeat:
			idx := assets[r.Intn(len(assets))]
			if ownAssets[idx] || optedInAssets[idx] {
				goto repeat
			}
			s.addTxn(idx, 0, addr, addr)
			optedInAssets[idx] = true
		}
		wait := false
		if i == len(addresses)-1 {
			wait = true
		}
		s.flush(wait)
		holders[addr] = optedInAssets
		for idx := range optedInAssets {
			var list []string
			var ok bool
			if list, ok = assetHolders[idx]; !ok {
				list = make([]string, 0, maxAssets)
			}
			list = append(list, addr)
			assetHolders[idx] = list
		}
		ratio := float64(i*barWidth) / float64(len(addresses))
		printProgress(int(ratio), barWidth, int64(i), "Opting-in")
	}
	printProgress(0, 0, 0, "Opting-in")

	// for i := 0; i < len(addresses); i++ {
	// 	addr := addresses[i]
	// 	ownAssets := creators[addr]
	// 	optedInAssets := holders[addr]
	// 	fmt.Printf("%s %d %d\n", addr, len(ownAssets), len(optedInAssets))
	// }

	for i := 0; i < len(addresses)/2; i++ {
		addr := addresses[i]
		info, err := client.AccountInformation(addr)
		a.NoError(err)
		a.Equal(maxAssets, len(info.AssetParams))
		a.Equal(maxAssets, len(info.Assets))
	}
	for i := len(addresses) / 2; i < len(addresses); i++ {
		addr := addresses[i]
		info, err := client.AccountInformation(addr)
		a.NoError(err)
		a.Equal(0, len(info.AssetParams))
		a.LessOrEqual(len(info.Assets), maxAssets)
	}

	fmt.Printf("Opted in %d out of %d assets\n\n", len(assetHolders), len(assets))

	acctHoldings := make([]int, len(addresses))
	acctParams := make([]int, len(addresses))
	for i := 0; i < len(addresses); i++ {
		addr := addresses[i]
		info, err := client.AccountInformation(addr)
		if err != nil {
			fmt.Printf("Failed at %s\n", addr)
		}
		a.NoError(err)
		acctHoldings[i] = len(info.Assets)
		acctParams[i] = len(info.AssetParams)
	}

	acctBelow := 0
	acctEq := 0
	acctAbove := 0
	for _, count := range acctHoldings {
		if count < maxAssets {
			acctBelow++
		} else if count == maxAssets {
			acctEq++
		} else {
			acctAbove++
		}
	}

	fmt.Printf("%d accounts with less than %d holdings\n", acctBelow, maxAssets)
	fmt.Printf("%d accounts with eq to %d holdings\n", acctEq, maxAssets)
	fmt.Printf("%d accounts with more than %d holdings\n", acctAbove, maxAssets)

	acctBelow = 0
	acctEq = 0
	acctAbove = 0
	for _, count := range acctParams {
		if count < maxAssets {
			acctBelow++
		} else if count == maxAssets {
			acctEq++
		} else {
			acctAbove++
		}
	}

	fmt.Printf("%d accounts with less than %d params\n", acctBelow, maxAssets)
	fmt.Printf("%d accounts with eq to %d params\n", acctEq, maxAssets)
	fmt.Printf("%d accounts with more than %d params\n", acctAbove, maxAssets)

	// run maxIterations series of random transfers
	for i := 0; i < maxIterations; i++ {
		for j := 0; j < numTransfers; j++ {
		retry:
			idx := assets[r.Intn(len(assets))]
			sender, ok := assetCreators[idx]
			a.True(ok)
			holders, ok := assetHolders[idx]
			if !ok || len(holders) < 2 {
				goto retry
			}
			receiver := holders[r.Intn(len(holders))]
			txnProcessor.addTxn(idx, 1, sender, receiver)
			ratio := float64(((i)*numTransfers+(j))*barWidth) / float64(maxIterations*numTransfers)
			printProgress(int(ratio), barWidth, int64(i), "Transfering")
		}
	}
	txnProcessor.flush(true)
	printProgress(0, 0, 0, "Transfering")

	if _, ok := txnProcessor.(*assetTxnGroupSender); ok {
		// grace period just in case for real sending
		time.Sleep(5 * time.Minute)
	}
}

func TestAsset2k(t *testing.T) {
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

	// use a fixed seed
	// generate random 32 uint8 numbers
	// shuffle into 128 account keys

	const seed = int64(100)
	const keyLenBytes = 32
	const groupSize = 16
	const numAccounts = 128
	const numIterations = 1000

	maxAssets := config.Consensus[protocol.ConsensusFuture].MaxAssetsPerAccount
	maxProtoAssets := config.Consensus[protocol.ConsensusFuture].MaxAssetsPerAccount
	branch := "feature"

	source := rand.NewSource(seed)
	r := rand.New(source)
	seq := make([]byte, keyLenBytes)
	for i := 0; i < len(seq); i++ {
		seq[i] = byte(r.Uint32())
	}

	keys := make([][]byte, numAccounts)
	addresses := make([]string, numAccounts)
	for i := 0; i < len(keys); i++ {
		keys[i] = make([]byte, len(seq))
		r.Shuffle(len(seq), func(i, j int) { seq[i], seq[j] = seq[j], seq[i] })
		copy(keys[i], seq)
		importedKey, err := client.ImportKey(wh, keys[i])
		a.NoError(err)
		addresses[i] = importedKey.Address
	}

	// fund these new accounts
	const balance = 10000000000
	for _, addr := range addresses {
		_, err = client.SendPaymentFromUnencryptedWallet(account0, addr, 0, balance, nil)
		a.NoError(err)
	}
	const maxRetries = 5
	retry := 0
	for retry < maxRetries {
		rnd, err := client.CurrentRound()
		a.NoError(err)
		_, err = client.WaitForRound(rnd + 2)
		a.NoError(err)
		bal, err := client.GetBalance(addresses[len(addresses)-1])
		a.NoError(err)
		if bal == balance {
			break
		}
		retry++
	}

	// create X assets per account for a half of accounts where X is a test parameter
	// X = MaxAssetsPerAccount for limited assets and 2k for unlimited
	// opt-in all accounts into all created accounts
	// execute 1000 * 1024 random transfers of these assets

	// txnLogFilename := fmt.Sprintf("%s-txn_log-branch_%s-assets_%d-proto_%d.txt", t.Name(), branch, maxAssets, maxProtoAssets)
	// processor := makeAssetTxnGroupLogger(a, &fixture, groupSize, txnLogFilename)

	processor := makeAssetTxnGroupSender(a, &fixture, groupSize)

	var txnProcessor txnProcessor = &processor
	performRandomTransfers(a, r, groupSize, numIterations, maxAssets, &fixture, addresses, txnProcessor)

	// dump account db
	if _, ok := txnProcessor.(*assetTxnGroupSender); ok {
		all := make([]generatedV2.Account, len(addresses))
		for i := 0; i < len(addresses); i++ {
			info, err := client.AccountInformationV2(addresses[i])
			a.NoError(err)
			all[i] = info
		}
		blob, err := json.Marshal(all)
		a.NoError(err)

		balancesFilename := fmt.Sprintf("%s-branch_%s-assets_%d-proto_%d.json", t.Name(), branch, maxAssets, maxProtoAssets)
		err = ioutil.WriteFile(balancesFilename, blob, 0644)
		a.NoError(err)
	} else if p, ok := txnProcessor.(*assetTxnGroupLogger); ok {
		p.file.Close()
	}

	// repeat for
	// master MaxAssetsPerAccount=1000 accounts vs feature branch
	// master MaxAssetsPerAccount=2000 accounts vs feature branch vs feature branch MaxAssetsPerAccount=1000
}
