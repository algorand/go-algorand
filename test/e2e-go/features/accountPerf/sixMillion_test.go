// Copyright (C) 2019-2022 Algorand, Inc.
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

package fataccount

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	clientApi "github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const numberOfThreads = 256
const printFreequency = 400
const groupTransactions = true
const channelDepth = 100
const sixMillion = 6000000
const sixThousand = 6000
const verbose = false

var failTest bool
var maxTxGroupSize int

type psKey struct {
	sk *crypto.SignatureSecrets
	pk basics.Address
}

type txnKey struct {
	sk *crypto.SignatureSecrets
	tx transactions.Transaction
}

func broadcastTransactions(queueWg *sync.WaitGroup, c libgoal.Client, sigTxnChan <-chan *transactions.SignedTxn, errChan chan<- error) {
	for stxn := range sigTxnChan {
		if stxn == nil {
			break
		}
		var err error
		for x := 0; x < 50; x++ { // retry only 50 times
			_, err = c.BroadcastTransaction(*stxn)
			if err == nil {
				break
			}
			fmt.Printf("broadcastTransactions[%d]: %s", x, err)
			time.Sleep(time.Millisecond * 256)
		}
		if err != nil {
			handleError(err, "Error broadcastTransactions", errChan)
		}
	}
	queueWg.Done()
}

func broadcastTransactionGroups(queueWg *sync.WaitGroup, c libgoal.Client, sigTxnGrpChan <-chan []transactions.SignedTxn, errChan chan<- error) {
	for stxns := range sigTxnGrpChan {
		if stxns == nil {
			break
		}
		var err error
		for x := 0; x < 50; x++ { // retry only 50 times
			err = c.BroadcastTransactionGroup(stxns)
			if err == nil {
				if verbose {
					if stxns[0].Txn.ApplicationCallTxnFields.OnCompletion == transactions.OptInOC &&
						stxns[0].Txn.ApplicationCallTxnFields.ApplicationID == 0 {
						sender := stxns[0].Txn.Header.Sender
						info, _ := getAccountInformation(c, 0, 0, sender.String(), "broadcastTransactionGroups")
						for _, app := range *info.CreatedApps {
							fmt.Printf("created app: %d\n", app.Id)
						}
					}

					if stxns[0].Txn.ApplicationCallTxnFields.OnCompletion == transactions.OptInOC &&
						stxns[0].Txn.ApplicationCallTxnFields.ApplicationID > 0 {
						sender := stxns[0].Txn.Header.Sender
						for _, tx := range stxns {
							appId := tx.Txn.ApplicationCallTxnFields.ApplicationID
							_, err := getAccountApplicationInformation(c, sender.String(), uint64(appId), "broadcastTransactionGroups")
							fmt.Printf("bTG: %d\t %s\n", appId, sender)
							if err != nil {
								fmt.Printf("opt-in for appid %d failed! error %s\n\n", appId, err)
								continue
							}
						}
					}
				}
				break
			}
			fmt.Printf("broadcastTransactionGroups[%d]: %s\n", x, err)
			if strings.Contains(err.Error(), "already in ledger") {
				err = nil
				break
			}
			time.Sleep(time.Millisecond * 256)
		}
		if err != nil {
			handleError(err, "Error broadcastTransactionGroups", errChan)
		}
	}
	queueWg.Done()
}

func getAccountInformation(
	client libgoal.Client,
	expectedCountApps uint64,
	expectedCountAssets uint64,
	address string,
	context string) (info generated.Account, err error) {

	for x := 0; x < 50; x++ { // retry only 50 times
		info, err = client.AccountInformationV2(address, true)
		if err == nil {
			if expectedCount > 0 && int(expectedCount) != len(*info.CreatedApps) {
				fmt.Printf("Missing appsPerAccount: %s got: %d expected: %d\n", address, len(*info.CreatedApps), expectedCount)
				fmt.Printf("%s\n\n", spew.Sdump(info))
			if expectedCountApps > 0 && int(expectedCountApps) != len(*info.CreatedApps) {
				fmt.Printf("Missing appsPerAccount: %s got: %d expected: %d\n", address, len(*info.CreatedApps), expectedCountApps)
				fmt.Printf("%s\n\n", spew.Sdump(info))
				failTest = true
				continue
			}
			if expectedCountAssets > 0 && int(expectedCountAssets) != len(*info.CreatedAssets) {
				fmt.Printf("Missing assetsPerAccount: %s got: %d expected: %d\n", address, len(*info.CreatedAssets), expectedCountAssets)
				fmt.Printf("%s\n\n", spew.Sdump(info))
				failTest = true
				continue
			}
			break
		}
		fmt.Printf("AccountInformationV2 (%s) [%d]: %s\n", context, x, err)
		time.Sleep(time.Millisecond * 256)
	}
	return
}

func getAccountApplicationInformation(
	client libgoal.Client,
	address string,
	appId uint64,
	context string) (appInfo generated.AccountApplicationResponse, err error) {

	for x := 0; x < 50; x++ { // retry only 50 times
		appInfo, err = client.AccountApplicationInformation(address, appId)
		if err == nil {
			break
		}
		fmt.Printf("AccountApplicationInformation (%s) [%d]: %s\n", context, x, err)
		time.Sleep(time.Millisecond * 256)
	}
	return
}

func signer(
	sigWg *sync.WaitGroup,
	client libgoal.Client,
	txnChan <-chan *txnKey,
	sigTxnChan chan<- *transactions.SignedTxn,
	errChan chan<- error) {

	for tk := range txnChan {
		if tk == nil {
			continue
		}
		stxn := tk.tx.Sign(tk.sk)
		sigTxnChan <- &stxn
	}
	sigWg.Done()
}

func signerGrpTxn(
	sigWg *sync.WaitGroup,
	client libgoal.Client,
	txnGrpChan <-chan []txnKey,
	sigTxnGrpChan chan<- []transactions.SignedTxn,
	errChan chan<- error) {

	for tGroup := range txnGrpChan {

		// prepare the array of transactions for the group id
		sendTransactions := make([]transactions.Transaction, len(tGroup))
		for i, tk := range tGroup {
			sendTransactions[i] = tk.tx
		}
		// get the group id
		gid, err := client.GroupID(sendTransactions)
		handleError(err, "Error GroupID", errChan)

		// set the group id to each transaction
		for i, _ := range tGroup {
			sendTransactions[i].Group = gid
		}

		// sign the transactions
		stxns := make([]transactions.SignedTxn, len(tGroup))
		for i, tk := range tGroup {
			stxns[i] = sendTransactions[i].Sign(tk.sk)
		}

		sigTxnGrpChan <- stxns
	}
	sigWg.Done()
}

func Test5MAssetsScenario1(t *testing.T) {
	test5MAssets(t, 1)
}

func Test5MAssetsScenario2(t *testing.T) {
	test5MAssets(t, 2)
}

func Test5MAssetsScenario3(t *testing.T) {
	test5MAssets(t, 3)
}

func Test5MAssetsScenario4(t *testing.T) {
	test5MAssets(t, 4)
}

func test5MAssets(t *testing.T, scenario int) {
	partitiontest.PartitionTest(t)

	var fixture fixtures.RestClientFixture
	var sigWg sync.WaitGroup
	var queueWg sync.WaitGroup
	var hkWg sync.WaitGroup
	var errWatcherWg sync.WaitGroup

	maxTxGroupSize = config.Consensus[protocol.ConsensusCurrentVersion].MaxTxGroupSize
	fixture.Setup(t, filepath.Join("nettemplates", "DevModeOneWallet.json"))

	defer func() {
		hkWg.Wait()
		fixture.Shutdown()
	}()
	client := fixture.LibGoalClient

	accountList, err := fixture.GetWalletsSortedByBalance()
	require.NoError(t, err)
	// get the wallet account
	wAcct := accountList[0].Address

	suggestedParams, err := client.SuggestedParams()
	require.NoError(t, err)
	var genesisHash crypto.Digest
	copy(genesisHash[:], suggestedParams.GenesisHash)
	tLife := config.Consensus[protocol.ConsensusVersion(suggestedParams.ConsensusVersion)].MaxTxnLife

	// fund the non-wallet base account
	ba := generateKeys(1)
	baseAcct := ba[0]
	sender, err := basics.UnmarshalChecksumAddress(wAcct)
	satxn := sendAlgoTransaction(t, 0, sender, baseAcct.pk, 1000000000000000, 1, genesisHash)
	err = signAndBroadcastTransaction(0, &satxn, client, &fixture)
	require.NoError(t, err)

	txnChan := make(chan *txnKey, channelDepth)
	txnGrpChan := make(chan []txnKey, channelDepth)
	sigTxnChan := make(chan *transactions.SignedTxn, channelDepth)
	sigTxnGrpChan := make(chan []transactions.SignedTxn, channelDepth)
	errChan := make(chan error, channelDepth)
	stopChan := make(chan struct{}, 1)

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		sigWg.Add(1)
		if groupTransactions {
			go signerGrpTxn(&sigWg, client, txnGrpChan, sigTxnGrpChan, errChan)
		} else {
			go signer(&sigWg, client, txnChan, sigTxnChan, errChan)
		}
	}

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		queueWg.Add(1)
		if groupTransactions {
			go broadcastTransactionGroups(&queueWg, client, sigTxnGrpChan, errChan)
		} else {
			go broadcastTransactions(&queueWg, client, sigTxnChan, errChan)
		}
	}

	// error handling
	errWatcherWg.Add(1)
	go func() {
		errCount := 0
		for range errChan {
			errCount++
			if errCount > 1000 {
				fmt.Println("Too many errors!")
				stopChan <- struct{}{}
				break
			}
		}
		close(stopChan)
		errWatcherWg.Done()
	}()

	// some housekeeping
	hkWg.Add(1)
	go func() {
		sigWg.Wait()
		close(sigTxnChan)
		close(sigTxnGrpChan)
		queueWg.Wait()
		close(errChan)
		errWatcherWg.Wait()
		hkWg.Done()
	}()

	// Call different scenarios
	switch scenario {
	case 1:
		scenarioA(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan)
	case 2:
		scenarioB(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan)
	case 3:
		scenarioC(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan)
	case 4:
		scenarioD(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan)

	}
}

func generateKeys(numAccounts int) (keys []psKey) {
	keys = make([]psKey, 0, numAccounts)
	var seed crypto.Seed
	for a := 0; a < numAccounts; a++ {
		crypto.RandBytes(seed[:])
		privateKey := crypto.GenerateSignatureSecrets(seed)
		publicKey := basics.Address(privateKey.SignatureVerifier)
		keys = append(keys, psKey{pk: publicKey, sk: privateKey})
	}
	return
}

func sendAlgoTransaction(
	t *testing.T,
	round uint64,
	sender basics.Address,
	receiver basics.Address,
	amount uint64,
	tLife uint64,
	genesisHash crypto.Digest) (txn transactions.Transaction) {

	txn = transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + tLife),
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: amount},
		},
	}
	return
}

func createAssetTransaction(
	t *testing.T,
	counter uint64,
	round uint64,
	sender basics.Address,
	tLife uint64,
	amount uint64,
	genesisHash crypto.Digest) (assetTx transactions.Transaction) {

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)
	assetTx = transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + tLife),
			GenesisHash: genesisHash,
			Note:        note,
		},
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			AssetParams: basics.AssetParams{
				Total:         amount,
				DefaultFrozen: false,
				Manager:       sender,
			},
		},
	}
	return
}

func sendAssetTransaction(
	t *testing.T,
	round uint64,
	sender basics.Address,
	tLife uint64,
	genesisHash crypto.Digest,
	assetID basics.AssetIndex,
	receiver basics.Address,
	amount uint64) (tx transactions.Transaction) {

	tx = transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + tLife),
			GenesisHash: genesisHash,
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     assetID,
			AssetAmount:   amount,
			AssetReceiver: receiver,
		},
	}
	return
}

// create 6M unique assets by a different 6,000 accounts, and have a single account opted in, and owning all of them
func scenarioA(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	baseAcct psKey,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	tLife uint64,
	stopChan <-chan struct{}) {

	client := fixture.LibGoalClient

	numberOfAccounts := uint64(sixThousand) // 6K
	numberOfAssets := uint64(sixMillion)    // 6M

	assetsPerAccount := numberOfAssets / numberOfAccounts

	balance := uint64(200000000) // 100300000 for (1002 assets)  99363206259 below min 99363300000 (993632 assets)

	totalAssetAmount := uint64(0)

	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := uint64(2)
	counter := uint64(0)
	txnGroup := make([]txnKey, 0, maxTxGroupSize)
	var err error

	// create 6K accounts
	firstValid, counter, keys := createAccounts(
		t,
		fixture,
		numberOfAccounts+1,
		baseAcct,
		firstValid,
		balance,
		counter,
		tLife,
		genesisHash,
		txnChan,
		txnGrpChan,
		stopChan)

	// have a single account opted in all of them
	ownAllAccount := keys[numberOfAccounts-1]

	fmt.Println("Creating assets...")

	// create 6M unique assets by a different 6,000 accounts
	assetAmount := uint64(100)
	for nai, na := range keys {
		if na == ownAllAccount {
			continue
		}
		for asi := uint64(0); asi < assetsPerAccount; asi++ {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}

			if nai%printFreequency == 0 && int(asi)%printFreequency == 0 {
				fmt.Printf("create asset for acct: %d asset %d\n", nai, asi)
			}
			atx := createAssetTransaction(t, asi, firstValid, na.pk, tLife, uint64(600000000)+assetAmount, genesisHash)
			totalAssetAmount += uint64(600000000) + assetAmount
			assetAmount++

			counter, txnGroup = queueTransaction(na.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	fmt.Println("Opt-in assets...")

	// make ownAllAccount very rich
	sendAlgoTx := sendAlgoTransaction(t, firstValid, baseAcct.pk, ownAllAccount.pk, 10000000000000, tLife, genesisHash)
	counter, txnGroup = queueTransaction(baseAcct.sk, sendAlgoTx, txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)

	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := getAccountInformation(client, 0, assetsPerAccount, nacc.pk.String(), "ScenarioA opt-in assets")
		require.NoError(t, err)
		for assi, asset := range *info.Assets {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}

			if assi%printFreequency == 0 && acci%printFreequency == 0 {
				fmt.Printf("Accepting assets acct: %d asset %d\n", acci, assi)
			}
			optInT := sendAssetTransaction(
				t,
				firstValid,
				ownAllAccount.pk,
				tLife,
				genesisHash,
				basics.AssetIndex(asset.AssetId),
				ownAllAccount.pk,
				uint64(0))

			counter, txnGroup = queueTransaction(ownAllAccount.sk, optInT, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	fmt.Println("Transfer assets...")

	// and owning all of them
	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := getAccountInformation(client, 0, assetsPerAccount, nacc.pk.String(), "ScenarioA transfer assets")
		require.NoError(t, err)
		for assi, asset := range *info.Assets {
			select {
			case <-stopChan:
				require.False(t, true, "Test interrupted")
			default:
			}

			if assi%printFreequency == 0 && acci%printFreequency == 0 {
				fmt.Printf("Sending assets acct: %d asset %d\n", acci, assi)
			}
			assSend := sendAssetTransaction(
				t,
				firstValid,
				nacc.pk,
				tLife,
				genesisHash,
				basics.AssetIndex(asset.AssetId),
				ownAllAccount.pk,
				asset.Amount)
			counter, txnGroup = queueTransaction(nacc.sk, assSend, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	// Verify the assets are transfered here
	tAssetAmt := uint64(0)
	for _, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := getAccountInformation(client, 0, assetsPerAccount, nacc.pk.String(), "ScenarioA verify assets")
		require.NoError(t, err)
		for _, asset := range *info.Assets {
			select {
			case <-stopChan:
				require.False(t, true, "Test interrupted")
			default:
			}

			assHold, err := client.AccountAssetInformation(ownAllAccount.pk.String(), asset.AssetId)
			require.NoError(t, err)

			tAssetAmt += assHold.AssetHolding.Amount
		}
	}
	require.Equal(t, totalAssetAmount, tAssetAmt)
}

// create 6M unique assets, all created by a single account.
func scenarioB(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	baseAcct psKey,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	tLife uint64,
	stopChan <-chan struct{}) {

	numberOfAssets := uint64(sixMillion) // 6M
	totalAssetAmount := uint64(0)

	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := uint64(2)
	counter := uint64(0)
	txnGroup := make([]txnKey, 0, maxTxGroupSize)
	var err error

	fmt.Println("Creating assets..")

	// create 6M unique assets by a single account
	assetAmount := uint64(100)

	for asi := uint64(0); asi < numberOfAssets; asi++ {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}

		if int(asi)%printFreequency == 0 {
			fmt.Printf("create asset %d / %d\n", asi, numberOfAssets)
		}
		atx := createAssetTransaction(t, asi, firstValid, baseAcct.pk, tLife, uint64(600000000)+assetAmount, genesisHash)
		totalAssetAmount += uint64(600000000) + assetAmount
		assetAmount++

		counter, txnGroup = queueTransaction(baseAcct.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

		counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
		require.NoError(t, err)
	}

	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	client := fixture.LibGoalClient

	info, err := client.AccountInformationV2(baseAcct.pk.String(), false)
	require.NoError(t, err)
	require.Equal(t, numberOfAssets, info.TotalAssetsOptedIn)
	require.Equal(t, numberOfAssets, info.TotalCreatedAssets)

	// Verify the assets are transfered here
	tAssetAmt := uint64(0)
	info, err = client.AccountInformationV2(baseAcct.pk.String(), false)
	require.NoError(t, err)
	counter = 0
	for aid := uint64(0); counter < numberOfAssets && aid < 2*numberOfAssets; aid++ {
		select {
		case <-stopChan:
			require.False(t, true, "Test interrupted")
		default:
		}

		assHold, err := client.AccountAssetInformation(baseAcct.pk.String(), aid)
		var httpError clientApi.HTTPError
		if errors.As(err, &httpError) && httpError.StatusCode == http.StatusNotFound {
			continue
		}
		require.NoError(t, err)
		tAssetAmt += assHold.AssetHolding.Amount
	}
	require.Equal(t, totalAssetAmount, tAssetAmt)
}

// create 6M unique apps by a different 6,000 accounts, and have a single account opted-in all of them.
// Make an app call to each of them, and make sure the app store some information into the local storage.
func scenarioC(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	baseAcct psKey,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	tLife uint64,
	stopChan <-chan struct{}) {

	client := fixture.LibGoalClient

	numberOfAccounts := uint64(sixThousand) // 6K
	numberOfApps := uint64(sixMillion)      // 6M
	appsPerAccount := (numberOfApps + (numberOfAccounts - 1)) / numberOfAccounts

	balance := uint64(1000000000) // balance 199226999 below min 199275000

	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := uint64(2)
	counter := uint64(0)
	txnGroup := make([]txnKey, 0, maxTxGroupSize)
	var err error

	appCallFields := make([]transactions.ApplicationCallTxnFields, numberOfApps)

	// create 6K accounts
	firstValid, counter, keys := createAccounts(
		t,
		fixture,
		numberOfAccounts+1, // make an additional account which will opt in and call all the apps
		baseAcct,
		firstValid,
		balance,
		counter,
		tLife,
		genesisHash,
		txnChan,
		txnGrpChan,
		stopChan)

	// have a single account opted in all of them
	ownAllAccount := keys[numberOfAccounts]
	// make ownAllAccount very rich
	sendAlgoTx := sendAlgoTransaction(t, firstValid, baseAcct.pk, ownAllAccount.pk, 10000000000000, tLife, genesisHash)
	counter, txnGroup = queueTransaction(baseAcct.sk, sendAlgoTx, txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)

	fmt.Println("Creating applications ...")

	// create 6M unique apps by a different 6,000 accounts
	for nai, na := range keys {
		if na == ownAllAccount {
			continue
		}
		for appi := uint64(0); appi < appsPerAccount; appi++ {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}

			if int(appi)%printFreequency == 0 && int(nai)%printFreequency == 0 {
				fmt.Printf("scenario3: create app %d / %d for account %d / %d\n", appi, appsPerAccount, nai, numberOfAccounts)
			}
			atx := makeAppTransaction(t, client, appi, firstValid, na.pk, tLife, false, genesisHash)
			appCallFields[appi] = atx.ApplicationCallTxnFields
			counter, txnGroup = queueTransaction(na.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	fmt.Println("Opt-in applications...")

	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := getAccountInformation(client, appsPerAccount, 0, nacc.pk.String(), "ScenarioC opt-in apps")
		require.NoError(t, err)
		for appi, app := range *info.CreatedApps {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}

			if acci%printFreequency == 0 && appi%printFreequency == 0 {
				fmt.Printf("scenario3: Opting into Application acct: %d app %d\n", acci, app.Id)
			}
			optInTx := makeOptInAppTransaction(t, client, basics.AppIndex(app.Id), firstValid, ownAllAccount.pk, tLife, genesisHash)
			counter, txnGroup = queueTransaction(ownAllAccount.sk, optInTx, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	fmt.Println("verifying optin apps...")

	for _, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := getAccountInformation(client, appsPerAccount, 0, nacc.pk.String(), "ScenarioC verify accounts")
		require.NoError(t, err)

		for _, capp := range *info.CreatedApps {
			appInfo, err := getAccountApplicationInformation(client, ownAllAccount.pk.String(), capp.Id, "verifying after optin")
			if err != nil {
				fmt.Printf("account: %s  appid: %d error %s\n\n", ownAllAccount.pk, capp.Id, err)
				continue
			}
			require.Equal(t, uint64(1), (*appInfo.AppLocalState.KeyValue)[0].Value.Uint)
			require.Equal(t, uint64(2), (*capp.Params.GlobalState)[0].Value.Uint)
		}
	}

	fmt.Println("calling applications...")

	// Make an app call to each of them
	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := getAccountInformation(client, appsPerAccount, 0, nacc.pk.String(), "ScenarioC call apps")
		require.NoError(t, err)
		for appi, app := range *info.CreatedApps {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}

			if acci%printFreequency == 0 && appi%printFreequency == 0 {
				fmt.Printf("scenario3: Calling Application acct: %d app %d\n", acci, app.Id)
			}

			optInTx := callAppTransaction(t, client, basics.AppIndex(app.Id), firstValid, ownAllAccount.pk, tLife, genesisHash)
			counter, txnGroup = queueTransaction(ownAllAccount.sk, optInTx, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	fmt.Println("Completed. Verifying accounts...")

	for _, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := getAccountInformation(client, appsPerAccount, 0, nacc.pk.String(), "ScenarioC verify accounts")
		require.NoError(t, err)

		for _, capp := range *info.CreatedApps {
			appInfo, err := getAccountApplicationInformation(client, ownAllAccount.pk.String(), capp.Id, "after call")
			if err != nil {
				fmt.Printf("account: %s  appid: %d error %s\n\n", ownAllAccount.pk, capp.Id, err)
				continue
			}
			require.Equal(t, uint64(2), (*appInfo.AppLocalState.KeyValue)[0].Value.Uint)
			require.Equal(t, uint64(3), (*capp.Params.GlobalState)[0].Value.Uint)
		}
	}
	require.Equal(t, failTest, false)
}

// create 6M unique apps by a different 6,000 accounts, and have a single account opted-in all of them. Make an app call to each of them, and make sure the app store some information into the local storage.
//func scenarioC(
// create 6M unique apps by a single account. Opt-into all the applications and make sure the app stores information to both the local and global storage.
func scenarioD(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	baseAcct psKey,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	tLife uint64,
	stopChan <-chan struct{}) {

	client := fixture.LibGoalClient

	numberOfApps := uint64(sixMillion) // 6M
	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := uint64(2)
	counter := uint64(0)
	txnGroup := make([]txnKey, 0, maxTxGroupSize)
	var err error

	globalStateCheck := make([]bool, numberOfApps)
	appCallFields := make([]transactions.ApplicationCallTxnFields, numberOfApps)

	fmt.Println("Creating applications ...")

	// create 6M apps
	for asi := uint64(0); asi < numberOfApps; asi++ {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}

		if int(asi)%printFreequency == 0 {
			fmt.Printf("scenario4: create app %d / %d\n", asi, numberOfApps)
		}
		atx := makeAppTransaction(t, client, asi, firstValid, baseAcct.pk, tLife, true, genesisHash)
		appCallFields[asi] = atx.ApplicationCallTxnFields
		counter, txnGroup = queueTransaction(baseAcct.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

		counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
		require.NoError(t, err)
	}

	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	// check the results in parallel
	parallelCheckers := numberOfThreads
	checkAppChan := make(chan uint64, parallelCheckers)
	checkResChan := make(chan uint64, parallelCheckers)
	var wg sync.WaitGroup
	var globalStateCheckMu deadlock.Mutex

	for p := 0; p < parallelCheckers; p++ {
		wg.Add(1)
		go func() {
			for i := range checkAppChan {
				var app generated.Application
				cont := false
				for {
					app, err = client.ApplicationInformation(i)
					if err != nil {
						if strings.Contains(err.Error(), "application does not exist") {
							cont = true
							break
						}
						time.Sleep(time.Millisecond * 100)
						continue
					}
					break
				}
				if cont {
					continue
				}
				checkResChan <- 1
				pass := checkApplicationParams(
					appCallFields[(*app.Params.GlobalState)[0].Value.Uint],
					app.Params,
					baseAcct.pk.String(),
					&globalStateCheck,
					globalStateCheckMu)
				if !pass {
					fmt.Printf("scenario4: app params check failed for %d\n", app.Id)
				}
			}
			wg.Done()
		}()
	}

	checked := uint64(0)
	lastPrint := uint64(0)
	for i := uint64(0); checked < numberOfApps; {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		case val := <-checkResChan:
			checked += val
		case checkAppChan <- i:
			i++
		default:
			time.Sleep(10 * time.Millisecond)
		}
		if checked != lastPrint && int(checked)%printFreequency == 0 {
			fmt.Printf("scenario4: check app params %d / %d\n", checked, numberOfApps)
			lastPrint = checked
		}
	}
	close(checkAppChan)
	wg.Wait()

	for _, x := range globalStateCheck {
		require.True(t, x)

	}
}

func handleError(err error, message string, errChan chan<- error) {
	if err != nil {
		fmt.Printf("%s: %v\n", message, err)
		select {
		// use select to avoid blocking when the errChan is not interested in messages.
		case errChan <- err:
		default:
		}
	}
}

func checkPoint(counter, firstValid, tLife uint64, force bool, fixture *fixtures.RestClientFixture) (newCounter, nextFirstValid uint64, err error) {
	waitBlock := 5
	lastRound := firstValid + counter - 1
	if force || counter == tLife-800 { // TODO: remove -800 after resolving "Missing appsPerAccount" issue
		fmt.Printf("Waiting for round %d...", int(lastRound))
		for x := 0; x < 1000; x++ {
			err := fixture.WaitForRound(lastRound, time.Duration(waitBlock)*time.Second)
			if err == nil {
				fmt.Printf(" waited %d sec, done.\n", (x+1)*waitBlock)
				status, err := fixture.AlgodClient.Status()
				if err != nil {
					return 0, lastRound + 1, nil
				}
				return 0, status.LastRound + 1, nil
			} else {
				fmt.Printf(" waited %d sec, continue waiting...\n", (x+1)*waitBlock)
			}
		}
		fmt.Println("Giving up!")
		return 0, 0, fmt.Errorf("Waited for round %d for %d seconds. Giving up!", firstValid+counter, 1000*waitBlock)
	}
	return counter, firstValid, nil
}

func signAndBroadcastTransaction(
	round uint64,
	txn *transactions.Transaction,
	client libgoal.Client,
	fixture *fixtures.RestClientFixture) error {

	walletHandle, err := client.GetUnencryptedWalletHandle()
	if err != nil {
		return err
	}
	stxn, err := client.SignTransactionWithWallet(walletHandle, nil, *txn)
	if err != nil {
		return err
	}
	_, err = client.BroadcastTransaction(stxn)
	if err != nil {
		return err
	}
	err = fixture.WaitForRound(round, time.Millisecond*2000)
	return err
}

func queueTransaction(
	sk *crypto.SignatureSecrets,
	tx transactions.Transaction,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	counter uint64,
	txnGroup []txnKey) (uint64, []txnKey) {
	tk := txnKey{tx: tx, sk: sk}

	if !groupTransactions {
		txnChan <- &tk
		return counter + 1, txnGroup
	}
	txnGroup = append(txnGroup, tk)
	if len(txnGroup) == maxTxGroupSize {
		sendTransactions := make([]txnKey, len(txnGroup))
		for i, t := range txnGroup {
			sendTransactions[i] = t
		}

		txnGrpChan <- sendTransactions
		txnGroup = txnGroup[:0]
		return counter + 1, txnGroup
	}
	return counter, txnGroup
}

func flushQueue(
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	counter uint64,
	txnGroup []txnKey) (uint64, []txnKey) {

	if len(txnGroup) == 0 {
		return counter, txnGroup
	}
	sendTransactions := make([]txnKey, len(txnGroup))
	for i, t := range txnGroup {
		sendTransactions[i] = t
	}
	txnGrpChan <- sendTransactions
	txnGroup = txnGroup[:0]
	return counter + 1, txnGroup
}

func makeAppTransaction(
	t *testing.T,
	client libgoal.Client,
	counter uint64,
	round uint64,
	sender basics.Address,
	tLife uint64,
	setCounterInProg bool,
	genesisHash crypto.Digest) (appTx transactions.Transaction) {

	progCounter := uint64(1)
	if setCounterInProg {
		progCounter = counter
	}
	prog := fmt.Sprintf(`#pragma version 2
// a simple global and local calls counter app
byte b64 Y291bnRlcg== // counter
dup
app_global_get
int %d
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
`, progCounter)

	approvalOps, err := logic.AssembleString(prog)
	require.NoError(t, err)
	clearstateOps, err := logic.AssembleString("#pragma version 2\nint 1")
	require.NoError(t, err)
	schema := basics.StateSchema{
		NumUint: 1,
	}

	// create the app
	appTx, err = client.MakeUnsignedAppCreateTx(
		transactions.OptInOC, approvalOps.Program, clearstateOps.Program, schema, schema, nil, nil, nil, nil, 0)
	require.NoError(t, err)

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + tLife),
		GenesisHash: genesisHash,
		Note:        note,
	}
	return
}

func makeOptInAppTransaction(
	t *testing.T,
	client libgoal.Client,
	appIdx basics.AppIndex,
	round uint64,
	sender basics.Address,
	tLife uint64,
	genesisHash crypto.Digest) (appTx transactions.Transaction) {

	appTx, err := client.MakeUnsignedAppOptInTx(uint64(appIdx), nil, nil, nil, nil)
	require.NoError(t, err)

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + tLife),
		GenesisHash: genesisHash,
	}
	return
}

func checkApplicationParams(
	acTF transactions.ApplicationCallTxnFields,
	app generated.ApplicationParams,
	creator string,
	globalStateCheck *[]bool,
	globalStateCheckMu deadlock.Mutex) (pass bool) {

	pass = true
	if bytes.Compare(acTF.ApprovalProgram, app.ApprovalProgram) != 0 {
		return false
	}
	if bytes.Compare(acTF.ClearStateProgram, app.ClearStateProgram) != 0 {
		return false
	}
	if creator != app.Creator {
		return false
	}

	var oldVal bool
	globalStateCheckMu.Lock()
	oldVal = (*globalStateCheck)[(*app.GlobalState)[0].Value.Uint]
	(*globalStateCheck)[(*app.GlobalState)[0].Value.Uint] = true
	globalStateCheckMu.Unlock()
	if oldVal != false {
		return false
	}

	if acTF.GlobalStateSchema.NumByteSlice != app.GlobalStateSchema.NumByteSlice {
		return false
	}
	if acTF.GlobalStateSchema.NumUint != app.GlobalStateSchema.NumUint {
		return false
	}
	if acTF.LocalStateSchema.NumByteSlice != app.LocalStateSchema.NumByteSlice {
		return false
	}
	if acTF.LocalStateSchema.NumUint != app.LocalStateSchema.NumUint {
		return false
	}
	return pass
}

func createAccounts(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	numberOfAccounts uint64,
	baseAcct psKey,
	firstValid uint64,
	balance uint64,
	counter uint64,
	tLife uint64,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	stopChan <-chan struct{}) (newFirstValid uint64, newCounter uint64, keys []psKey) {

	fmt.Println("Creating accounts...")

	var err error
	txnGroup := make([]txnKey, 0, maxTxGroupSize)

	// create 6K accounts
	keys = generateKeys(int(numberOfAccounts))
	for i, key := range keys {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}
		if i%printFreequency == 0 {
			fmt.Println("account create txn: ", i)
		}
		txn := sendAlgoTransaction(t, firstValid, baseAcct.pk, key.pk, balance, tLife, genesisHash)
		counter, txnGroup = queueTransaction(baseAcct.sk, txn, txnChan, txnGrpChan, counter, txnGroup)

		counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
		require.NoError(t, err)
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)
	return firstValid, counter, keys
}

func callAppTransaction(
	t *testing.T,
	client libgoal.Client,
	appIdx basics.AppIndex,
	round uint64,
	sender basics.Address,
	tLife uint64,
	genesisHash crypto.Digest) (appTx transactions.Transaction) {

	appTx, err := client.MakeUnsignedAppNoOpTx(uint64(appIdx), nil, nil, nil, nil)
	require.NoError(t, err)

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + tLife),
		GenesisHash: genesisHash,
	}
	return
}
