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

package fataccount

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	clientApi "github.com/algorand/go-algorand/daemon/algod/api/client"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// uses numberOfGoRoutines to perform different operations (signing and preparing transactions) in parallel
var numberOfGoRoutines = runtime.NumCPU() * 2

// the frequency of printing progress status directly to stdout
const printFrequency = 3

// send transactions in groups or one by one
const groupTransactions = true

// number of elements queued in channels
const channelDepth = 100

// the test in intended for 6M apps/assets and 6K accounts. These variable values can be changed to modify this.
const targetCreateableCount = 100
const targetAccountCount = 10

// print wait times
const verbose = false

// transaction group size obtained from consensus parameter
var maxTxGroupSize int

type psKey struct {
	sk *crypto.SignatureSecrets
	pk basics.Address
}

type txnKey struct {
	sk *crypto.SignatureSecrets
	tx transactions.Transaction
}

// started as a goroutine which will listen to signed transactions and broadcast them
func broadcastTransactions(queueWg *sync.WaitGroup, fixture *fixtures.RestClientFixture, sigTxnChan <-chan *transactions.SignedTxn, errChan chan<- error) {
	defer queueWg.Done()
	for stxn := range sigTxnChan {
		if stxn == nil {
			break
		}
		_, err := fixture.AlgodClient.SendRawTransaction(*stxn)
		if err != nil {
			handleError(err, "Error broadcastTransactions", errChan)
		}
	}
}

// started as a goroutine which will listen to signed transaction groups and broadcast them
func broadcastTransactionGroups(queueWg *sync.WaitGroup, fixture *fixtures.RestClientFixture, sigTxnGrpChan <-chan []transactions.SignedTxn, errChan chan<- error) {
	defer queueWg.Done()
	for stxns := range sigTxnGrpChan {
		if stxns == nil {
			break
		}
		var err error

		err = fixture.AlgodClient.SendRawTransactionGroup(stxns)
		if err != nil {
			handleError(err, "Error broadcastTransactionGroups", errChan)
		}
	}
}

// queries the node for account information, and will ertry if the expected number of apps or assets are not returned
func getAccountInformation(
	fixture *fixtures.RestClientFixture,
	expectedCountApps uint64,
	expectedCountAssets uint64,
	address string,
	context string,
	log logging.Logger) (info model.Account, err error) {

	for x := 0; x < 5; x++ { // retry only 5 times
		info, err = fixture.AlgodClient.AccountInformation(address, true)
		if err != nil {
			return
		}
		if expectedCountApps > 0 && int(expectedCountApps) != len(*info.CreatedApps) {
			log.Errorf("Missing appsPerAccount: %s got: %d expected: %d", address, len(*info.CreatedApps), expectedCountApps)
			continue
		}
		if expectedCountAssets > 0 && int(expectedCountAssets) != len(*info.CreatedAssets) {
			log.Errorf("Missing assetsPerAccount: %s got: %d expected: %d", address, len(*info.CreatedAssets), expectedCountAssets)
			continue
		}
	}
	return
}

// queries the node for the given app information
func getAccountApplicationInformation(
	fixture *fixtures.RestClientFixture,
	address string,
	appID basics.AppIndex) (appInfo model.AccountApplicationResponse, err error) {

	appInfo, err = fixture.AlgodClient.AccountApplicationInformation(address, appID)
	return
}

// started as a goroutine, signs the transactions from the channel
func signer(
	sigWg *sync.WaitGroup,
	txnChan <-chan *txnKey,
	sigTxnChan chan<- *transactions.SignedTxn) {
	defer sigWg.Done()
	for tk := range txnChan {
		if tk == nil {
			continue
		}
		stxn := tk.tx.Sign(tk.sk)
		sigTxnChan <- &stxn
	}
}

// started as a goroutine, signs the transaction groups from the channel
func signerGrpTxn(
	sigWg *sync.WaitGroup,
	client libgoal.Client,
	txnGrpChan <-chan []txnKey,
	sigTxnGrpChan chan<- []transactions.SignedTxn,
	errChan chan<- error) {
	defer sigWg.Done()
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
		for i := range tGroup {
			sendTransactions[i].Group = gid
		}

		// sign the transactions
		stxns := make([]transactions.SignedTxn, len(tGroup))
		for i, tk := range tGroup {
			stxns[i] = sendTransactions[i].Sign(tk.sk)
		}

		sigTxnGrpChan <- stxns
	}
}

// create 6M unique assets by a different 6,000 accounts, and have a single account opted in, and owning all of them
func Test5MAssetsScenario1(t *testing.T) {
	test5MAssets(t, 1)
}

// create 6M unique assets, all created by a single account.
func Test5MAssetsScenario2(t *testing.T) {
	test5MAssets(t, 2)
}

// create 6M unique apps by a different 6,000 accounts, and have a single account opted-in all of them.
// Make an app call to each of them, and make sure the app store some information into the local storage.
func Test5MAssetsScenario3(t *testing.T) {
	test5MAssets(t, 3)
}

// create 6M unique apps by a single account. Opt-into all the applications and make sure the app stores information to both the local and global storage.
func Test5MAssetsScenario4(t *testing.T) {
	test5MAssets(t, 4)
}

// the common section of all test scenarios
func test5MAssets(t *testing.T, scenario int) {
	partitiontest.PartitionTest(t)

	var fixture fixtures.RestClientFixture
	var sigWg sync.WaitGroup
	var queueWg sync.WaitGroup
	var hkWg sync.WaitGroup
	var errWatcherWg sync.WaitGroup

	log := logging.TestingLog(t)

	maxTxGroupSize = config.Consensus[protocol.ConsensusCurrentVersion].MaxTxGroupSize
	fixture.Setup(t, filepath.Join("nettemplates", "DevModeOneWallet.json"))

	defer func() {
		hkWg.Wait()
		fixture.Shutdown()
	}()

	accountList, err := fixture.GetWalletsSortedByBalance()
	require.NoError(t, err)
	// get the wallet account
	wAcct := accountList[0].Address

	suggestedParams, err := fixture.AlgodClient.SuggestedParams()
	require.NoError(t, err)
	var genesisHash crypto.Digest
	copy(genesisHash[:], suggestedParams.GenesisHash)
	tLife := basics.Round(config.Consensus[protocol.ConsensusVersion(suggestedParams.ConsensusVersion)].MaxTxnLife)

	// fund the non-wallet base account
	ba := generateKeys(1)
	baseAcct := ba[0]
	sender, err := basics.UnmarshalChecksumAddress(wAcct)
	require.NoError(t, err)
	satxn := sendAlgoTransaction(t, 0, sender, baseAcct.pk, 1000000000000000, 1, genesisHash)
	err = signAndBroadcastTransaction(0, &satxn, fixture.LibGoalClient, &fixture)
	require.NoError(t, err)

	txnChan := make(chan *txnKey, channelDepth)
	txnGrpChan := make(chan []txnKey, channelDepth)
	sigTxnChan := make(chan *transactions.SignedTxn, channelDepth)
	sigTxnGrpChan := make(chan []transactions.SignedTxn, channelDepth)
	errChan := make(chan error, channelDepth)
	stopChan := make(chan struct{}, 1)

	for ngoroutine := 0; ngoroutine < numberOfGoRoutines; ngoroutine++ {
		sigWg.Add(1)
		if groupTransactions {
			go signerGrpTxn(&sigWg, fixture.LibGoalClient, txnGrpChan, sigTxnGrpChan, errChan)
		} else {
			go signer(&sigWg, txnChan, sigTxnChan)
		}
	}

	for ngoroutine := 0; ngoroutine < numberOfGoRoutines; ngoroutine++ {
		queueWg.Add(1)
		if groupTransactions {
			go broadcastTransactionGroups(&queueWg, &fixture, sigTxnGrpChan, errChan)
		} else {
			go broadcastTransactions(&queueWg, &fixture, sigTxnChan, errChan)
		}
	}

	// error handling
	errWatcherWg.Add(1)
	go func() {
		defer errWatcherWg.Done()
		errCount := 0
		for err := range errChan {
			log.Warnf("%s", err.Error())
			errCount++
			if errCount > 10 {
				log.Warnf("too many errors %s", err.Error())
				stopChan <- struct{}{}
				break
			}
		}
		close(stopChan)
	}()

	// some housekeeping
	hkWg.Add(1)
	go func() {
		defer hkWg.Done()
		sigWg.Wait()
		close(sigTxnChan)
		close(sigTxnGrpChan)
		queueWg.Wait()
		close(errChan)
		errWatcherWg.Wait()
	}()

	// Call different scenarios
	switch scenario {
	case 1:
		scenarioA(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan, log)
	case 2:
		scenarioB(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan, log)
	case 3:
		scenarioC(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan, log)
	case 4:
		scenarioD(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan, log)
	}
}

// generates numAccounts keys; we generate the same seeds here when generating the secret keys
// so that this test would be reproducible.
func generateKeys(numAccounts int) (keys []psKey) {
	keys = make([]psKey, 0, numAccounts)
	var seed crypto.Seed
	seed[len(seed)-1] = 1
	for a := 0; a < numAccounts; a++ {
		seed[0], seed[1], seed[2], seed[3] = byte(a), byte(a>>8), byte(a>>16), byte(a>>24)
		privateKey := crypto.GenerateSignatureSecrets(seed)
		publicKey := basics.Address(privateKey.SignatureVerifier)
		keys = append(keys, psKey{pk: publicKey, sk: privateKey})
	}
	return
}

// prepares a send algo transaction
func sendAlgoTransaction(
	t *testing.T,
	round basics.Round,
	sender basics.Address,
	receiver basics.Address,
	amount uint64,
	tLife basics.Round,
	genesisHash crypto.Digest) (txn transactions.Transaction) {

	txn = transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  round,
			LastValid:   round + tLife,
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: amount},
		},
	}
	return
}

// prepares a create asset transaction
func createAssetTransaction(
	t *testing.T,
	counter uint64,
	round basics.Round,
	sender basics.Address,
	tLife basics.Round,
	amount uint64,
	genesisHash crypto.Digest) (assetTx transactions.Transaction) {

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)
	assetTx = transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  round,
			LastValid:   round + tLife,
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

// prepares a send asset transaction
func sendAssetTransaction(
	t *testing.T,
	round basics.Round,
	sender basics.Address,
	tLife basics.Round,
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

func printStdOut(index int, total uint64, message string) {
	if printFrequency == 0 {
		return
	}
	if index%int(total/(printFrequency+1)+1) == 0 {
		fmt.Printf("%s: %d / %d\n", message, index, total)
	}
}

// create 6M unique assets by a different 6,000 accounts, and have a single account opted in, and owning all of them
func scenarioA(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	baseAcct psKey,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	tLife basics.Round,
	stopChan <-chan struct{},
	log logging.Logger) {

	numberOfAccounts := uint64(targetAccountCount)  // 6K
	numberOfAssets := uint64(targetCreateableCount) // 6M

	assetsPerAccount := numberOfAssets / numberOfAccounts

	balance := uint64(200000000) // 100300000 for (1002 assets)  99363206259 below min 99363300000 (993632 assets)

	totalAssetAmount := uint64(0)

	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := basics.Round(2)
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
		stopChan,
		log)

	// have a single account opted in all of them
	ownAllAccount := keys[numberOfAccounts-1]

	log.Infof("Creating assets...")

	// create 6M unique assets by a different 6,000 accounts
	assetAmount := uint64(100)
	for nai, na := range keys {
		if na == ownAllAccount {
			continue
		}
		printStdOut(nai, numberOfAccounts, "ScenarioA: create assets for acct")

		for asi := uint64(0); asi < assetsPerAccount; asi++ {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}
			atx := createAssetTransaction(t, asi, firstValid, na.pk, tLife, uint64(600000000)+assetAmount, genesisHash)
			totalAssetAmount += uint64(600000000) + assetAmount
			assetAmount++

			counter, txnGroup = queueTransaction(na.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture, log)
	require.NoError(t, err)

	log.Infof("Opt-in assets...")

	// make ownAllAccount very rich
	sendAlgoTx := sendAlgoTransaction(t, firstValid, baseAcct.pk, ownAllAccount.pk, 10000000000000, tLife, genesisHash)
	counter, txnGroup = queueTransaction(baseAcct.sk, sendAlgoTx, txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)

	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		printStdOut(acci, numberOfAccounts, "ScenarioA: Accepting assets from acct")
		info, err := getAccountInformation(fixture, 0, assetsPerAccount, nacc.pk.String(), "ScenarioA opt-in assets", log)
		require.NoError(t, err)
		require.Equal(t, int(assetsPerAccount), len(*info.Assets)) // test the asset holding.
		for _, asset := range *info.Assets {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}

			optInT := sendAssetTransaction(
				t,
				firstValid,
				ownAllAccount.pk,
				tLife,
				genesisHash,
				asset.AssetID,
				ownAllAccount.pk,
				uint64(0))

			counter, txnGroup = queueTransaction(ownAllAccount.sk, optInT, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture, log)
	require.NoError(t, err)

	log.Infof("Transfer assets...")

	// and owning all of them
	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		printStdOut(acci, numberOfAccounts, "ScenarioA: Sending assets from acct")

		info, err := getAccountInformation(fixture, 0, assetsPerAccount, nacc.pk.String(), "ScenarioA transfer assets", log)
		require.NoError(t, err)
		require.Equal(t, int(assetsPerAccount), len(*info.Assets)) // test the asset holding.
		for _, asset := range *info.Assets {
			select {
			case <-stopChan:
				require.False(t, true, "Test interrupted")
			default:
			}

			assSend := sendAssetTransaction(
				t,
				firstValid,
				nacc.pk,
				tLife,
				genesisHash,
				asset.AssetID,
				ownAllAccount.pk,
				asset.Amount)
			counter, txnGroup = queueTransaction(nacc.sk, assSend, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture, log)
	require.NoError(t, err)

	log.Infof("Verifying assets...")
	// Verify the assets are transfered here
	tAssetAmt := uint64(0)
	for nai, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		printStdOut(nai, numberOfAccounts, "ScenarioA: Verifying assets from account")
		info, err := getAccountInformation(fixture, 0, assetsPerAccount, nacc.pk.String(), "ScenarioA verify assets", log)
		require.NoError(t, err)
		require.Equal(t, int(assetsPerAccount), len(*info.Assets)) // test the asset holding.
		for _, asset := range *info.Assets {
			select {
			case <-stopChan:
				require.False(t, true, "Test interrupted")
			default:
			}

			assHold, err := fixture.AlgodClient.AccountAssetInformation(ownAllAccount.pk.String(), asset.AssetID)
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
	tLife basics.Round,
	stopChan <-chan struct{},
	log logging.Logger) {

	const numberOfAssets = targetCreateableCount // 6M
	totalAssetAmount := uint64(0)

	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := basics.Round(2)
	counter := uint64(0)
	txnGroup := make([]txnKey, 0, maxTxGroupSize)
	var err error

	log.Infof("Creating assets..")

	// create 6M unique assets by a single account
	assetAmount := uint64(100)

	for asi := uint64(0); asi < numberOfAssets; asi++ {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}

		printStdOut(int(asi), numberOfAssets, "create asset")
		atx := createAssetTransaction(t, asi, firstValid, baseAcct.pk, tLife, uint64(600000000)+assetAmount, genesisHash)
		totalAssetAmount += uint64(600000000) + assetAmount
		assetAmount++

		counter, txnGroup = queueTransaction(baseAcct.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

		counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
		require.NoError(t, err)
	}

	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture, log)
	require.NoError(t, err)

	info, err := fixture.AlgodClient.AccountInformation(baseAcct.pk.String(), false)
	require.NoError(t, err)
	require.EqualValues(t, numberOfAssets, info.TotalAssetsOptedIn)
	require.EqualValues(t, numberOfAssets, info.TotalCreatedAssets)

	log.Infof("Verifying assets...")
	// Verify the assets are transferred here
	tAssetAmt := uint64(0)
	counter = 0
	// this loop iterates over all the range of potential assets, tries to confirm all of them.
	// many of these are expected to be non-existing.
	startIdx := basics.AssetIndex(1000) // tx counter starts from 1000
	for aid := startIdx; counter < numberOfAssets && aid < 2*startIdx*numberOfAssets; aid++ {
		select {
		case <-stopChan:
			require.False(t, true, "Test interrupted")
		default:
		}

		assHold, err := fixture.AlgodClient.AccountAssetInformation(baseAcct.pk.String(), aid)
		var httpError clientApi.HTTPError
		if errors.As(err, &httpError) && httpError.StatusCode == http.StatusNotFound {
			continue
		}
		counter++
		require.NoError(t, err)
		require.NotZero(t, assHold.AssetHolding.Amount)
		tAssetAmt += assHold.AssetHolding.Amount
		printStdOut(int(counter), numberOfAssets, "ScenarioB: Verifying assets")
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
	tLife basics.Round,
	stopChan <-chan struct{},
	log logging.Logger) {

	client := fixture.LibGoalClient
	numberOfAccounts := uint64(targetAccountCount) // 6K
	numberOfApps := uint64(targetCreateableCount)  // 6M
	appsPerAccount := (numberOfApps + (numberOfAccounts - 1)) / numberOfAccounts

	balance := uint64(1000000000) // balance 199226999 below min 199275000

	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := basics.Round(2)
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
		stopChan,
		log)

	// have a single account opted in all of them
	ownAllAccount := keys[numberOfAccounts]
	// make ownAllAccount very rich
	sendAlgoTx := sendAlgoTransaction(t, firstValid, baseAcct.pk, ownAllAccount.pk, 10000000000000, tLife, genesisHash)
	counter, txnGroup = queueTransaction(baseAcct.sk, sendAlgoTx, txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)

	log.Infof("Creating applications ...")

	// create 6M unique apps by a different 6,000 accounts
	for nai, na := range keys {
		if na == ownAllAccount {
			continue
		}

		printStdOut(nai, numberOfAccounts, "scenario3: create apps for account")
		for appi := uint64(0); appi < appsPerAccount; appi++ {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}
			atx := makeAppTransaction(t, client, appi, firstValid, na.pk, tLife, false, genesisHash)
			appCallFields[appi] = atx.ApplicationCallTxnFields
			counter, txnGroup = queueTransaction(na.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture, log)
	require.NoError(t, err)

	log.Infof("Opt-in applications...")

	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		printStdOut(acci, numberOfAccounts, "scenario3: Opting into Application acct")
		info, err := getAccountInformation(fixture, appsPerAccount, 0, nacc.pk.String(), "ScenarioC opt-in apps", log)
		require.NoError(t, err)
		for _, app := range *info.CreatedApps {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}
			optInTx := makeOptInAppTransaction(t, client, app.Id, firstValid, ownAllAccount.pk, tLife, genesisHash)
			counter, txnGroup = queueTransaction(ownAllAccount.sk, optInTx, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture, log)
	require.NoError(t, err)

	log.Infof("verifying optin apps...")

	for nai, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		printStdOut(nai, numberOfAccounts, "ScenarioC: Verifying apps opt-in from account")
		info, err := getAccountInformation(fixture, appsPerAccount, 0, nacc.pk.String(), "ScenarioC verify accounts", log)
		require.NoError(t, err)
		require.Equal(t, appsPerAccount, info.TotalAppsOptedIn) // since we opted into the app
		for _, capp := range *info.CreatedApps {
			appInfo, err := getAccountApplicationInformation(fixture, ownAllAccount.pk.String(), capp.Id) // "verifying after optin"
			if err != nil {
				log.Errorf("account: %s  appid: %d error %s", ownAllAccount.pk, capp.Id, err)
				continue
			}
			require.Equal(t, uint64(1), (*appInfo.AppLocalState.KeyValue)[0].Value.Uint)
			require.Equal(t, uint64(2), (*capp.Params.GlobalState)[0].Value.Uint)
			require.Nil(t, appInfo.CreatedApp)
		}
	}

	log.Infof("calling applications...")

	// Make an app call to each of them
	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		printStdOut(acci, numberOfAccounts, "scenario3: Calling Application acct")
		info, err := getAccountInformation(fixture, appsPerAccount, 0, nacc.pk.String(), "ScenarioC call apps", log)
		require.NoError(t, err)
		for _, app := range *info.CreatedApps {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}
			optInTx := callAppTransaction(t, client, app.Id, firstValid, ownAllAccount.pk, tLife, genesisHash)
			counter, txnGroup = queueTransaction(ownAllAccount.sk, optInTx, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture, log)
	require.NoError(t, err)

	log.Infof("Completed. Verifying accounts...")

	for nai, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		printStdOut(nai, numberOfAccounts, "ScenarioC: Verifying app calls from account")
		info, err := getAccountInformation(fixture, appsPerAccount, 0, nacc.pk.String(), "ScenarioC verify accounts", log)
		require.NoError(t, err)
		require.Equal(t, appsPerAccount, info.TotalAppsOptedIn) // since we opted into the app
		for _, capp := range *info.CreatedApps {
			appInfo, err := getAccountApplicationInformation(fixture, ownAllAccount.pk.String(), capp.Id) // "after call"
			if err != nil {
				log.Errorf("account: %s  appid: %d error %s", ownAllAccount.pk, capp.Id, err)
				continue
			}
			require.Equal(t, uint64(2), (*appInfo.AppLocalState.KeyValue)[0].Value.Uint)
			require.Equal(t, uint64(3), (*capp.Params.GlobalState)[0].Value.Uint)
			require.Nil(t, appInfo.CreatedApp)
		}
	}
}

// create 6M unique apps by a single account. Opt-into all the applications and make sure the app stores information to both the local and global storage.
func scenarioD(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	baseAcct psKey,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	tLife basics.Round,
	stopChan <-chan struct{},
	log logging.Logger) {

	client := fixture.LibGoalClient
	const numberOfApps = targetCreateableCount // 6M
	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := basics.Round(2)
	counter := uint64(0)
	txnGroup := make([]txnKey, 0, maxTxGroupSize)
	var err error

	globalStateCheck := make([]bool, numberOfApps)
	appCallFields := make([]transactions.ApplicationCallTxnFields, numberOfApps)

	log.Infof("Creating applications ...")

	// create 6M apps
	for asi := uint64(0); asi < numberOfApps; asi++ {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}

		printStdOut(int(asi), numberOfApps, "scenario4: create app")
		atx := makeAppTransaction(t, client, asi, firstValid, baseAcct.pk, tLife, true, genesisHash)
		appCallFields[asi] = atx.ApplicationCallTxnFields
		counter, txnGroup = queueTransaction(baseAcct.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

		counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
		require.NoError(t, err)
	}

	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture, log)
	require.NoError(t, err)

	// check the results in parallel
	parallelCheckers := numberOfGoRoutines
	checkAppChan := make(chan basics.AppIndex, parallelCheckers)
	checkResChan := make(chan uint64, parallelCheckers)
	var wg sync.WaitGroup
	var globalStateCheckMu deadlock.Mutex

	log.Infof("Completed. Verifying apps...")

	for p := 0; p < parallelCheckers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range checkAppChan {
				app, err := fixture.AlgodClient.ApplicationInformation(i)
				if err != nil {
					if strings.Contains(err.Error(), "application does not exist") {
						continue
					}
					checkResChan <- 0
					continue
				}
				pass := checkApplicationParams(
					appCallFields[(*app.Params.GlobalState)[0].Value.Uint],
					app.Params,
					baseAcct.pk.String(),
					&globalStateCheck,
					&globalStateCheckMu)
				if pass {
					checkResChan <- 1
				} else {
					checkResChan <- 0
					log.Errorf("scenario4: app params check failed for %d", app.Id)
				}
			}
		}()
	}

	checked := uint64(0)
	passed := uint64(0)
	lastPrint := uint64(0)
	for i := basics.AppIndex(0); checked < numberOfApps; {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		case val := <-checkResChan:
			checked++
			passed += val
		case checkAppChan <- i:
			i++
		default:
			time.Sleep(10 * time.Millisecond)
		}
		if checked != lastPrint {
			printStdOut(int(checked), numberOfApps, "scenario4: check app params")
			lastPrint = checked
		}
	}
	close(checkAppChan)
	wg.Wait()

	require.EqualValues(t, numberOfApps, passed)
	for _, x := range globalStateCheck {
		require.True(t, x)
	}
}

// handles errors by channeling them between goroutines
func handleError(err error, message string, errChan chan<- error) {
	if err != nil {
		err2 := fmt.Errorf("%s: %v", message, err)
		select {
		// use select to avoid blocking when the errChan is not interested in messages.
		case errChan <- err2:
		default:
		}
	}
}

// handle the counters to prepare and send transactions in batches of MaxTxnLife transactions
func checkPoint(counter uint64, firstValid basics.Round, tLife basics.Round, force bool, fixture *fixtures.RestClientFixture, log logging.Logger) (newcounter uint64, nextFirstValid basics.Round, err error) {
	lastRound := firstValid + basics.Round(counter) - 1
	if force || basics.Round(counter) == tLife {
		if verbose {
			fmt.Printf("Waiting for round %d...", int(lastRound))
		}
		nodeStat, err := fixture.AlgodClient.WaitForRound(lastRound, time.Minute)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to wait for block %d : %w", lastRound, err)
		}
		return 0, nodeStat.LastRound + 1, nil
	}
	return counter, firstValid, nil
}

// signs and broadcasts a single transaction
func signAndBroadcastTransaction(
	round basics.Round,
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

	_, err = fixture.AlgodClient.SendRawTransaction(stxn)
	if err != nil {
		return err
	}
	err = fixture.WaitForRound(round, time.Millisecond*2000)
	return err
}

// queues transactions and packages them into maxTxGroupSize groups
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

// flushes the queue to push transaction groups with fewer than maxTxGroupSize transactions
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

// prepares an app creation transaction
func makeAppTransaction(
	t *testing.T,
	client libgoal.Client,
	counter uint64,
	round basics.Round,
	sender basics.Address,
	tLife basics.Round,
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
		transactions.OptInOC, approvalOps.Program, clearstateOps.Program, schema, schema, nil, libgoal.RefBundle{}, 0)
	require.NoError(t, err)

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  round,
		LastValid:   round + tLife,
		GenesisHash: genesisHash,
		Note:        note,
	}
	return
}

// prepares a opt-in app transaction
func makeOptInAppTransaction(
	t *testing.T,
	client libgoal.Client,
	appIdx basics.AppIndex,
	round basics.Round,
	sender basics.Address,
	tLife basics.Round,
	genesisHash crypto.Digest) (appTx transactions.Transaction) {

	appTx, err := client.MakeUnsignedAppOptInTx(appIdx, nil, libgoal.RefBundle{}, 0)
	require.NoError(t, err)

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  round,
		LastValid:   round + tLife,
		GenesisHash: genesisHash,
	}
	return
}

// checks and verifies the app params by comparing them against the baseline
func checkApplicationParams(
	acTF transactions.ApplicationCallTxnFields,
	app model.ApplicationParams,
	creator string,
	globalStateCheck *[]bool,
	globalStateCheckMu *deadlock.Mutex) (pass bool) {

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
	var oldVal bool
	globalStateCheckMu.Lock()
	oldVal = (*globalStateCheck)[(*app.GlobalState)[0].Value.Uint]
	(*globalStateCheck)[(*app.GlobalState)[0].Value.Uint] = true
	globalStateCheckMu.Unlock()
	if oldVal != false {
		return false
	}
	return pass
}

// creates accounts (public/secret key pairs)
func createAccounts(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	numberOfAccounts uint64,
	baseAcct psKey,
	firstValid basics.Round,
	balance uint64,
	counter uint64,
	tLife basics.Round,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	stopChan <-chan struct{},
	log logging.Logger) (newFirstValid basics.Round, newcounter uint64, keys []psKey) {

	log.Infof("Creating accounts...")

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
		printStdOut(i, numberOfAccounts, "account create txn")
		txn := sendAlgoTransaction(t, firstValid, baseAcct.pk, key.pk, balance, tLife, genesisHash)
		counter, txnGroup = queueTransaction(baseAcct.sk, txn, txnChan, txnGrpChan, counter, txnGroup)

		counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture, log)
		require.NoError(t, err)
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture, log)
	require.NoError(t, err)
	return firstValid, counter, keys
}

// prepare app call transaction
func callAppTransaction(
	t *testing.T,
	client libgoal.Client,
	appIdx basics.AppIndex,
	round basics.Round,
	sender basics.Address,
	tLife basics.Round,
	genesisHash crypto.Digest) (appTx transactions.Transaction) {

	appTx, err := client.MakeUnsignedAppNoOpTx(appIdx, nil, libgoal.RefBundle{}, 0)
	require.NoError(t, err)

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  round,
		LastValid:   round + tLife,
		GenesisHash: genesisHash,
	}
	return
}
