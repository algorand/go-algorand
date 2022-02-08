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
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const roundDelay = uint64(400) // should be greater than numberOfThreads
const numberOfThreads = 256
const printFreequency = 10
const groupTransactions = false
const channelDepth = 100

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
		for x := 0; x < 5; x++ { // retry only 20 times
			_, err = c.BroadcastTransaction(*stxn)
			if err == nil {
				break
			}
			handleError(err, "Error broadcasting transaction", errChan)
			time.Sleep(time.Millisecond * 256)
		}
	}
	queueWg.Done()
}

func broadcastTransactionGroups(queueWg *sync.WaitGroup, c libgoal.Client, sigTxnGrpChan <-chan []transactions.SignedTxn, errChan chan<- error) {
	for stxns := range sigTxnGrpChan {
		if stxns == nil {
			break
		}
		for x := 0; x < 20; x++ { // retry only 20 times
			err := c.BroadcastTransactionGroup(stxns)
			if err == nil {
				break
			}
			handleError(err, "Error broadcasting transaction", errChan)
			time.Sleep(time.Millisecond * 256)
		}
	}
	queueWg.Done()
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

/*
func signerGrpTxn(
	sigWg *sync.WaitGroup,
	client libgoal.Client,
	txnChan <-chan *txnKey,
	sigTxnGrpChan chan<- []transactions.SignedTxn,
	errChan chan<- error) {

	groupChan := make(chan []transactions.Transaction, 1)

	var groupWg sync.WaitGroup

	// group transactions and send

	groupWg.Add(1)
	go func() {
		for tGroup := range groupChan {
			gid, err := client.GroupID(tGroup)
			handleError(err, "Error GroupID", errChan)

			var stxns []transactions.SignedTxn
			for i, _ := range tGroup {
				tGroup[i].Group = gid

				var walletHandle []byte
				var err error
				for x := 0; x < 20; x++ {
					walletHandle, err = client.GetUnencryptedWalletHandle()
					if err == nil {
						break
					}
				}
				handleError(err, "Error GetUnencryptedWalletHandle", errChan)

				for x := 0; x < 20; x++ {
					stxn, err := client.SignTransactionWithWallet(walletHandle, nil, tGroup[i])
					if err == nil {
						stxns = append(stxns, stxn)
						break
					}
				}
				handleError(err, "Error SignTransactionWithWallet", errChan)
			}
			sigTxnGrpChan <- stxns
		}
		groupWg.Done()
	}()

	grpTransactions := make([]*transactions.Transaction, 0, maxTxGroupSize)

	for txn := range txnChan {

		if txn == nil { // if exsits transactions waiting to get grouped
			if len(grpTransactions) > 0 {
				sendTransactions := make([]transactions.Transaction, len(grpTransactions))
				for i, t := range grpTransactions {
					sendTransactions[i] = *t
				}
				groupChan <- sendTransactions
				grpTransactions = grpTransactions[:0]
			}
			continue
		}

		grpTransactions = append(grpTransactions, txn)
		if len(grpTransactions) == maxTxGroupSize {
			sendTransactions := make([]transactions.Transaction, maxTxGroupSize)
			for i, t := range grpTransactions {
				sendTransactions[i] = *t
			}
			groupChan <- sendTransactions
			grpTransactions = grpTransactions[:0]
		}
	}

	close(groupChan)
	groupWg.Wait()
	sigWg.Done()
}
*/
func zeroSub(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return 0
}

func Test5MAssets(t *testing.T) {
	partitiontest.PartitionTest(t)

	var fixture fixtures.RestClientFixture
	var sigWg sync.WaitGroup
	var queueWg sync.WaitGroup
	var hkWg sync.WaitGroup

	maxTxGroupSize = config.Consensus[protocol.ConsensusFuture].MaxTxGroupSize

	fixture.Setup(t, filepath.Join("nettemplates", "DevModeOneWalletFuture.json"))
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

	// fund the non-wallet base account
	ba := generateKeys(1)
	baseAcct := ba[0]
	sender, err := basics.UnmarshalChecksumAddress(wAcct)
	satxn := sendAlgoTransaction(t, 0, sender, baseAcct.pk, 100000000000000, 1, genesisHash)
	err = signAndBroadcastTransaction(0, &satxn, client, &fixture)
	require.NoError(t, err)

	txnChan := make(chan *txnKey, channelDepth)
	sigTxnChan := make(chan *transactions.SignedTxn, channelDepth)
	sigTxnGrpChan := make(chan []transactions.SignedTxn, channelDepth)
	errChan := make(chan error, channelDepth)
	stopChan := make(chan struct{}, 1)

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		sigWg.Add(1)
		if groupTransactions {
			//			go signerGrpTxn(&sigWg, client, txnChan, sigTxnGrpChan, errChan)
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
	go func() {
		errCount := 0
		for range errChan {
			errCount++
			if errCount > 100 {
				fmt.Println("Too many errors!")
				stopChan <- struct{}{}
				break
			}
		}
	}()

	// some housekeeping
	hkWg.Add(1)
	go func() {
		sigWg.Wait()
		close(sigTxnChan)
		close(sigTxnGrpChan)
		queueWg.Wait()
		close(errChan)
		hkWg.Done()
	}()

	// Call different scenarios
	scenarioA(t, &fixture, baseAcct, genesisHash, txnChan, stopChan)
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

	sround := zeroSub(round, roundDelay)
	txn = transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(sround),
			LastValid:   basics.Round(sround + tLife),
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
	round uint64,
	sender basics.Address,
	tLife uint64,
	amount uint64,
	genesisHash crypto.Digest) (assetTx transactions.Transaction) {

	sround := zeroSub(round, roundDelay)
	assetTx = transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(sround),
			LastValid:   basics.Round(sround + tLife),
			GenesisHash: genesisHash,
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

	sround := zeroSub(round, roundDelay)
	tx = transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(sround),
			LastValid:   basics.Round(sround + tLife),
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

func scenarioA(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	baseAcct psKey,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	stopChan <-chan struct{}) {

	client := fixture.LibGoalClient

	// create 6M unique assets by a different 6,000 accounts, and have a single account opted in, and owning all of them
	numberOfAccounts := uint64(6000) // 6K
	numberOfAssets := uint64(600000) // 6M

	assetsPerAccount := numberOfAssets / numberOfAccounts

	balance := uint64(200000000) // 100300000 for (1002 assets)

	params, err := client.SuggestedParams()
	require.NoError(t, err)
	tLife := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)].MaxTxnLife

	round := uint64(1)
	totalAssetAmount := uint64(0)

	defer func() {
		close(txnChan)
	}()

	xround := uint64(0)

	fmt.Println("Creating accounts...")

	// create 6K accounts
	keys := generateKeys(int(numberOfAccounts))
	for i, key := range keys {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}
		if i%printFreequency == 0 {
			fmt.Println("account create txn: ", i)
		}
		txn := sendAlgoTransaction(t, round, baseAcct.pk, key.pk, balance, tLife, genesisHash)
		tk := txnKey{tx: txn, sk: baseAcct.sk}
		txnChan <- &tk
		round++
		if round%(tLife/2) == 0 {
			txnChan <- nil
			round = checkPoint(round, 0, fixture)
			require.Greater(t, round, uint64(0))
			xround = round
		}
	}

	txnChan <- nil
	round = checkPoint(round, 0, fixture)
	require.Greater(t, round, uint64(0))
	xround = round
	fmt.Println("Creating assets...")

	// create 6M unique assets by a different 6,000 accounts
	for nai, na := range keys {
		for asi := uint64(0); asi < assetsPerAccount; asi++ {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}

			if nai%printFreequency == 0 && int(asi)%printFreequency == 0 {
				fmt.Printf("create asset for acct: %d asset %d\n", nai, asi)
			}
			atx := createAssetTransaction(t, round, na.pk, tLife, 90000000+round, genesisHash)
			tk := txnKey{tx: atx, sk: na.sk}
			txnChan <- &tk
			totalAssetAmount += 90000000 + round
			round++
			if round%(tLife/2) == 0 {
				txnChan <- nil
				round = checkPoint(round, 0, fixture)
				require.Greater(t, round, uint64(0))
				xround = round
			}

		}
	}

	txnChan <- nil
	round = checkPoint(round, xround, fixture)
	require.Greater(t, round, uint64(0))
	xround = round
	fmt.Println("Opt-in assets...")

	// have a single account opted in all of them
	ownAllAccount := keys[numberOfAccounts-1]
	// make ownAllAccount very rich
	sendAlgoTx := sendAlgoTransaction(t, round, baseAcct.pk, ownAllAccount.pk, 100000000000, tLife, genesisHash)
	tk := txnKey{tx: sendAlgoTx, sk: baseAcct.sk}
	txnChan <- &tk

	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := client.AccountInformationV2(nacc.pk.String())
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
				round,
				ownAllAccount.pk,
				tLife,
				genesisHash,
				basics.AssetIndex(asset.AssetId),
				ownAllAccount.pk,
				uint64(0))
			tk := txnKey{tx: optInT, sk: ownAllAccount.sk}
			txnChan <- &tk
			round++
			if round%(tLife/2) == 0 {
				txnChan <- nil
				round = checkPoint(round, 0, fixture)
				require.Greater(t, round, uint64(0))
				xround = round
			}

		}
	}

	txnChan <- nil
	round = checkPoint(round, xround, fixture)
	require.Greater(t, round, uint64(0))
	xround = round
	fmt.Println("Transfer assets...")

	// and owning all of them
	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := client.AccountInformationV2(nacc.pk.String())
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
			optInT := sendAssetTransaction(
				t,
				round,
				nacc.pk,
				tLife,
				genesisHash,
				basics.AssetIndex(asset.AssetId),
				ownAllAccount.pk,
				asset.Amount)
			tk := txnKey{tx: optInT, sk: nacc.sk}
			txnChan <- &tk
			round++
			if round%(tLife/2) == 0 {
				txnChan <- nil
				round = checkPoint(round, 0, fixture)
				require.Greater(t, round, uint64(0))
				xround = round
			}

		}
	}

	txnChan <- nil
	round = checkPoint(round, xround, fixture)
	require.Greater(t, round, uint64(0))
	xround = round

	// Verify the assets are transfered here
	info, err := client.AccountInformationV2(ownAllAccount.pk.String())
	require.NoError(t, err)
	require.Equal(t, int(numberOfAssets), len(*info.Assets))
	tAssetAmt := uint64(0)
	for _, asset := range *info.Assets {
		tAssetAmt += asset.Amount
	}
	if totalAssetAmount != tAssetAmt {
		fmt.Printf("%d != %d\n", totalAssetAmount, tAssetAmt)
	}
	require.Equal(t, totalAssetAmount, tAssetAmt)
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

func checkPoint(round, xround uint64, fixture *fixtures.RestClientFixture) uint64 {
	if groupTransactions {
		round = (round-xround+uint64(maxTxGroupSize-1))/uint64(maxTxGroupSize) + xround
	}
	fmt.Printf("Waiting for round %d...", int(round))
	err := fixture.WaitForRound(round, channelDepth*time.Millisecond*200*1000)
	if err == nil {
		fmt.Printf("done\n")
	} else {
		fmt.Printf("failed\n")
		return 0
	}
	return round
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
