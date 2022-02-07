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

const roundDelay = uint64(400) // should be greate than numberOfThreads
const numberOfThreads = 256
const printFreequency = 10
const groupTransactions = false
const channelDepth = 1

var maxTxGroupSize int

func broadcastTransactions(queueWg *sync.WaitGroup, c libgoal.Client, sigTxnChan <-chan *transactions.SignedTxn, errChan chan<- error) {
	for stxn := range sigTxnChan {
		if stxn == nil {
			break
		}
		for x := 0; x < 20; x++ { // retry only 20 times
			_, err := c.BroadcastTransaction(*stxn)
			if err == nil {
				break
			}
			handleError(err, "Error broadcasting transaction", errChan)
			time.Sleep(time.Millisecond * 256)
		}
	}
	queueWg.Done()
}

func broadcastTransactionGroups(queueWg *sync.WaitGroup, c libgoal.Client, sigTxnGrpChan <-chan *[]transactions.SignedTxn, errChan chan<- error) {
	for stxns := range sigTxnGrpChan {
		if stxns == nil {
			break
		}
		for x := 0; x < 20; x++ { // retry only 20 times
			err := c.BroadcastTransactionGroup(*stxns)
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
	txnChan <-chan *transactions.Transaction,
	sigTxnChan chan<- *transactions.SignedTxn,
	errChan chan<- error) {

	for txn := range txnChan {
		if txn == nil {
			continue
		}
		walletHandle, err := client.GetUnencryptedWalletHandle()
		handleError(err, "Error GetUnencryptedWalletHandle", errChan)

		stxn, err := client.SignTransactionWithWallet(walletHandle, nil, *txn)
		handleError(err, "Error SignTransactionWithWallet", errChan)

		sigTxnChan <- &stxn
	}
	sigWg.Done()
}

func signerGrpTxn(
	sigWg *sync.WaitGroup,
	client libgoal.Client,
	txnChan <-chan *transactions.Transaction,
	sigTxnGrpChan chan<- *[]transactions.SignedTxn,
	errChan chan<- error) {

	groupChan := make(chan []transactions.Transaction, 1)

	var groupWg sync.WaitGroup

	// group transactions and send

	groupWg.Add(1)
	go func() {
		for tGroup := range groupChan {
			gid, err := client.GroupID(tGroup)
			handleError(err, "Error GetUnencryptedWalletHandle", errChan)

			var stxns []transactions.SignedTxn
			for i, _ := range tGroup {
				tGroup[i].Group = gid

				walletHandle, err := client.GetUnencryptedWalletHandle()
				handleError(err, "Error GetUnencryptedWalletHandle", errChan)

				stxn, err := client.SignTransactionWithWallet(walletHandle, nil, tGroup[i])
				handleError(err, "Error SignTransactionWithWallet", errChan)

				stxns = append(stxns, stxn)
			}
			sigTxnGrpChan <- &stxns
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
	baseAcct := accountList[0].Address

	txnChan := make(chan *transactions.Transaction, channelDepth)
	sigTxnChan := make(chan *transactions.SignedTxn, channelDepth)
	sigTxnGrpChan := make(chan *[]transactions.SignedTxn, channelDepth)
	errChan := make(chan error, channelDepth)
	stopChan := make(chan struct{}, 1)

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		sigWg.Add(1)
		if groupTransactions {
			go signerGrpTxn(&sigWg, client, txnChan, sigTxnGrpChan, errChan)
		} else {
			go signer(&sigWg, client, txnChan, sigTxnChan, errChan)
		}
	}

	suggestedParams, err := client.SuggestedParams()
	require.NoError(t, err)
	var genesisHash crypto.Digest
	copy(genesisHash[:], suggestedParams.GenesisHash)

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

func activateAccountTransaction(
	t *testing.T,
	client libgoal.Client,
	round uint64,
	sender basics.Address,
	tLife uint64,
	genesisHash crypto.Digest) (txn transactions.Transaction, receiver basics.Address) {

	walletHandle, err := client.GetUnencryptedWalletHandle()
	require.NoError(t, err)

	address, err := client.GenerateAddress(walletHandle)
	require.NoError(t, err)

	receiver, err = basics.UnmarshalChecksumAddress(address)
	require.NoError(t, err)

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
			Amount:   basics.MicroAlgos{Raw: 100000000},
		},
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
	baseAcct string,
	genesisHash crypto.Digest,
	txnChan chan<- *transactions.Transaction,
	stopChan <-chan struct{}) {

	client := fixture.LibGoalClient

	// create 6M unique assets by a different 6,000 accounts, and have a single account opted in, and owning all of them
	numberOfAccounts := uint64(6000) // 6K
	numberOfAssets := uint64(600000) // 6M

	assetsPerAccount := numberOfAssets / numberOfAccounts

	sender, err := basics.UnmarshalChecksumAddress(baseAcct)
	require.NoError(t, err)

	params, err := client.SuggestedParams()
	require.NoError(t, err)
	tLife := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)].MaxTxnLife

	createdAccounts := make([]basics.Address, 0, numberOfAccounts)

	round := uint64(0)

	totalAssetAmount := uint64(0)

	defer func() {
		close(txnChan)
	}()

	fmt.Println("Creating accounts...")

	// create 6K accounts
	for txi := uint64(0); txi < numberOfAccounts; txi++ {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}
		if int(txi)%printFreequency == 0 {
			fmt.Println("account create txn: ", txi)
		}
		txn, newAccount := activateAccountTransaction(t, client, round, sender, tLife, genesisHash)
		txnChan <- &txn

		createdAccounts = append(createdAccounts, newAccount)
		round++
	}

	txnChan <- nil
	round = checkPoint(round, 0, fixture)
	xround := round
	fmt.Println("Creating assets...")

	// create 6M unique assets by a different 6,000 accounts
	for nai, na := range createdAccounts {
		for asi := uint64(0); asi < assetsPerAccount; asi++ {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}

			if nai%printFreequency == 0 && int(asi)%printFreequency == 0 {
				fmt.Printf("create asset for acct: %d asset %d\n", nai, asi)
			}
			atx := createAssetTransaction(t, round, na, tLife, 90000000+round, genesisHash)
			txnChan <- &atx
			totalAssetAmount += 90000000 + round
			round++
		}
	}

	txnChan <- nil
	round = checkPoint(round, xround, fixture)
	xround = round
	fmt.Println("Opt-in assets...")

	// have a single account opted in all of them
	ownAllAccount := createdAccounts[numberOfAccounts-1]
	sendAlgoTx := sendAlgoTransaction(t, round, sender, ownAllAccount, 100000000000, tLife, genesisHash)
	txnChan <- &sendAlgoTx

	for acci, nacc := range createdAccounts {
		if nacc == ownAllAccount {
			continue
		}
		info, err := client.AccountInformationV2(nacc.String())
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
				ownAllAccount,
				tLife,
				genesisHash,
				basics.AssetIndex(asset.AssetId),
				ownAllAccount,
				uint64(0))
			txnChan <- &optInT
			round++
		}
	}

	txnChan <- nil
	round = checkPoint(round, xround, fixture)
	xround = round
	fmt.Println("Transfer assets...")

	// and owning all of them
	for acci, nacc := range createdAccounts {
		if nacc == ownAllAccount {
			continue
		}
		info, err := client.AccountInformationV2(nacc.String())
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
				nacc,
				tLife,
				genesisHash,
				basics.AssetIndex(asset.AssetId),
				ownAllAccount,
				asset.Amount)
			txnChan <- &optInT
			round++
		}
	}

	txnChan <- nil
	round = checkPoint(round, xround, fixture)
	xround = round

	// Verify the assets are transfered here
	info, err := client.AccountInformationV2(ownAllAccount.String())
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
	err := fixture.WaitForRound(round, 200*time.Second)
	if err == nil {
		fmt.Printf("done\n")
	} else {
		fmt.Printf("failed\n")
	}
	return round
}
