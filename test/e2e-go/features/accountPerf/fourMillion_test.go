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
const printFreequency = 100

func queuePayments(queueWg *sync.WaitGroup, c libgoal.Client, sigTxnChan <-chan *transactions.SignedTxn, errChan chan<- error) {
	for stxn := range sigTxnChan {
		if stxn == nil {
			break
		}
		for x := 0; x < 20; x++ { // retry only 20 times
			_, err := c.BroadcastTransaction(*stxn)
			if err == nil {
				break
			}
			fmt.Printf("Error broadcasting transaction: %v\n", err)
			select {
			// use select to avoid blocking when the errChan is not interested in messages.
			case errChan <- err:
			default:
			}
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
			break
		}
		walletHandle, err := client.GetUnencryptedWalletHandle()
		if err != nil {
			fmt.Printf("Error GetUnencryptedWalletHandle: %v\n", err)
			select {
			// use select to avoid blocking when the errChan is not interested in messages.
			case errChan <- err:
			default:
			}
		}

		stxn, err := client.SignTransactionWithWallet(walletHandle, nil, *txn)
		if err != nil {
			fmt.Printf("Error SignTransactionWithWallet: %v\n", err)
			select {
			// use select to avoid blocking when the errChan is not interested in messages.
			case errChan <- err:
			default:
			}
		}

		sigTxnChan <- &stxn
	}
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

	fixture.Setup(t, filepath.Join("nettemplates", "DevModeOneWalletFuture.json"))
	defer func() {
		hkWg.Wait()
		fixture.Shutdown()
	}()
	client := fixture.LibGoalClient

	accountList, err := fixture.GetWalletsSortedByBalance()
	require.NoError(t, err)
	baseAcct := accountList[0].Address

	txnChan := make(chan *transactions.Transaction, 100)
	sigTxnChan := make(chan *transactions.SignedTxn, 100)
	errChan := make(chan error, 100)
	stopChan := make(chan struct{}, 1)

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		sigWg.Add(1)
		go signer(&sigWg, client, txnChan, sigTxnChan, errChan)
	}

	suggestedParams, err := client.SuggestedParams()
	require.NoError(t, err)
	var genesisHash crypto.Digest
	copy(genesisHash[:], suggestedParams.GenesisHash)

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		queueWg.Add(1)
		go queuePayments(&queueWg, client, sigTxnChan, errChan)
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
			Amount:   basics.MicroAlgos{Raw: 10000000000},
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

	numberOfAccounts := uint64(100) // 6K
	numberOfAssets := uint64(2000)  // 6M

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

	fmt.Printf("Waiting for round %d...", int(round))
	fixture.WaitForRound(round, 10*time.Second)
	fmt.Printf("done\n")

	// have a single account opted in all of them
	ownAllAccount := createdAccounts[numberOfAccounts-1]
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

	fmt.Printf("Waiting for round %d...", int(round))
	fixture.WaitForRound(round, 10*time.Second)
	fmt.Printf("done\n")

	// Verify the assets are transfered here
	info, err := client.AccountInformationV2(ownAllAccount.String())
	require.NoError(t, err)
	require.Equal(t, len(*info.Assets), int(numberOfAssets))
	tAssetAmt := uint64(0)
	for _, asset := range *info.Assets {
		tAssetAmt += asset.Amount
	}
	if totalAssetAmount != tAssetAmt {
		fmt.Printf("%d != %d\n", totalAssetAmount, tAssetAmt)
	}
	require.Equal(t, totalAssetAmount, tAssetAmt)
}
