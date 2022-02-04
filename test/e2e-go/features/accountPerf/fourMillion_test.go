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

const roundDelay = uint64(200)

func queuePayments(queueWg *sync.WaitGroup, c libgoal.Client, q <-chan *transactions.SignedTxn) {
	counter := 0
	failures := 0
	for stxn := range q {

		if stxn == nil {
			break
		}
		for {
			_, err := c.BroadcastTransaction(*stxn)
			if err == nil {
				counter++
				break
			}
			fmt.Printf("Error broadcasting transaction: %v\n", err)
			if failures > 100 {
				break
			}
			time.Sleep(time.Millisecond * 250)
			failures++
		}
	}
	queueWg.Done()
}

func signer(t *testing.T, sigWg *sync.WaitGroup, client libgoal.Client, txnChan <-chan *transactions.Transaction, sigTxnChan chan<- *transactions.SignedTxn) {
	for txn := range txnChan {
		if txn == nil {
			break
		}
		walletHandle, err := client.GetUnencryptedWalletHandle()
		require.NoError(t, err)

		stxn, err := client.SignTransactionWithWallet(walletHandle, nil, *txn)
		require.NoError(t, err)
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

	fixture.Setup(t, filepath.Join("nettemplates", "DevModeOneWallet.json"))
	defer fixture.Shutdown()
	client := fixture.LibGoalClient

	numberOfThreads := 128

	accountList, err := fixture.GetWalletsSortedByBalance()
	require.NoError(t, err)
	baseAcct := accountList[0].Address

	var sigWg sync.WaitGroup
	var queueWg sync.WaitGroup
	var hkWg sync.WaitGroup
	txnChan := make(chan *transactions.Transaction, 100)
	sigTxnChan := make(chan *transactions.SignedTxn, 100)

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		sigWg.Add(1)
		go signer(t, &sigWg, client, txnChan, sigTxnChan)
	}

	suggestedParams, err := client.SuggestedParams()
	require.NoError(t, err)
	var genesisHash crypto.Digest
	copy(genesisHash[:], suggestedParams.GenesisHash)

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		queueWg.Add(1)
		go queuePayments(&queueWg, client, sigTxnChan)
	}

	// some housekeeping
	hkWg.Add(1)
	go func() {
		sigWg.Wait()
		close(sigTxnChan)
		queueWg.Wait()
		hkWg.Done()
	}()

	lastRound := uint64(0)
	// Call different scenarios
	lastRound = scenarioA(t, &fixture, baseAcct, genesisHash, txnChan)
	hkWg.Wait()
	fixture.WaitForRound(lastRound, 1000*time.Second)
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
	txnChan chan<- *transactions.Transaction) uint64 {

	client := fixture.LibGoalClient

	// create 6M unique assets by a different 6,000 accounts, and have a single account opted in, and owning all of them

	numberOfAccounts := uint64(600) // 6K
	numberOfAssets := uint64(6000)   // 6M

	assetsPerAccount := numberOfAssets / numberOfAccounts

	sender, err := basics.UnmarshalChecksumAddress(baseAcct)
	require.NoError(t, err)

	params, err := client.SuggestedParams()
	require.NoError(t, err)
	tLife := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)].MaxTxnLife

	createdAccounts := make([]basics.Address, 0, numberOfAccounts)

	round := uint64(0)

	totalAssetAmount := uint64(0)

	// create 6K accounts
	for txi := uint64(0); txi < numberOfAccounts; txi++ {
		if txi%100 == 0 {
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
			if nai%100 == 0 && asi%100 == 0 {
				fmt.Printf("create asset for acct: %d asset %d\n", nai, asi)
			}
			atx := createAssetTransaction(t, round, na, tLife, 90000000+round, genesisHash)
			txnChan <- &atx
			totalAssetAmount += 90000000 + round
			round++
		}
	}

	fixture.WaitForRound(round, 1000*time.Second)

	// have a single account opted in all of them
	ownAllAccount := createdAccounts[numberOfAccounts-1]
	for acci, nacc := range createdAccounts {
		if nacc == ownAllAccount {
			continue
		}
		info, err := client.AccountInformationV2(nacc.String())
		require.NoError(t, err)
		for assi, asset := range *info.Assets {
			if assi%100 == 0 && acci%100 == 0 {
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
			if assi%100 == 0 && acci%100 == 0 {
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

	close(txnChan)

	fixture.WaitForRound(round, 1000*time.Second)

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
	return round
}
