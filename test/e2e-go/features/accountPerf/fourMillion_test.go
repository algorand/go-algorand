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

func queuePayments(queueWg *sync.WaitGroup, c libgoal.Client, q <-chan *transactions.SignedTxn) {
	counter := 0
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
			time.Sleep(config.Consensus[protocol.ConsensusCurrentVersion].AgreementFilterTimeout)
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
		if err != nil {
			fmt.Printf("Error signing: %v\n", err)
		}
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

	numberOfThreads := 8

	accountList, err := fixture.GetWalletsSortedByBalance()
	require.NoError(t, err)
	baseAcct := accountList[0].Address

	status, err := client.Status()
	require.NoError(t, err)
	var sigWg sync.WaitGroup
	var queueWg sync.WaitGroup
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

	// Call to different scenarios
	go scenarioA(t, client, baseAcct, genesisHash, txnChan)

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		queueWg.Add(1)
		go queuePayments(&queueWg, client, sigTxnChan)
	}

	sigWg.Wait()
	close(sigTxnChan)
	queueWg.Wait()
	status, err = client.Status()
	require.NoError(t, err)

	var tx transactions.Transaction
	for {
		tx, err = client.SendPaymentFromUnencryptedWallet(baseAcct, baseAcct, config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee, 0, nil)
		if err == nil {
			break
		}

		fmt.Printf("Error broadcasting final transaction: %v\n", err)
		time.Sleep(config.Consensus[protocol.ConsensusCurrentVersion].AgreementFilterTimeout)
	}
	_, err = fixture.WaitForConfirmedTxn(status.LastRound+100, baseAcct, tx.ID().String())
	fmt.Printf("Waiting for confirmation transaction to commit..\n")
	require.NoError(t, err)
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

	sround := zeroSub(round, 200)
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

func createAssetTransaction(
	t *testing.T,
	round uint64,
	sender basics.Address,
	tLife uint64,
	genesisHash crypto.Digest) (assetTx transactions.Transaction) {

	sround := zeroSub(round, 200)
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
				Total:         100+round,
				DefaultFrozen: false,
				Manager:       sender,
			},
		},
	}
	return
}

func scenarioA(
	t *testing.T,
	client libgoal.Client,
	baseAcct string,
	genesisHash crypto.Digest,
	txnChan chan<- *transactions.Transaction) {

	numberOfAccounts := 600 // 6K
	numberOfAssets := 60000   // 6M

	assetsPerAccount := numberOfAssets / numberOfAccounts

	sender, err := basics.UnmarshalChecksumAddress(baseAcct)
	require.NoError(t, err)

	params, err := client.SuggestedParams()
	require.NoError(t, err)
	tLife := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)].MaxTxnLife

	createdAccounts := make([]basics.Address, 0, numberOfAccounts)
	
	round := uint64(0)
	for txi := 0; txi < numberOfAccounts; txi++ {
		if txi%100 == 0 {
			fmt.Println("account create txn: ", txi)
		}
		txn, newAccount := activateAccountTransaction(t, client, round, sender, tLife, genesisHash)
		txnChan <- &txn

		createdAccounts = append(createdAccounts, newAccount)
		round++
	}

	for nai, na := range createdAccounts {
		for asi := 0; asi < assetsPerAccount; asi++ {
			if asi%100 == 0 {
				fmt.Printf("asset create: acct: %d asset %d\n", nai, asi)
			}

			atx := createAssetTransaction(t, round, na, tLife, genesisHash)
			txnChan <- &atx
			round++
		}
	}

	close(txnChan)
}
