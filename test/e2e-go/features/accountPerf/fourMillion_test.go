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

// Check that devmode is functioning as designed.
package devmode

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

func queuePayments(wg *sync.WaitGroup, c libgoal.Client, q <-chan *transactions.SignedTxn) {
	counter := 0
	for stxn := range q{
		
		if stxn == nil {
			break
		}
		for {
			_, err := c.BroadcastTransaction(*stxn)
			if err == nil {
				counter++
				if counter % 100 == 0 {
					fmt.Println("broadcasted: ", counter)
				}
				break
			}

			fmt.Printf("Error broadcasting transaction: %v\n", err)
			time.Sleep(config.Consensus[protocol.ConsensusCurrentVersion].AgreementFilterTimeout)
		}
	}
	wg.Done()
}

func signer(t *testing.T, wg *sync.WaitGroup, client libgoal.Client, txnChan <-chan *transactions.Transaction, sigTxnChan chan<- *transactions.SignedTxn) {
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
	wg.Done()
}

func zeroSub(a, b int) int {
	if a > b {
		return a-b
	}
	return 0	
}

func Test5MAssets(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Make the network progress faster
	consensus := make(config.ConsensusProtocols)
	fastProtocol := config.Consensus[protocol.ConsensusCurrentVersion]
	fastProtocol.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	fastProtocol.AgreementFilterTimeoutPeriod0 = 400 * time.Millisecond
	fastProtocol.AgreementFilterTimeout = 400 * time.Millisecond
	//	consensus[protocol.ConsensusFuture] = fastProtocol
	consensus[protocol.ConsensusCurrentVersion] = fastProtocol

	// Setup the fixture with the modified fast consensus
	var fixture fixtures.RestClientFixture
	//	fixture.SetConsensus(consensus)

	fixture.Setup(t, filepath.Join("nettemplates", "DevModeOneWallet.json")) //OneNodeFuture.json"))//DevModeOneWallet.json"))
	// fixture.Setup(t, filepath.Join("nettemplates", "OneNodeFuture.json"))//OneNodeFuture.json"))//DevModeOneWallet.json"))
	defer fixture.Shutdown()
	client := fixture.LibGoalClient

	numberOfAccounts := 6000 // 6K
	//	numberOfAssets := 60     // 6M

	// We will create three new accounts, transfer some amount of money into
	// the first account, and then transfer a smaller amount to the second
	// account while closing out the rest into the third.

	accountList, err := fixture.GetWalletsSortedByBalance()
	require.NoError(t, err)
	baseAcct := accountList[0].Address

	status, err := client.Status()
	require.NoError(t, err)
	fmt.Println(status)
	if true {
		var sigWg sync.WaitGroup
		txnChan := make(chan *transactions.Transaction, 100)
		sigTxnChan := make(chan *transactions.SignedTxn, 100)
		for nthread := 0; nthread < 10; nthread++ {
			sigWg.Add(1)
			go signer(t, &sigWg, client, txnChan, sigTxnChan)
		}


		suggestedParams, err := client.SuggestedParams()
		require.NoError(t, err)
		var genesisHash crypto.Digest
		copy(genesisHash[:], suggestedParams.GenesisHash)


		go func() {
			sender, err := basics.UnmarshalChecksumAddress(baseAcct)
			require.NoError(t, err)

			params, err := client.SuggestedParams()
			require.NoError(t, err)
			proto := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]

			round := 0
			for txi := 0; txi < numberOfAccounts; txi++ {
				if txi%100 == 0 {
					fmt.Println("making txn: ", txi)
				}

				walletHandle, err := client.GetUnencryptedWalletHandle()
				require.NoError(t, err)

				accti, err := client.GenerateAddress(walletHandle)
				require.NoError(t, err)

				receiver, err := basics.UnmarshalChecksumAddress(accti)
				require.NoError(t, err)

				sround := zeroSub(round, 200)
				txn := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:      sender,
						Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
						FirstValid:  basics.Round(sround),
						LastValid:   basics.Round(sround) + basics.Round(proto.MaxTxnLife),
						GenesisHash: genesisHash,
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 100000},
					},
				}
				round++
				txnChan <- &txn
			}
			fmt.Println("******************** closing txnChan")
			close(txnChan)

			sigWg.Wait()
			fmt.Println("******************** closing sigTxnChan")
			close(sigTxnChan)
		}()

		var queueWg sync.WaitGroup
		queueTxns := make(chan *transactions.SignedTxn, 100)

		go func() {		
			//		var sigTxns []*transactions.SignedTxn
			for stxn := range sigTxnChan{
				
				if stxn == nil {
					break
				}
				queueTxns <- stxn
				//			sigTxns = append(sigTxns, stxn)
			}
			fmt.Println("******************** closing queueTxns")
			close(queueTxns)

		}()

		for nthread := 0; nthread < 10; nthread++ {
			queueWg.Add(1)
			go queuePayments(&queueWg, client, queueTxns)
		}

		queueWg.Wait()
		status, err = client.Status()
		require.NoError(t, err)

		fmt.Printf("Waiting for round %d to start benchmark..\n", status.LastRound+1)
		//		status, err = client.WaitForRound(status.LastRound + 1)
		//		require.NoError(t, err)


		fmt.Printf("Starting to issue %d transactions\n", numberOfAccounts)


		//		for _, stxn := range sigTxns {
		//			queueTxns <- stxn
		//		}
		//		close(queueTxns)

		fmt.Printf("Waiting for transactions to be queued to algod..\n")
		queueWg.Wait()

		fmt.Printf("wait done..\n")

		// Now, send a payment with low fee, so that when this transaction
		// clears, we can infer that all previous transactions also cleared.
		var tx transactions.Transaction
		for {
			tx, err = client.SendPaymentFromUnencryptedWallet(baseAcct, baseAcct, config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee, 0, nil)
			if err == nil {
				break
			}

			fmt.Printf("Error broadcasting final transaction: %v\n", err)
			time.Sleep(5 * time.Second)
		}
		_, err = fixture.WaitForConfirmedTxn(status.LastRound+100, baseAcct, tx.ID().String())
		fmt.Printf("Waiting for confirmation transaction to commit..\n")
		require.NoError(t, err)
	}



	/*

	
	// Transfer some money to acct0, as well as other random accounts to
	// fill up the Merkle tree with more than one element.
	for i := 0; i < numberOfAccounts; i++ {
		
		walletHandle, err := client.GetUnencryptedWalletHandle()
		require.NoError(t, err)

		accti, err := client.GenerateAddress(walletHandle)
		require.NoError(t, err)

		if i%10 == 0 {
			fmt.Println("done: ", i)
		}

		for x := 0; x < 5; x++ {
			_, err = client.SendPaymentFromUnencryptedWallet(baseAcct, accti, 1000, 10000000, nil)
			if err == nil {
				break
			}
			fmt.Println(err)
			time.Sleep(1 * time.Second)
			fmt.Println(x)
			//			require.NoError(t, err)
		}

		for j := 0; j < numberOfAssets/numberOfAccounts; j++ {

		}

	}
*/
	fmt.Println("done")

	/*

		// Start devmode network, and make sure everything is primed by sending a transaction.
		var fixture fixtures.RestClientFixture
		fixture.SetupNoStart(t, filepath.Join("nettemplates", "DevModeOneWallet.json"))
		fixture.Start()
		defer fixture.Shutdown()
		sender, err := fixture.GetRichestAccount()
		require.NoError(t, err)


		// Add accounts
		key := crypto.GenerateSignatureSecrets(crypto.Seed{})
		receiver := basics.Address(key.SignatureVerifier)
		txn := fixture.SendMoneyAndWait(0, 100000, 1000, sender.Address, receiver.String(), "")


		txn = fixture.SendMoneyAndWait(0, 333, 1000, receiver.Address, sender.String(), "")
		fmt.Println(txn)

	*/
}
