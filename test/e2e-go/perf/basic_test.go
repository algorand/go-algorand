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

package algod

import (
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func queuePayments(b *testing.B, wg *sync.WaitGroup, c libgoal.Client, q <-chan *transactions.SignedTxn) {
	for {
		stxn := <-q
		if stxn == nil {
			break
		}

		for {
			_, err := c.BroadcastTransaction(*stxn)
			if err == nil {
				break
			}

			fmt.Printf("Error broadcasting transaction: %v\n", err)
			time.Sleep(config.Consensus[protocol.ConsensusCurrentVersion].AgreementFilterTimeout)
		}
	}

	wg.Done()
}

func signer(b *testing.B, wg *sync.WaitGroup, c libgoal.Client, wh []byte, txnChan <-chan *transactions.Transaction, sigTxnChan chan<- *transactions.SignedTxn) {
	for {
		txn := <-txnChan
		if txn == nil {
			break
		}

		stxn, err := c.SignTransactionWithWallet(wh, nil, *txn)
		if err != nil {
			fmt.Printf("Error signing: %v\n", err)
		}
		a.NoError(err)

		sigTxnChan <- &stxn
	}

	wg.Done()
}

func BenchmarkPaymentsThroughput(b *testing.B) {
	// doBenchTemplate(b, "perf/OneNodeOneWalletBigBlocks.json", "Primary")
	//doBenchTemplate(b, "perf/FourNodes25Each.json", "Node2")
	doBenchTemplate(b, "perf/FiveNodes50WalletsWithRelay.json", "Node0")
}

func doBenchTemplate(b *testing.B, template string, moneynode string) {
	fmt.Printf("Starting to benchmark template %s\n", template)

	// consensusTestBigBlocks is a version of ConsensusV0 used for testing
	// with big block size (large MaxTxnBytesPerBlock).
	// at the time versioning was introduced.
	const consensusTestBigBlocks = protocol.ConsensusVersion("test-big-blocks")

	var fixture fixtures.RestClientFixture

	testBigBlocks := config.Consensus[protocol.ConsensusCurrentVersion]
	testBigBlocks.MaxTxnBytesPerBlock = 100000000
	testBigBlocks.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}

	fixture.SetConsensus(config.ConsensusProtocols{
		consensusTestBigBlocks: testBigBlocks,
	})
	fixture.Setup(b, filepath.Join("nettemplates", template))
	defer fixture.Shutdown()

	c := fixture.GetLibGoalClientForNamedNode(moneynode)

	wallet, err := c.GetUnencryptedWalletHandle()
	a.NoError(err)

	addrs, err := c.ListAddresses(wallet)
	a.NoError(err)
	require.True(b, len(addrs) > 0)
	addr := addrs[0]

	suggest, err := c.SuggestedParams()
	a.NoError(err)

	var genesisHash crypto.Digest
	copy(genesisHash[:], suggest.GenesisHash)

	// Increase the number of keepalive connections, since we use many
	// goroutines to talk to algod and kmd.
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 100

	var status generatedV2.NodeStatusResponse

	b.Run(template, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			numTransactions := 100000

			b.StopTimer()

			fmt.Printf("Pre-signing %d transactions..\n", numTransactions)
			wh, err := c.GetUnencryptedWalletHandle()
			a.NoError(err)

			var sigWg sync.WaitGroup
			txnChan := make(chan *transactions.Transaction, 100)
			sigTxnChan := make(chan *transactions.SignedTxn, 100)
			for nthread := 0; nthread < 10; nthread++ {
				sigWg.Add(1)
				go signer(b, &sigWg, c, wh, txnChan, sigTxnChan)
			}

			go func() {
				sender, err := basics.UnmarshalChecksumAddress(addr)
				a.NoError(err)

				round, err := c.CurrentRound()
				a.NoError(err)

				params, err := c.SuggestedParams()
				a.NoError(err)
				proto := config.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]

				for txi := 0; txi < numTransactions; txi++ {
					var dst basics.Address
					crypto.RandBytes(dst[:])

					txn := transactions.Transaction{
						Type: protocol.PaymentTx,
						Header: transactions.Header{
							Sender:      sender,
							Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
							FirstValid:  basics.Round(round),
							LastValid:   basics.Round(round) + basics.Round(proto.MaxTxnLife),
							GenesisHash: genesisHash,
						},
						PaymentTxnFields: transactions.PaymentTxnFields{
							Receiver: dst,
							Amount:   basics.MicroAlgos{Raw: 100000},
						},
					}

					txnChan <- &txn
				}
				close(txnChan)

				sigWg.Wait()
				close(sigTxnChan)
			}()

			var sigTxns []*transactions.SignedTxn
			for {
				stxn := <-sigTxnChan
				if stxn == nil {
					break
				}

				sigTxns = append(sigTxns, stxn)
			}

			status, err = c.Status()
			a.NoError(err)

			fmt.Printf("Waiting for round %d to start benchmark..\n", status.LastRound+1)
			status, err = c.WaitForRound(status.LastRound + 1)
			a.NoError(err)

			b.StartTimer()

			fmt.Printf("Starting to issue %d transactions\n", numTransactions)

			var queueWg sync.WaitGroup
			queueTxns := make(chan *transactions.SignedTxn, 100)
			for nthread := 0; nthread < 10; nthread++ {
				queueWg.Add(1)
				go queuePayments(b, &queueWg, c, queueTxns)
			}

			for _, stxn := range sigTxns {
				queueTxns <- stxn
			}
			close(queueTxns)

			fmt.Printf("Waiting for transactions to be queued to algod..\n")
			queueWg.Wait()

			// Now, send a payment with low fee, so that when this transaction
			// clears, we can infer that all previous transactions also cleared.
			var tx transactions.Transaction
			for {
				tx, err = c.SendPaymentFromUnencryptedWallet(addr, addr, config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee, 0, nil)
				if err == nil {
					break
				}

				fmt.Printf("Error broadcasting final transaction: %v\n", err)
				time.Sleep(5 * time.Second)
			}

			_, err = fixture.WaitForConfirmedTxn(status.LastRound+100, addr, tx.ID().String())
			fmt.Printf("Waiting for confirmation transaction to commit..\n")
			a.NoError(err)
		}
	})

	fmt.Printf("Block size statistics:\n")
	for round := status.LastRound + 1; ; round++ {
		blk, err := c.Block(round)
		if err != nil {
			break
		}

		fmt.Printf("  %d: %d txns\n", round, len(blk.Transactions.Transactions))
	}
}
