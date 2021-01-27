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

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/passphrase"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/common"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const transactionBlockSize = 800

var nroutines = runtime.NumCPU() * 2

func loadMnemonic(mnemonic string) crypto.Seed {
	seedbytes, err := passphrase.MnemonicToKey(mnemonic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot recover key seed from mnemonic: %v\n", err)
		os.Exit(1)
	}

	var seed crypto.Seed
	copy(seed[:], seedbytes)
	return seed
}

func main() {
	var cfg config
	var err error
	if cfg, err = loadConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "unable to load config : %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Configuration file loaded successfully.\n")

	seed := loadMnemonic(cfg.AccountMnemonic)
	privateKey := crypto.GenerateSignatureSecrets(seed)
	publicKey := basics.Address(privateKey.SignatureVerifier)

	fmt.Printf("Spending account public key : %v\n", publicKey.String())

	err = spendLoop(cfg, privateKey, publicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spend loop error : %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}

func isSpendRound(cfg config, round uint64) bool {
	return cfg.RoundModulator == 0 || ((round+cfg.RoundOffset)%cfg.RoundModulator == 0)
}

func nextSpendRound(cfg config, round uint64) uint64 {
	if cfg.RoundModulator == 0 {
		return round
	}
	return ((round+cfg.RoundOffset)/cfg.RoundModulator)*cfg.RoundModulator + cfg.RoundModulator
}

func spendLoop(cfg config, privateKey *crypto.SignatureSecrets, publicKey basics.Address) (err error) {
	restClient := client.MakeRestClient(*cfg.ClientURL, cfg.APIToken)
	for {
		waitForRound(restClient, cfg, true)
		queueFull := generateTransactions(restClient, cfg, privateKey, publicKey)
		if queueFull {
			waitForRound(restClient, cfg, false)
			if !cfg.Repeat {
				fmt.Fprintf(os.Stdout, "Repeat configuration flag set to false, terminating.\n")
				break
			}
		}
	}
	return nil
}

func waitForRound(restClient client.RestClient, cfg config, spendingRound bool) {
	var nodeStatus generatedV2.NodeStatusResponse
	var err error
	for {
		nodeStatus, err = restClient.Status()
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to check status : %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		if isSpendRound(cfg, nodeStatus.LastRound) == spendingRound {
			// time to send transactions.
			return
		}
		if spendingRound {
			fmt.Printf("Current round %d, waiting for spending round %d\n", nodeStatus.LastRound, nextSpendRound(cfg, nodeStatus.LastRound))
		}
		for {
			// wait for the next round.
			nodeStatus, err = restClient.WaitForBlock(basics.Round(nodeStatus.LastRound))
			if err != nil {
				fmt.Fprintf(os.Stderr, "unable to wait for next round node status : %v", err)
				time.Sleep(1 * time.Second)
				break
			}
			if isSpendRound(cfg, nodeStatus.LastRound) == spendingRound {
				// time to send transactions.
				return
			}
		}
	}
}

func generateTransactions(restClient client.RestClient, cfg config, privateKey *crypto.SignatureSecrets, publicKey basics.Address) (queueFull bool) {
	var nodeStatus generatedV2.NodeStatusResponse
	var err error
	nodeStatus, err = restClient.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to check status : %v", err)
		return false
	}
	var vers common.Version
	vers, err = restClient.Versions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to get versions : %v", err)
		return false
	}
	var genesisHash crypto.Digest
	copy(genesisHash[:], vers.GenesisHash)
	// create transactionBlockSize transaction to send.
	txns := make([]transactions.SignedTxn, transactionBlockSize, transactionBlockSize)
	for i := range txns {
		tx := transactions.Transaction{
			Header: transactions.Header{
				Sender:      publicKey,
				Fee:         basics.MicroAlgos{Raw: cfg.Fee},
				FirstValid:  basics.Round(nodeStatus.LastRound),
				LastValid:   basics.Round(nodeStatus.LastRound + 2),
				Note:        make([]byte, 4),
				GenesisID:   vers.GenesisID,
				GenesisHash: genesisHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: publicKey,
				Amount:   basics.MicroAlgos{Raw: 0},
			},
			Type: protocol.PaymentTx,
		}
		crypto.RandBytes(tx.Note[:])
		txns[i] = tx.Sign(privateKey)
	}

	// create multiple go-routines to send all these requests.
	var sendWaitGroup sync.WaitGroup
	sendWaitGroup.Add(nroutines)
	sent := make([]int, nroutines, nroutines)
	for i := 0; i < nroutines; i++ {
		go func(base int) {
			defer sendWaitGroup.Done()
			for x := base; x < transactionBlockSize; x += nroutines {
				_, err2 := restClient.SendRawTransaction(txns[x])
				if err2 != nil {
					if strings.Contains(err2.Error(), "txn dead") || strings.Contains(err2.Error(), "below threshold") {
						break
					}
					fmt.Fprintf(os.Stderr, "unable to send transaction : %v\n", err2)
				} else {
					sent[base]++
				}
			}
		}(i)
	}
	sendWaitGroup.Wait()
	totalSent := 0
	for i := 0; i < nroutines; i++ {
		totalSent += sent[i]
	}
	return totalSent != transactionBlockSize
}
