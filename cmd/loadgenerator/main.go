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

package main

import (
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/passphrase"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	generatedV2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/common"
	algodAcct "github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

var nroutines = runtime.NumCPU() * 2

func maybefail(err error, msg string, args ...interface{}) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, msg, args...)
	os.Exit(1)
}

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

// Like shared/pingpong/accounts.go
func findRootKeys(algodDir string) []*crypto.SignatureSecrets {
	keylist := make([]*crypto.SignatureSecrets, 0, 5)
	filepath.Walk(algodDir, func(path string, info fs.FileInfo, err error) error {
		var handle db.Accessor
		handle, err = db.MakeErasableAccessor(path)
		if err != nil {
			return nil // don't care, move on
		}
		defer handle.Close()

		// Fetch an account.Participation from the database
		root, err := algodAcct.RestoreRoot(handle)
		if err != nil {
			return nil // don't care, move on
		}
		keylist = append(keylist, root.Secrets())
		return nil
	})
	return keylist
}

var runOnce = flag.Bool("once", false, "Terminate after first spend loop")

func main() {
	var algodDir string
	flag.StringVar(&algodDir, "d", "", "algorand data dir")
	var configArg string
	flag.StringVar(&configArg, "config", "loadgenerator.config", "path to json or json literal")

	var cfg config
	var err error
	flag.Parse()
	if cfg, err = loadConfig(configArg); err != nil {
		fmt.Fprintf(os.Stderr, "unable to load config : %v\n", err)
		os.Exit(1)
	}

	if (cfg.ClientURL == nil || cfg.ClientURL.String() == "") || cfg.APIToken == "" {
		if algodDir != "" {
			path := filepath.Join(algodDir, "algod.net")
			net, err := ioutil.ReadFile(path)
			maybefail(err, "%s: %v\n", path, err)
			path = filepath.Join(algodDir, "algod.token")
			token, err := ioutil.ReadFile(path)
			maybefail(err, "%s: %v\n", path, err)
			cfg.ClientURL, err = url.Parse(fmt.Sprintf("http://%s", string(strings.TrimSpace(string(net)))))
			maybefail(err, "bad net url %v\n", err)
			cfg.APIToken = string(token)
		} else {
			fmt.Fprintf(os.Stderr, "need (config.ClientURL and config.APIToken) or (-d ALGORAND_DATA)\n")
			os.Exit(1)
		}
	}
	fmt.Printf("Configuration file loaded successfully.\n")

	var privateKey *crypto.SignatureSecrets
	var publicKey basics.Address
	if len(cfg.AccountMnemonic) > 0 {
		seed := loadMnemonic(cfg.AccountMnemonic)
		privateKey = crypto.GenerateSignatureSecrets(seed)
		publicKey = basics.Address(privateKey.SignatureVerifier)
	} else if len(algodDir) > 0 {
		// get test cluster local unlocked wallet
		keys := findRootKeys(algodDir)
		if len(keys) == 0 {
			fmt.Fprintf(os.Stderr, "%s: found no root keys\n", algodDir)
			os.Exit(1)
		}
		privateKey = keys[rand.Intn(len(keys))]
		publicKey = basics.Address(privateKey.SignatureVerifier)
	} else {
		fmt.Fprintf(os.Stderr, "need either config.AccountMnemonic or -d ALGORAND_DATA for spendable account")
		os.Exit(1)
	}

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
			// done for this round, wait for a non-send round
			waitForRound(restClient, cfg, false)
			if *runOnce {
				fmt.Fprintf(os.Stdout, "Once flag set, terminating.\n")
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
			fmt.Printf("Last round %d, waiting for spending round %d\n", nodeStatus.LastRound, nextSpendRound(cfg, nodeStatus.LastRound))
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

const transactionBlockSize = 800

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
	sendSize := cfg.TxnsToSend
	if cfg.TxnsToSend == 0 {
		sendSize = transactionBlockSize
	}
	// create sendSize transaction to send.
	txns := make([]transactions.SignedTxn, sendSize, sendSize)
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
	// each thread makes new HTTP connections per API call
	var sendWaitGroup sync.WaitGroup
	sendWaitGroup.Add(nroutines)
	sent := make([]int, nroutines, nroutines)
	for i := 0; i < nroutines; i++ {
		go func(base int) {
			defer sendWaitGroup.Done()
			for x := base; x < sendSize; x += nroutines {
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
	if cfg.TxnsToSend != 0 {
		// We attempted what we were asked. We're done.
		return true
	}
	return totalSent != sendSize
}
