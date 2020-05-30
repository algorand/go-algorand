// Copyright (C) 2019-2020 Algorand, Inc.
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

package pingpong

import (
	"fmt"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"math"
	"os"
	"sort"
	"time"
)

func ensureAccounts(ac libgoal.Client, initCfg PpConfig) (accounts map[string]uint64, cfg PpConfig, err error) {
	accounts = make(map[string]uint64)
	cfg = initCfg

	wallet, err := ac.GetUnencryptedWalletHandle()

	var srcAcctPresent bool
	var richestAccount string
	var richestBalance uint64

	addresses, err := ac.ListAddresses(wallet)

	if err != nil {
		return nil, PpConfig{}, err
	}

	// find either srcAccount or the richest account
	for _, addr := range addresses {
		if addr == cfg.SrcAccount {
			srcAcctPresent = true
		}

		amount, err := ac.GetBalance(addr)
		if err != nil {
			return nil, PpConfig{}, err
		}

		amt := amount
		if !srcAcctPresent && amt > richestBalance {
			richestAccount = addr
			richestBalance = amt
		}
		accounts[addr] = amt
		if !initCfg.Quiet {
			fmt.Printf("Found local account: %s -> %v\n", addr, amt)
		}
	}

	if !srcAcctPresent {
		if cfg.SrcAccount != "" {
			err = fmt.Errorf("specified Source Account '%s' not found", cfg.SrcAccount)
			return
		}

		if richestBalance >= cfg.MinAccountFunds {
			srcAcctPresent = true
			cfg.SrcAccount = richestAccount

			fmt.Printf("Identified richest account to use for Source Account: %s -> %v\n", richestAccount, richestBalance)
		} else {
			err = fmt.Errorf("no accounts found with sufficient stake (> %d)", cfg.MinAccountFunds)
			return
		}
	} else {
		fmt.Printf("Located Source Account: %s -> %v\n", cfg.SrcAccount, accounts[cfg.SrcAccount])
	}

	// If we have more accounts than requested, pick the top N (not including src)
	if len(accounts) > int(cfg.NumPartAccounts+1) {
		fmt.Printf("Finding the richest %d accounts to use for transacting\n", cfg.NumPartAccounts)
		accounts = takeTopAccounts(accounts, cfg.NumPartAccounts, cfg.SrcAccount)
	} else {
		// Not enough accounts yet (or just enough).  Create more if needed
		if len(accounts) != int(cfg.NumPartAccounts+1) {
			fmt.Printf("Not enough accounts - creating %d more\n", int(cfg.NumPartAccounts+1)-len(accounts))
		}
		accounts, err = generateAccounts(ac, accounts, cfg.NumPartAccounts, wallet)
		if err != nil {
			return
		}
	}

	return
}

func throttleTransactionRate(startTime time.Time, cfg PpConfig, totalSent uint64) {
	localTimeDelta := time.Now().Sub(startTime)
	currentTps := float64(totalSent) / localTimeDelta.Seconds()
	if currentTps > float64(cfg.TxnPerSec) {
		sleepSec := float64(totalSent)/float64(cfg.TxnPerSec) - localTimeDelta.Seconds()
		sleepTime := time.Duration(int64(math.Round(sleepSec*1000))) * time.Millisecond
		time.Sleep(sleepTime)
	}
}

func prepareAssets(accounts map[string]uint64, client libgoal.Client, cfg PpConfig) (assetParams map[uint64]v1.AssetParams, err error) {

	var startTime = time.Now()
	var totalSent uint64 = 0

	if err != nil {
		return
	}

	for addr := range accounts {
		fmt.Printf("**** participant account %v\n", addr)
	}

	for addr := range accounts {
		addrAccount, addrErr := client.AccountInformation(addr)
		if addrErr != nil {
			fmt.Printf("Cannot lookup source account %v\n", addr)
			err = addrErr
			return
		}

		toCreate := int(cfg.NumAsset) - len(addrAccount.AssetParams)

		fmt.Printf("Creating %v create asset transaction for account %v \n", toCreate, addr)
		fmt.Printf("cfg.NumAsset %v, addrAccount.AssetParams %v\n", cfg.NumAsset, addrAccount.AssetParams)

		signedTxns := make([]*transactions.SignedTxn, toCreate)

		// create assets in srcAccount
		for i := 0; i < toCreate; i++ {
			var metaLen = 32
			meta := make([]byte, metaLen, metaLen)
			crypto.RandBytes(meta[:])
			totalSupply := cfg.MinAccountAsset * uint64(cfg.NumPartAccounts) * 9

			if totalSupply < cfg.MinAccountAsset { //overflow
				fmt.Printf("Too many NumPartAccounts\n")
				return
			}
			assetName := fmt.Sprintf("pong%d", i)
			fmt.Printf("Creating asset %s\n", assetName)
			tx, createErr := client.MakeUnsignedAssetCreateTx(totalSupply, false, addr, addr, addr, addr, "ping", assetName, "", meta, 0)
			if createErr != nil {
				fmt.Printf("Cannot make asset create txn with meta %v\n", meta)
				err = createErr
				return
			}
			tx, err = client.FillUnsignedTxTemplate(addr, 0, 0, cfg.MaxFee, tx)
			if err != nil {
				fmt.Printf("Cannot fill asset creation txn\n")
				return
			}

			var hWallet []byte
			hWallet, err = client.GetUnencryptedWalletHandle()
			if err != nil {
				fmt.Printf("Failed to get wallet handle\n")
				return
			}
			signedTxn, signErr := client.SignTransactionWithWallet(hWallet, nil, tx)
			if signErr != nil {
				fmt.Printf("Cannot sign asset creation txn\n")
				err = signErr
				return
			}

			signedTxns[i] = &signedTxn

			if !cfg.Quiet {
				fmt.Printf("Create a new asset: supply=%d \n", totalSupply)
			}
			accounts[addr] -= tx.Fee.Raw

			fmt.Printf("Broadcasting create asset transactions for account %v\n", addr)

			txid, broadcastErr := client.BroadcastTransaction(*signedTxns[i])
			if broadcastErr != nil {
				fmt.Printf("Cannot broadcast asset creation txn error: %v", broadcastErr)
			} else if !cfg.Quiet {
				fmt.Printf("Broadcast asset creation:  txid=%s\n", txid)
			}

			totalSent++
			throttleTransactionRate(startTime, cfg, totalSent)

		}

		account, accountErr := client.AccountInformation(addr)
		if accountErr != nil {
			fmt.Printf("Cannot lookup source account %v\n", addr)
			err = accountErr
			return
		}

		assetParams = account.AssetParams
		fmt.Printf("Configured  %d assets %+v\n", len(assetParams), assetParams)

	}

	for addr := range accounts {
		fmt.Printf("**** participant account %v\n", addr)
	}
	time.Sleep(time.Second * 10)
	err = fundAccounts(accounts, client, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
		return
	}

	for addr := range accounts {
		fmt.Printf("Opting in assets from account %v\n", addr)
		addrAccount, addrErr := client.AccountInformation(addr)
		if addrErr != nil {
			fmt.Printf("Cannot lookup source account\n")
			err = addrErr
			return
		}

		assetParams = addrAccount.AssetParams
		fmt.Printf("Optining in %d assets %+v\n", len(assetParams), assetParams)

		// Opt-in Accounts for each asset
		for k := range assetParams {
			fmt.Printf("optin asset %+v\n", k)

			for addr2 := range accounts {
				fmt.Printf("Opting in assets to account %v \n", addr2)
				addrAccount2, addrErr2 := client.AccountInformation(addr2)
				if addrErr2 != nil {
					fmt.Printf("Cannot lookup source account\n")
					err = addrErr2
					return
				}
				// if addr already opened this asset, skip
				if _, ok := addrAccount2.Assets[k]; !ok {
					// init asset k in addr
					tx, sendErr := client.MakeUnsignedAssetSendTx(k, 0, addr2, "", "")
					if sendErr != nil {
						fmt.Printf("Cannot initiate asset optin %v in account %v\n", k, addr2)
						err = sendErr
						return
					}

					tx, err = client.FillUnsignedTxTemplate(addr2, 0, 0, cfg.MaxFee, tx)
					if err != nil {
						fmt.Printf("Cannot fill asset optin %v init txn in account %v\n", k, addr2)
						return
					}

					var hWallet []byte
					hWallet, err = client.GetUnencryptedWalletHandle()
					if err != nil {
						fmt.Printf("Failed to get wallet handle\n")
						return
					}
					signedTxn, signErr := client.SignTransactionWithWallet(hWallet, nil, tx)
					if signErr != nil {
						fmt.Printf("Cannot sign asset optin %v init txn in account %v\n", k, addr2)
						err = signErr
						return
					}

					_, broadcastErr := client.BroadcastTransaction(signedTxn)
					if broadcastErr != nil {
						fmt.Printf("Cannot broadcast asset optin %v in account %v\n", k, addr2)
						fmt.Printf("error %v \n", broadcastErr)
						err = broadcastErr
						return
					} else {
						if !cfg.Quiet {
							fmt.Printf("Init asset %v in account %v\n", k, addr2)
						}
						accounts[addr2] -= tx.Fee.Raw
					}

					totalSent++
					throttleTransactionRate(startTime, cfg, totalSent)

				}
			}
		}
	}
	time.Sleep(time.Second * 10)

	for addr := range accounts {
		fmt.Printf("**** participant account %v\n", addr)
	}
	time.Sleep(time.Second * 10)
	err = fundAccounts(accounts, client, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
		return
	}

	for addr := range accounts {
		fmt.Printf("Distributing assets from account %v\n", addr)
		addrAccount, addrErr := client.AccountInformation(addr)
		if addrErr != nil {
			fmt.Printf("Cannot lookup source account\n")
			err = addrErr
			return
		}

		assetParams = addrAccount.AssetParams
		fmt.Printf("Distributing assets %+v\n", assetParams)

		// Opt-in Accounts for each asset
		for k := range assetParams {

			fmt.Printf("Distributing %+v assets  \n", k)

			assetAmt := assetParams[k].Total / uint64(len(accounts))
			for addr2 := range accounts {
				if addr != addr2 {

					fmt.Printf("Distributing assets from %v to %v \n", addr, addr2)

					tx, sendErr := constructTxn(addr, addr2, cfg.MaxFee, assetAmt, k, client, cfg)
					if sendErr != nil {
						fmt.Printf("Cannot transfer asset %v from account %v\n", k, addr)
						err = sendErr
						return
					}
					stxn, signErr := signTxn(cfg.SrcAccount, tx, client, cfg)
					if signErr != nil {
						fmt.Printf("Cannot sign asset %v init fund txn in account %v\n", k, addr)
						err = signErr
						return
					}
					_, broadcastErr := client.BroadcastTransaction(stxn)
					if broadcastErr != nil {
						fmt.Printf("Cannot broadcast asset transfer %v from account %v to account %v\n", k, addr, addr2)
						fmt.Printf("error %v \n", broadcastErr)
						err = signErr
						return
					} else {
						if !cfg.Quiet {
							fmt.Printf("Transfer %d asset %d to account %s\n", assetAmt, k, addr)
						}
						accounts[addr] -= tx.Fee.Raw
					}

					totalSent++
					throttleTransactionRate(startTime, cfg, totalSent)
				}
			}

		}

		err = fundAccounts(accounts, client, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
			return
		}

		time.Sleep(time.Second * 10)
	}
	return
}

func takeTopAccounts(allAccounts map[string]uint64, numAccounts uint32, srcAccount string) (accounts map[string]uint64) {
	allAddrs := make([]string, len(allAccounts))
	var i int
	for addr := range allAccounts {
		allAddrs[i] = addr
		i++
	}
	// Sort richest to poorest
	sort.SliceStable(allAddrs, func(i, j int) bool {
		amt1 := allAccounts[allAddrs[i]]
		amt2 := allAccounts[allAddrs[j]]
		return amt1 > amt2
	})

	// Now populate a new map with just the accounts needed
	accountsRequired := int(numAccounts + 1) // Participating and Src
	accounts = make(map[string]uint64)
	accounts[srcAccount] = allAccounts[srcAccount]
	for _, addr := range allAddrs {
		accounts[addr] = allAccounts[addr]
		if len(accounts) == accountsRequired {
			break
		}
	}
	return
}

func generateAccounts(client libgoal.Client, allAccounts map[string]uint64, numAccounts uint32, wallet []byte) (map[string]uint64, error) {
	// Compute the number of accounts to generate
	accountsRequired := int(numAccounts+1) - len(allAccounts)

	for accountsRequired > 0 {
		accountsRequired--
		addr, err := client.GenerateAddress(wallet)
		if err != nil {
			return allAccounts, err
		}

		allAccounts[addr] = 0
	}

	return allAccounts, nil
}
