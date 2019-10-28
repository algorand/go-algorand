// Copyright (C) 2019 Algorand, Inc.
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
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/libgoal"
	"sort"
	"time"
)

func ensureAccounts(ac libgoal.Client, initCfg PpConfig) (accounts map[string]uint64,  cfg PpConfig, err error) {
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

func prepareAssets(accounts map[string]uint64, client libgoal.Client, cfg PpConfig) (assetParams map[uint64]v1.AssetParams, err error) {
	// get existing assets
	account, accountErr := client.AccountInformation(cfg.SrcAccount)
	if accountErr != nil {
		fmt.Printf("Cannot lookup source account")
		err = accountErr
		return
	}

	// Get wallet handle token
	var h []byte
	h, err = client.GetUnencryptedWalletHandle()
	if err != nil {
		return
	}

	toCreate := int(cfg.NumAsset) - len(account.AssetParams)

	// create assets in srcAccount
	for i := 0; i < toCreate; i++ {
		var metaLen = 32
		meta := make([]byte, metaLen, metaLen)
		crypto.RandBytes(meta[:])
		totalSupply := cfg.MinAccountAsset * uint64(cfg.NumPartAccounts) * 9
		if totalSupply < cfg.MinAccountAsset { //overflow
			fmt.Printf("Too many NumPartAccounts")
			return
		}
		tx, createErr := client.MakeUnsignedAssetCreateTx(totalSupply, false, cfg.SrcAccount, cfg.SrcAccount, cfg.SrcAccount, cfg.SrcAccount, "ping", "pong", "", meta)
		if createErr != nil {
			fmt.Printf("Cannot make asset create txn\n")
			err = createErr
			return
		}
		tx, err = client.FillUnsignedTxTemplate(cfg.SrcAccount, 0, 0, cfg.MaxFee, tx)
		if err != nil {
			fmt.Printf("Cannot fill asset creation txn\n")
			return
		}

		signedTxn, signErr := client.SignTransactionWithWallet(h, nil, tx)
		if signErr != nil {
			fmt.Printf("Cannot sign asset creation txn\n")
			err = signErr
			return
		}

		txid, broadcastErr := client.BroadcastTransaction(signedTxn)
		if broadcastErr != nil {
			fmt.Printf("Cannot broadcast asset creation txn\n")
			err = broadcastErr
			return
		}

		if !cfg.Quiet {
			fmt.Printf("Create a new asset: supply=%d, txid=%s\n", totalSupply, txid)
		}
		accounts[cfg.SrcAccount] -= tx.Fee.Raw
	}

	// get these assets
	for {
		account, accountErr = client.AccountInformation(cfg.SrcAccount)
		if accountErr != nil {
			fmt.Printf("Cannot lookup source account")
			err = accountErr
			return
		}
		if len(account.AssetParams) >= int(cfg.NumAsset) {
			break
		}
		time.Sleep(time.Second)
	}

	assetParams = account.AssetParams

	for addr := range accounts {
		addrAccount, addrErr := client.AccountInformation(addr)
		if addrErr != nil {
			fmt.Printf("Cannot lookup source account")
			err = addrErr
			return
		}

		for k := range assetParams {
			// if addr already opened this asset, skip
			if _, ok := addrAccount.Assets[k]; !ok {
				// init asset k in addr
				tx, sendErr := client.MakeUnsignedAssetSendTx(k, 0, addr, "", "")
				if sendErr != nil {
					fmt.Printf("Cannot initiate asset %v in account %v\n", k, addr)
					err = sendErr
					return
				}

				tx, err = client.FillUnsignedTxTemplate(addr, 0, 0, cfg.MaxFee, tx)
				if err != nil {
					fmt.Printf("Cannot fill asset %v init txn in account %v\n", k, addr)
					return
				}

				signedTxn, signErr := client.SignTransactionWithWallet(h, nil, tx)
				if signErr != nil {
					fmt.Printf("Cannot sign asset %v init txn in account %v\n", k, addr)
					err = signErr
					return
				}

				_, broadcastErr := client.BroadcastTransaction(signedTxn)
				if broadcastErr != nil {
					fmt.Printf("Cannot broadcast asset %v init txn in account %v\n", k, addr)
					err = broadcastErr
					return
				}

				if !cfg.Quiet {
					fmt.Printf("Init asset %v in account %v\n", k, addr)
				}
				accounts[addr] -= tx.Fee.Raw
			}

			// fund asset
			var assetAmt uint64
			if asset, ok := addrAccount.Assets[k]; ok {
				if asset.Amount > cfg.MinAccountAsset {
					assetAmt = 0
				} else {
					assetAmt = cfg.MinAccountAsset - asset.Amount
				}
			} else {
				assetAmt = cfg.MinAccountAsset
			}

			if assetAmt == 0 {
				continue
			}

			tx, sendErr := constructTxn(cfg.SrcAccount, addr, cfg.MaxFee, assetAmt, k, client, cfg)
			if sendErr != nil {
				fmt.Printf("Cannot initiate asset %v in account %v\n", k, addr)
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
				fmt.Printf("Cannot broadcast asset %v init fund txn in account %v\n", k, addr)
				err = broadcastErr
				return
			}
			if !cfg.Quiet {
				fmt.Printf("Fund %d asset %d to account %s\n", assetAmt, k, addr)
			}
			accounts[cfg.SrcAccount] -= tx.Fee.Raw
		}

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
