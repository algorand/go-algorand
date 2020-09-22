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
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/algorand/go-algorand/crypto"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
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

	// Only reuse existing accounts for non asset testing and non app testing.
	// For asset testing, new participant accounts will be created since accounts are limited to 1000 assets.
	// For app testing, new participant accounts will be created since accounts are limited to 10 aps.
	if cfg.NumAsset == 0 && cfg.NumApp == 0 {
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
	}

	return
}

// throttle transaction rate
func throttleTransactionRate(startTime time.Time, cfg PpConfig, totalSent uint64) {
	localTimeDelta := time.Now().Sub(startTime)
	currentTps := float64(totalSent) / localTimeDelta.Seconds()
	if currentTps > float64(cfg.TxnPerSec) {
		sleepSec := float64(totalSent)/float64(cfg.TxnPerSec) - localTimeDelta.Seconds()
		sleepTime := time.Duration(int64(math.Round(sleepSec*1000))) * time.Millisecond
		time.Sleep(sleepTime)
	}
}

// Prepare assets for asset transaction testing
// Step 1) Create X assets for each of the participant accounts
// Step 2) For each participant account, opt-in to assets of all other participant accounts
// Step 3) Evenly distribute the assets across all participant accounts
func prepareAssets(accounts map[string]uint64, client libgoal.Client, cfg PpConfig) (resultAssetMaps map[uint64]v1.AssetParams, err error) {

	var startTime = time.Now()
	var totalSent uint64 = 0
	resultAssetMaps = make(map[uint64]v1.AssetParams)

	// 1) Create X assets for each of the participant accounts
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

		// create assets in participant account
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
			if !cfg.Quiet {
				fmt.Printf("Creating asset %s\n", assetName)
			}
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

			_, err = signAndBroadcastTransaction(accounts, addr, tx, client, cfg)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "signing and broadcasting asset creation failed with error %v\n", err)
				return
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

		assetParams := account.AssetParams
		fmt.Printf("Configured  %d assets %+v\n", len(assetParams), assetParams)

	}

	time.Sleep(time.Second * 15)

	// 2) For each participant account, opt-in to assets of all other participant accounts
	for addr := range accounts {
		if !cfg.Quiet {
			fmt.Printf("Opting in assets from account %v\n", addr)
		}
		addrAccount, addrErr := client.AccountInformation(addr)
		if addrErr != nil {
			fmt.Printf("Cannot lookup source account\n")
			err = addrErr
			return
		}

		assetParams := addrAccount.AssetParams
		if !cfg.Quiet {
			fmt.Printf("Optining in %d assets %+v\n", len(assetParams), assetParams)
		}

		// Opt-in Accounts for each asset
		for k := range assetParams {
			if !cfg.Quiet {
				fmt.Printf("optin asset %+v\n", k)
			}

			for addr2 := range accounts {
				if addr != addr2 {
					if !cfg.Quiet {
						fmt.Printf("Opting in assets to account %v \n", addr2)
					}
					_, addrErr2 := client.AccountInformation(addr2)
					if addrErr2 != nil {
						fmt.Printf("Cannot lookup optin account\n")
						err = addrErr2
						return
					}

					// opt-in asset k for addr
					tx, sendErr := client.MakeUnsignedAssetSendTx(k, 0, addr2, "", "")
					if sendErr != nil {
						fmt.Printf("Cannot initiate asset optin %v in account %v\n", k, addr2)
						err = sendErr
						return
					}

					tx, err = client.FillUnsignedTxTemplate(addr2, 0, 0, cfg.MaxFee, tx)
					if err != nil {
						fmt.Printf("Cannot fill asset optin %v in account %v\n", k, addr2)
						return
					}

					_, err = signAndBroadcastTransaction(accounts, addr2, tx, client, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "signing and broadcasting asset optin failed with error %v\n", err)
						return
					}

					totalSent++
					throttleTransactionRate(startTime, cfg, totalSent)
				}
			}
		}
	}
	time.Sleep(time.Second * 15)

	// Step 3) Evenly distribute the assets across all participant accounts
	for addr := range accounts {
		if !cfg.Quiet {
			fmt.Printf("Distributing assets from account %v\n", addr)
		}
		addrAccount, addrErr := client.AccountInformation(addr)
		if addrErr != nil {
			fmt.Printf("Cannot lookup source account\n")
			err = addrErr
			return
		}

		assetParams := addrAccount.AssetParams
		if !cfg.Quiet {
			fmt.Printf("Distributing  %d assets\n", len(assetParams))
		}

		// Distribute assets to each account
		for k := range assetParams {
			if !cfg.Quiet {
				fmt.Printf("Distributing asset %v \n", k)
			}

			assetAmt := assetParams[k].Total / uint64(len(accounts))
			for addr2 := range accounts {
				if addr != addr2 {
					if !cfg.Quiet {
						fmt.Printf("Distributing assets from %v to %v \n", addr, addr2)
					}

					tx, sendErr := constructTxn(addr, addr2, cfg.MaxFee, assetAmt, k, client, cfg)
					if sendErr != nil {
						fmt.Printf("Cannot transfer asset %v from account %v\n", k, addr)
						err = sendErr
						return
					}

					_, err = signAndBroadcastTransaction(accounts, addr, tx, client, cfg)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "signing and broadcasting asset distribution failed with error %v\n", err)
						return
					}

					totalSent++
					throttleTransactionRate(startTime, cfg, totalSent)
				}
			}
			// append the asset to the result assets
			resultAssetMaps[k] = assetParams[k]
		}
	}
	time.Sleep(time.Second * 10)
	return
}

func signAndBroadcastTransaction(accounts map[string]uint64, sender string, tx transactions.Transaction, client libgoal.Client, cfg PpConfig) (txID string, err error) {
	var signedTx transactions.SignedTxn
	signedTx, err = signTxn(sender, tx, client, cfg)
	if err != nil {
		fmt.Printf("Cannot sign trx %+v with account %v\nerror %v\n", tx, sender, err)
		return
	}
	txID, err = client.BroadcastTransaction(signedTx)
	if err != nil {
		fmt.Printf("Cannot broadcast transaction %+v\nerror %v \n", signedTx, err)
		return
	}
	if !cfg.Quiet {
		fmt.Printf("Broadcast transaction %v\n", txID)
	}
	accounts[sender] -= tx.Fee.Raw

	return
}

func genBigNoOpAndBigHashes(numOps uint32, numHashes uint32, hashSize string) []byte {
	var progParts []string
	progParts = append(progParts, `#pragma version 2`)
	progParts = append(progParts, `byte base64 AA==`)

	for i := uint32(0); i < numHashes; i++ {
		progParts = append(progParts, hashSize)
	}
	for i := uint32(0); i < numOps/2; i++ {
		progParts = append(progParts, `int 1`)
		progParts = append(progParts, `pop`)
	}
	progParts = append(progParts, `int 1`)
	progParts = append(progParts, `return`)
	progAsm := strings.Join(progParts, "\n")
	progBytes, err := logic.AssembleString(progAsm)
	if err != nil {
		panic(err)
	}
	return progBytes
}

func genMaxClone(numKeys int) []byte {
	// goto flip if first key exists
	flipBranch := `
		int 0  // current app id
		int 1  // key
		itob
		app_global_get_ex
		bnz flip
	`

	writePrefix := `
		write:
		int 0
	`

	writeBlock := `
		int 1
		+
		dup
		itob
		dup
		app_global_put
	`

	writeSuffix := `
		int 1
		return
	`

	// flip stored value's low bit
	flipPrefix := `
		flip:
		btoi
		int 1
		^
		itob
		store 0
		int 1
		itob
		load 0
		app_global_put
	`

	flipSuffix := `
		int 1
		return
	`

	// generate assembly
	progParts := []string{"#pragma version 2"}
	progParts = append(progParts, flipBranch)
	progParts = append(progParts, writePrefix)
	for i := 0; i < numKeys; i++ {
		progParts = append(progParts, writeBlock)
	}
	progParts = append(progParts, writeSuffix)
	progParts = append(progParts, flipPrefix)
	progParts = append(progParts, flipSuffix)
	progAsm := strings.Join(progParts, "\n")

	// assemble
	progBytes, err := logic.AssembleString(progAsm)
	if err != nil {
		panic(err)
	}
	return progBytes
}

func prepareApps(accounts map[string]uint64, client libgoal.Client, cfg PpConfig) (appParams map[uint64]v1.AppParams, err error) {

	var appAccount v1.Account
	for tempAccount := range accounts {
		if tempAccount != cfg.SrcAccount {
			appAccount, err = client.AccountInformation(tempAccount)
			if err != nil {
				fmt.Printf("Warning, cannot lookup tempAccount account %s", tempAccount)
				return
			}
			break
		}
	}

	if !cfg.Quiet {
		fmt.Printf("Selected temp account: %s\n", appAccount.Address)
	}

	// Get wallet handle token
	var h []byte
	h, err = client.GetUnencryptedWalletHandle()
	if err != nil {
		return
	}

	toCreate := int(cfg.NumApp)

	// create apps in srcAccount
	for i := 0; i < toCreate; i++ {
		var tx transactions.Transaction

		// generate app program with roughly some number of operations
		prog := genBigNoOpAndBigHashes(cfg.AppProgOps, cfg.AppProgHashs, cfg.AppProgHashSize)
		if !cfg.Quiet {
			fmt.Printf("generated program: \n%s\n", prog)
		}

		globSchema := basics.StateSchema{NumByteSlice: 64}
		locSchema := basics.StateSchema{}
		tx, err = client.MakeUnsignedAppCreateTx(transactions.NoOpOC, prog, prog, globSchema, locSchema, nil, nil, nil, nil)
		if err != nil {
			fmt.Printf("Cannot create app txn\n")
			panic(err)
		}

		tx, err = client.FillUnsignedTxTemplate(appAccount.Address, 0, 0, cfg.MaxFee, tx)
		if err != nil {
			fmt.Printf("Cannot fill app creation txn\n")
			panic(err)
		}

		// Ensure different txids
		var note [8]byte
		crypto.RandBytes(note[:])
		tx.Note = note[:]

		signedTxn, signErr := client.SignTransactionWithWallet(h, nil, tx)
		if signErr != nil {
			fmt.Printf("Cannot sign app creation txn\n")
			err = signErr
			return
		}

		txid, broadcastErr := client.BroadcastTransaction(signedTxn)
		if broadcastErr != nil {
			fmt.Printf("Cannot broadcast app creation txn\n")
			err = broadcastErr
			return
		}

		if !cfg.Quiet {
			fmt.Printf("Create a new app: txid=%s\n", txid)
		}

		accounts[appAccount.Address] -= tx.Fee.Raw
	}

	var account v1.Account
	// get these apps
	for {
		account, err = client.AccountInformation(appAccount.Address)
		if err != nil {
			fmt.Printf("Warning, cannot lookup source account")
			return
		}
		if len(account.AppParams) >= int(cfg.NumApp) {
			break
		}
		time.Sleep(time.Second)
	}

	appParams = account.AppParams
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
