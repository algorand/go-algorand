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
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
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

					tx, sendErr := constructTxn(addr, addr2, cfg.MaxFee, assetAmt, k, CreatablesInfo{}, client, cfg)
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

func genAppProgram(numOps uint32, numHashes uint32, hashSize string, numGlobalKeys uint32, numLocalKeys uint32) []byte {
	// goto flip if first key exists
	flipBranchSize := uint32(6)
	flipBranch := `
		int 0  // current app id  [0]
		int 1  // key  [1, 0]
		itob   // ["\x01", 0]
		app_global_get_ex // [0|1, x]
		bnz flip  // [x]
		pop    // []
	`

	writePrefix := `
		write:
		int 0  // [0]
	`

	writeBlockSize := uint32(6)
	writeBlock := `
		int 1           // [1, 0]
		+               // [1]
		dup             // [1, 1]
		itob            // ["\x01", 1]
		dup             // ["\x01", "\x01", 1]
		app_global_put  // [1]
	`

	writeSuffix := `
		pop    // []
		int 1  // [1]
		return
	`

	writeLocBlockSize := uint32(16)
	writeLocBlock := `
		// handle a rare case when there is no opt ins for this app
		// the caller adds opted in accounts to txn.Accounts
		txn NumAccounts // [x, 1, n]
		int 1           // [1, x, 1, n]
		==              // [0/1, 1, n]
		bz ok           // [1, n]
		int 1           // [1, n]
		+               // [1+n]
		dup             // [1+n, 1+n]
		dup             // [1+n, 1+n, 1+n]
		store 0         // [1+n, 1+n]
		txn NumAccounts // [N, 1+n, 1+n]
		int 1           // [1, N, 1+n, 1+n]
		-               // [N-1, 1+n, 1+n],  exclude sender
		%               // [A, 1+n], A = 1+n mod N
		int 1           // [1, A, 1+n], A = 1+n mod N
		+               // [A+1, 1+n]
		load 0          // [1+n, A+1, 1+n]
		itob            // ["\x n+1", A+1, 1+n]
		dup             // ["\x n+1", "\x n+1", A, 1+n]
		app_local_put   // [1+n]
	`

	// flip stored value's low bit
	flipPrefix := `
		flip:    // [x]
		btoi     // [n]
		int 1    // [1, n]
		^        // [n^1]
		itob     // ["\x n^1"]
		store 0  // []
		int 1    // [1]
		itob     // ["x01"]
		load 0   // ["\x n^1", "x01"]
		app_global_put  // []
	`

	flipSuffix := `
		int 1
		return
	`

	// generate assembly
	prefixSize := uint32(6)
	progParts := []string{
		// allow fast creation and opt in
		"#pragma version 2",
		"txn ApplicationID",
		"bz ok",
		"txn OnCompletion",
		"int OptIn",
		"==",
		"bnz ok",
	}
	progParts = append(progParts, flipBranch)
	progParts = append(progParts, writePrefix)
	for i := uint32(0); i < numGlobalKeys; i++ {
		progParts = append(progParts, writeBlock)
	}
	for i := uint32(0); i < numLocalKeys; i++ {
		progParts = append(progParts, writeLocBlock)
	}
	if numHashes > 0 {
		progParts = append(progParts, `byte base64 AA==`)
		for i := uint32(0); i < numHashes; i++ {
			progParts = append(progParts, hashSize)
		}
	}
	written := prefixSize + flipBranchSize + numHashes + numGlobalKeys*writeBlockSize + numLocalKeys*writeLocBlockSize
	if written < numOps {
		left := numOps - written - 20 // allow some space
		for i := uint32(0); i < left/2; i++ {
			progParts = append(progParts, `int 1`)
			progParts = append(progParts, `pop`)
		}
	}
	progParts = append(progParts, writeSuffix)
	progParts = append(progParts, flipPrefix)
	progParts = append(progParts, flipSuffix)
	progParts = append(progParts, []string{"ok:", "int 1", "return"}...)
	progAsm := strings.Join(progParts, "\n")

	// assemble
	progBytes, err := logic.AssembleString(progAsm)
	if err != nil {
		panic(err)
	}
	return progBytes
}

func sendAsGroup(txgroup []transactions.Transaction, client libgoal.Client, h []byte) (err error) {
	if len(txgroup) == 0 {
		err = fmt.Errorf("sendAsGroup: empty group")
		return
	}
	gid, gidErr := client.GroupID(txgroup)
	if gidErr != nil {
		err = gidErr
		return
	}
	var stxgroup []transactions.SignedTxn
	for _, txn := range txgroup {
		txn.Group = gid
		signedTxn, signErr := client.SignTransactionWithWallet(h, nil, txn)
		if signErr != nil {
			fmt.Printf("Cannot sign app creation txn\n")
			err = signErr
			return
		}
		stxgroup = append(stxgroup, signedTxn)
	}

	broadcastErr := client.BroadcastTransactionGroup(stxgroup)
	if broadcastErr != nil {
		fmt.Printf("Cannot broadcast app creation txn group\n")
		err = broadcastErr
		return
	}
	return
}

func prepareApps(accounts map[string]uint64, client libgoal.Client, cfg PpConfig) (appParams map[uint64]v1.AppParams, optIns map[uint64][]string, err error) {
	toCreate := int(cfg.NumApp)
	appsPerAcct := config.Consensus[protocol.ConsensusCurrentVersion].MaxAppsCreated
	// create min(groupSize, maxAppsPerAcct) per account to optimize sending in batches
	groupSize := config.Consensus[protocol.ConsensusCurrentVersion].MaxTxGroupSize
	if appsPerAcct > groupSize {
		appsPerAcct = groupSize
	}

	acctNeeded := toCreate / appsPerAcct
	if toCreate%appsPerAcct != 0 {
		acctNeeded++
	}
	if acctNeeded >= len(accounts) { // >= because cfg.SrcAccount is skipped
		err = fmt.Errorf("Need %d accts to create %d apps but got only %d accts", acctNeeded, toCreate, len(accounts))
		return
	}
	maxOptIn := uint32(config.Consensus[protocol.ConsensusCurrentVersion].MaxAppsOptedIn)
	if cfg.NumAppOptIn > maxOptIn {
		err = fmt.Errorf("Each acct can only opt in to %d but %d requested", maxOptIn, cfg.NumAppOptIn)
		return
	}

	var appAccounts []v1.Account
	for tempAccount := range accounts {
		if tempAccount != cfg.SrcAccount {
			var appAccount v1.Account
			appAccount, err = client.AccountInformation(tempAccount)
			if err != nil {
				fmt.Printf("Warning, cannot lookup tempAccount account %s", tempAccount)
				return
			}
			appAccounts = append(appAccounts, appAccount)
			if len(appAccounts) == acctNeeded {
				break
			}
		}
	}

	if !cfg.Quiet {
		fmt.Printf("Selected temp account:\n")
		for _, acct := range appAccounts {
			fmt.Printf("%s\n", acct.Address)
		}
	}

	// Get wallet handle token
	var h []byte
	h, err = client.GetUnencryptedWalletHandle()
	if err != nil {
		return
	}

	// create apps
	for idx, appAccount := range appAccounts {
		begin := idx * appsPerAcct
		end := (idx + 1) * appsPerAcct
		if end > toCreate {
			end = toCreate
		}
		var txgroup []transactions.Transaction
		for i := begin; i < end; i++ {
			var tx transactions.Transaction

			// generate app program with roughly some number of operations
			prog := genAppProgram(cfg.AppProgOps, cfg.AppProgHashes, cfg.AppProgHashSize, cfg.AppGlobKeys, cfg.AppLocalKeys)
			if !cfg.Quiet {
				fmt.Printf("generated program: \n%s\n", prog)
			}

			globSchema := basics.StateSchema{NumByteSlice: 64}
			locSchema := basics.StateSchema{NumByteSlice: 16}
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

			txgroup = append(txgroup, tx)
			accounts[appAccount.Address] -= tx.Fee.Raw
		}

		err = sendAsGroup(txgroup, client, h)
		if err != nil {
			return
		}

		if !cfg.Quiet {
			fmt.Printf("Created new %d apps\n", len(txgroup))
		}
	}

	// get these apps
	var aidxs []uint64
	appParams = make(map[uint64]v1.AppParams)
	for _, appAccount := range appAccounts {
		var account v1.Account
		for {
			account, err = client.AccountInformation(appAccount.Address)
			if err != nil {
				fmt.Printf("Warning, cannot lookup source account")
				return
			}
			if len(account.AppParams) >= appsPerAcct || len(aidxs) >= int(cfg.NumApp) {
				break
			}
			time.Sleep(time.Second)
		}
		for idx := range account.AppParams {
			aidxs = append(aidxs, idx)
		}
		for k, v := range account.AppParams {
			appParams[k] = v
		}
	}
	if len(aidxs) != len(appParams) {
		err = fmt.Errorf("duplicates in aidxs, %d != %d", len(aidxs), len(appParams))
		return
	}

	// time to opt in to these apps
	if cfg.NumAppOptIn > 0 {
		optIns = make(map[uint64][]string)
		for addr := range accounts {
			var txgroup []transactions.Transaction
			permAppIndices := rand.Perm(len(aidxs))
			for i := uint32(0); i < cfg.NumAppOptIn; i++ {
				j := permAppIndices[i]
				aidx := aidxs[j]
				var tx transactions.Transaction
				tx, err = client.MakeUnsignedAppOptInTx(aidx, nil, nil, nil, nil)
				if err != nil {
					fmt.Printf("Cannot create app txn\n")
					panic(err)
				}

				tx, err = client.FillUnsignedTxTemplate(addr, 0, 0, cfg.MaxFee, tx)
				if err != nil {
					fmt.Printf("Cannot fill app creation txn\n")
					panic(err)
				}

				// Ensure different txids
				var note [8]byte
				crypto.RandBytes(note[:])
				tx.Note = note[:]

				optIns[aidx] = append(optIns[aidx], addr)

				txgroup = append(txgroup, tx)
				if len(txgroup) == groupSize {
					err = sendAsGroup(txgroup, client, h)
					if err != nil {
						return
					}
					txgroup = txgroup[:0]
				}
			}
			// broadcast leftovers
			if len(txgroup) > 0 {
				err = sendAsGroup(txgroup, client, h)
				if err != nil {
					return
				}
			}
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
