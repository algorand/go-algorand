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

package pingpong

import (
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	algodAcct "github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/db"
)

func (pps *WorkerState) ensureAccounts(ac libgoal.Client, initCfg PpConfig) (accounts map[string]*pingPongAccount, cfg PpConfig, err error) {
	accounts = make(map[string]*pingPongAccount)
	cfg = initCfg

	genID, err2 := ac.GenesisID()
	if err2 != nil {
		err = err2
		return
	}
	genesisDir := filepath.Join(ac.DataDir(), genID)
	files, err2 := ioutil.ReadDir(genesisDir)
	if err2 != nil {
		err = err2
		return
	}

	var srcAcctPresent bool
	var richestAccount string
	var richestBalance uint64

	for _, info := range files {
		var handle db.Accessor

		// If it can't be a participation key database, skip it
		if !config.IsRootKeyFilename(info.Name()) {
			continue
		}

		// Fetch a handle to this database
		handle, err = db.MakeErasableAccessor(filepath.Join(genesisDir, info.Name()))
		if err != nil {
			// Couldn't open it, skip it
			continue
		}

		// Fetch an account.Participation from the database
		root, err := algodAcct.RestoreRoot(handle)
		handle.Close()
		if err != nil {
			// Couldn't read it, skip it
			continue
		}

		publicKey := root.Secrets().SignatureVerifier
		accountAddress := basics.Address(publicKey)

		if accountAddress.String() == cfg.SrcAccount {
			srcAcctPresent = true
		}

		amt, err := ac.GetBalance(accountAddress.String())
		if err != nil {
			return nil, PpConfig{}, err
		}

		if !srcAcctPresent && amt > richestBalance {
			richestAccount = accountAddress.String()
			richestBalance = amt
		}

		if !initCfg.Quiet {
			fmt.Printf("Found local account: %s -> %v\n", accountAddress.String(), amt)
		}

		accounts[accountAddress.String()] = &pingPongAccount{
			balance: amt,
			sk:      root.Secrets(),
			pk:      accountAddress,
		}
	}

	if !srcAcctPresent {
		if cfg.SrcAccount != "" {
			err = fmt.Errorf("specified Source Account '%s' not found", cfg.SrcAccount)
			return
		}

		if richestBalance >= cfg.MinAccountFunds {
			cfg.SrcAccount = richestAccount

			fmt.Printf("Identified richest account to use for Source Account: %s -> %v\n", richestAccount, richestBalance)
		} else {
			err = fmt.Errorf("no accounts found with sufficient stake (> %d)", cfg.MinAccountFunds)
			return
		}
	} else {
		fmt.Printf("Located Source Account: %s -> %v\n", cfg.SrcAccount, accounts[cfg.SrcAccount])
	}

	return
}

// throttle transaction rate
func throttleTransactionRate(startTime time.Time, cfg PpConfig, totalSent uint64) {
	localTimeDelta := time.Since(startTime)
	currentTps := float64(totalSent) / localTimeDelta.Seconds()
	if currentTps > float64(cfg.TxnPerSec) {
		sleepSec := float64(totalSent)/float64(cfg.TxnPerSec) - localTimeDelta.Seconds()
		sleepTime := time.Duration(int64(math.Round(sleepSec*1000))) * time.Millisecond
		util.NanoSleep(sleepTime)
	}
}

// Prepare assets for asset transaction testing
// Step 1) Create X assets for each of the participant accounts
// Step 2) For each participant account, opt-in to assets of all other participant accounts
// Step 3) Evenly distribute the assets across all participant accounts
func (pps *WorkerState) prepareAssets(accounts map[string]*pingPongAccount, client libgoal.Client) (resultAssetMaps map[uint64]v1.AssetParams, optIns map[uint64][]string, err error) {
	proto, err := getProto(client)
	if err != nil {
		return
	}

	var startTime = time.Now()
	var totalSent uint64 = 0
	resultAssetMaps = make(map[uint64]v1.AssetParams)

	// optIns contains own and explicitly opted-in assets
	optIns = make(map[uint64][]string)
	numCreatedAssetsByAddr := make(map[string]int, len(accounts))
	// 1) Create X assets for each of the participant accounts
	for addr := range accounts {
		if addr == pps.cfg.SrcAccount {
			continue
		}
		addrAccount, addrErr := client.AccountInformation(addr)
		if addrErr != nil {
			fmt.Printf("Cannot lookup source account %v\n", addr)
			err = addrErr
			return
		}

		toCreate := int(pps.cfg.NumAsset) - len(addrAccount.AssetParams)
		numCreatedAssetsByAddr[addr] = toCreate

		fmt.Printf("Creating %v create asset transaction for account %v \n", toCreate, addr)
		fmt.Printf("cfg.NumAsset %v, addrAccount.AssetParams %v\n", pps.cfg.NumAsset, addrAccount.AssetParams)

		totalSupply := pps.cfg.MinAccountAsset * uint64(pps.cfg.NumPartAccounts) * 9 * uint64(pps.cfg.GroupSize) * uint64(pps.cfg.RefreshTime.Seconds()) / pps.cfg.TxnPerSec
		// create assets in participant account
		for i := 0; i < toCreate; i++ {
			var metaLen = 32
			meta := make([]byte, metaLen)
			crypto.RandBytes(meta[:])

			if totalSupply < pps.cfg.MinAccountAsset { // overflow
				fmt.Printf("Too many NumPartAccounts\n")
				return
			}
			assetName := fmt.Sprintf("pong%d", i)
			if !pps.cfg.Quiet {
				fmt.Printf("Creating asset %s\n", assetName)
			}
			tx, createErr := client.MakeUnsignedAssetCreateTx(totalSupply, false, addr, addr, addr, addr, "ping", assetName, "", meta, 0)
			if createErr != nil {
				fmt.Printf("Cannot make asset create txn with meta %v\n", meta)
				err = createErr
				return
			}
			tx, err = client.FillUnsignedTxTemplate(addr, 0, 0, pps.cfg.MaxFee, tx)
			if err != nil {
				fmt.Printf("Cannot fill asset creation txn\n")
				return
			}
			tx.Note = pps.makeNextUniqueNoteField()
			_, err = signAndBroadcastTransaction(accounts[addr], tx, client)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "signing and broadcasting asset creation failed with error %v\n", err)
				return
			}

			totalSent++
			throttleTransactionRate(startTime, pps.cfg, totalSent)
		}
	}

	// wait until all the assets created
	allAssets := make(map[uint64]string, int(pps.cfg.NumAsset)*len(accounts))
	for addr := range accounts {
		if addr == pps.cfg.SrcAccount {
			continue
		}
		var account v1.Account
		deadline := time.Now().Add(3 * time.Minute)
		for {
			account, err = client.AccountInformation(addr)
			if err != nil {
				fmt.Printf("Warning: cannot lookup source account after assets creation")
				time.Sleep(1 * time.Second)
				continue
			}
			if len(account.AssetParams) >= numCreatedAssetsByAddr[addr] {
				break
			}
			if time.Now().After(deadline) {
				err = fmt.Errorf("asset creation took too long")
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			waitForNextRoundOrSleep(client, 500*time.Millisecond)
		}
		assetParams := account.AssetParams
		if !pps.cfg.Quiet {
			fmt.Printf("Configured %d assets %+v\n", len(assetParams), assetParams)
		}
		// add own asset to opt-ins since asset creators are auto-opted in
		for k := range account.AssetParams {
			optIns[k] = append(optIns[k], addr)
			allAssets[k] = addr
		}
	}

	// optInsByAddr tracks only explicitly opted-in assetsA
	optInsByAddr := make(map[string]map[uint64]bool)

	// reset rate-control
	startTime = time.Now()
	totalSent = 0

	// 2) For each participant account, opt-in up to proto.MaxAssetsPerAccount assets of all other participant accounts
	for addr := range accounts {
		if addr == pps.cfg.SrcAccount {
			continue
		}
		if !pps.cfg.Quiet {
			fmt.Printf("Opting to account %v\n", addr)
		}

		acct, addrErr := client.AccountInformation(addr)
		if addrErr != nil {
			fmt.Printf("Cannot lookup optin account\n")
			err = addrErr
			return
		}
		maxAssetsPerAccount := proto.MaxAssetsPerAccount
		// TODO : given that we've added unlimited asset support, we should revise this
		// code so that we'll have control on how many asset/account we want to create.
		// for now, I'm going to keep the previous max values until we have refactored this code.
		if maxAssetsPerAccount == 0 {
			maxAssetsPerAccount = config.Consensus[protocol.ConsensusV30].MaxAssetsPerAccount
		}
		numSlots := maxAssetsPerAccount - len(acct.Assets)
		optInsByAddr[addr] = make(map[uint64]bool)
		for k, creator := range allAssets {
			if creator == addr {
				continue
			}
			// do we have any more asset slots for this?
			if numSlots <= 0 {
				break
			}
			numSlots--

			// opt-in asset k for addr
			tx, sendErr := client.MakeUnsignedAssetSendTx(k, 0, addr, "", "")
			if sendErr != nil {
				fmt.Printf("Cannot initiate asset optin %v in account %v\n", k, addr)
				err = sendErr
				return
			}

			tx, err = client.FillUnsignedTxTemplate(addr, 0, 0, pps.cfg.MaxFee, tx)
			if err != nil {
				fmt.Printf("Cannot fill asset optin %v in account %v\n", k, addr)
				return
			}
			tx.Note = pps.makeNextUniqueNoteField()

			_, err = signAndBroadcastTransaction(accounts[addr], tx, client)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "signing and broadcasting asset optin failed with error %v\n", err)
				return
			}
			totalSent++

			optIns[k] = append(optIns[k], addr)
			optInsByAddr[addr][k] = true

			throttleTransactionRate(startTime, pps.cfg, totalSent)
		}
	}

	// wait until all opt-ins completed
	waitForNextRoundOrSleep(client, 500*time.Millisecond)
	for addr := range accounts {
		if addr == pps.cfg.SrcAccount {
			continue
		}
		expectedAssets := numCreatedAssetsByAddr[addr] + len(optInsByAddr[addr])
		var account v1.Account
		deadline := time.Now().Add(3 * time.Minute)
		for {
			account, err = client.AccountInformation(addr)
			if err != nil {
				fmt.Printf("Warning: cannot lookup source account after assets opt in")
				time.Sleep(1 * time.Second)
				continue
			}
			if len(account.Assets) == expectedAssets {
				break
			} else if len(account.Assets) > expectedAssets {
				err = fmt.Errorf("account %v has too many assets %d > %d ", addr, len(account.Assets), expectedAssets)
				return
			}

			if time.Now().After(deadline) {
				err = fmt.Errorf("asset opting in took too long")
				fmt.Printf("Error: %s\n", err.Error())
				return
			}
			waitForNextRoundOrSleep(client, 500*time.Millisecond)
		}
	}

	// reset rate-control
	startTime = time.Now()
	totalSent = 0

	// Step 3) Evenly distribute the assets across all opted-in accounts
	for k, creator := range allAssets {
		if !pps.cfg.Quiet {
			fmt.Printf("Distributing asset %+v from account %v\n", k, creator)
		}
		creatorAccount, creatorErr := client.AccountInformation(creator)
		if creatorErr != nil {
			fmt.Printf("Cannot lookup source account\n")
			err = creatorErr
			return
		}
		assetParams := creatorAccount.AssetParams

		for _, addr := range optIns[k] {
			assetAmt := assetParams[k].Total / uint64(len(optIns[k]))
			if !pps.cfg.Quiet {
				fmt.Printf("Distributing assets from %v to %v \n", creator, addr)
			}

			tx, sendErr := client.MakeUnsignedAssetSendTx(k, assetAmt, addr, "", "")
			if sendErr != nil {
				_, _ = fmt.Fprintf(os.Stdout, "error making unsigned asset send tx %v\n", sendErr)
				err = fmt.Errorf("error making unsigned asset send tx : %w", sendErr)
				return
			}
			tx.Note = pps.makeNextUniqueNoteField()
			tx, sendErr = client.FillUnsignedTxTemplate(creator, 0, 0, pps.cfg.MaxFee, tx)
			if sendErr != nil {
				_, _ = fmt.Fprintf(os.Stdout, "error making unsigned asset send tx %v\n", sendErr)
				err = fmt.Errorf("error making unsigned asset send tx : %w", sendErr)
				return
			}
			tx.LastValid = tx.FirstValid + 5
			if pps.cfg.MaxFee == 0 {
				var suggestedFee uint64
				suggestedFee, err = client.SuggestedFee()
				if err != nil {
					_, _ = fmt.Fprintf(os.Stdout, "error retrieving suggestedFee: %v\n", err)
					return
				}
				if suggestedFee > tx.Fee.Raw {
					tx.Fee.Raw = suggestedFee
				}
			}

			_, err = signAndBroadcastTransaction(accounts[creator], tx, client)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "signing and broadcasting asset distribution failed with error %v\n", err)
				return
			}

			totalSent++
			throttleTransactionRate(startTime, pps.cfg, totalSent)
		}
		// append the asset to the result assets
		resultAssetMaps[k] = assetParams[k]
	}

	// wait for all transfers acceptance
	waitForNextRoundOrSleep(client, 500*time.Millisecond)
	deadline := time.Now().Add(3 * time.Minute)
	var pending v1.PendingTransactions
	for {
		pending, err = client.GetPendingTransactions(100)
		if err != nil {
			fmt.Printf("Warning: cannot get pending txn")
			time.Sleep(1 * time.Second)
			continue
		}
		if pending.TotalTxns == 0 {
			break
		}
		if time.Now().After(deadline) {
			fmt.Printf("Warning: assets distribution took too long")
			break
		}
		waitForNextRoundOrSleep(client, 500*time.Millisecond)
	}
	return
}

func signAndBroadcastTransaction(senderAccount *pingPongAccount, tx transactions.Transaction, client libgoal.Client) (txID string, err error) {
	signedTx := tx.Sign(senderAccount.sk)
	txID, err = client.BroadcastTransaction(signedTx)
	if err != nil {
		fmt.Printf("Cannot broadcast transaction %+v\nerror %v \n", signedTx, err)
		return
	}
	senderAccount.addBalance(-int64(tx.Fee.Raw))
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
	ops, err := logic.AssembleString(progAsm)
	if err != nil {
		panic(err)
	}
	return ops.Program
}

func genAppProgram(numOps uint32, numHashes uint32, hashSize string, numGlobalKeys uint32, numLocalKeys uint32) ([]byte, string) {
	prologueSize := uint32(2 + 3 + 2 + 1 + 1 + 3)
	prologue := `#pragma version 2
		txn ApplicationID
		bz ok
		txn OnCompletion
		int OptIn
		==
		bnz ok
	`

	// goto flip if first key exists
	flipBranchSize := uint32(1 + 1 + 1 + 1 + 3 + 1)
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

	writeLocBlockPrefix := `
		// handle a rare case when there is no opt ins for this app
		// the caller adds opted in accounts to txn.Accounts
		txn NumAccounts // [x, n]
		int 1           // [1, x, n]
		==              // [0/1, n]
		bnz ok          // [n]
	`

	writeLocBlockSize := uint32(15 + 2)
	writeLocBlock := `
		int 1           // [1, n]
		+               // [1+n]
		dup             // [1+n, 1+n]
		dup             // [1+n, 1+n, 1+n]
		store 0         // [1+n, 1+n]
		txn NumAccounts // [N, 1+n, 1+n]
		int 1           // [1, N, 1+n, 1+n]
		-               // [N-1, 1+n, 1+n],  exclude sender
		%               // [A, 1+n], A = 1+n mod N-1
		int 1           // [1, A, 1+n],
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

	epilogue := `
		ok:
		int 1
		return
	`

	// generate assembly
	progParts := append([]string{}, prologue)
	progParts = append(progParts, flipBranch)
	progParts = append(progParts, writePrefix)
	for i := uint32(0); i < numGlobalKeys; i++ {
		progParts = append(progParts, writeBlock)
	}
	progParts = append(progParts, writeLocBlockPrefix)
	for i := uint32(0); i < numLocalKeys; i++ {
		progParts = append(progParts, writeLocBlock)
	}
	if numHashes > 0 {
		progParts = append(progParts, `byte base64 AA==`)
		for i := uint32(0); i < numHashes; i++ {
			progParts = append(progParts, hashSize)
		}
	}
	written := prologueSize + flipBranchSize + numHashes + numGlobalKeys*writeBlockSize + numLocalKeys*writeLocBlockSize
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
	progParts = append(progParts, epilogue)
	progAsm := strings.Join(progParts, "\n")

	// assemble
	ops, err := logic.AssembleString(progAsm)
	if err != nil {
		panic(err)
	}
	return ops.Program, progAsm
}

func waitForNextRoundOrSleep(client libgoal.Client, waitTime time.Duration) {
	status, err := client.Status()
	if err == nil {
		status, err = client.WaitForRound(status.LastRound)
		if err == nil {
			return
		}
	}
	time.Sleep(waitTime)
}

func (pps *WorkerState) sendAsGroup(txgroup []transactions.Transaction, client libgoal.Client, senders []string) (err error) {
	if len(txgroup) == 0 {
		err = fmt.Errorf("sendAsGroup: empty group")
		return
	}
	gid, gidErr := client.GroupID(txgroup)
	if gidErr != nil {
		err = gidErr
		return
	}
	stxgroup := make([]transactions.SignedTxn, len(txgroup))
	for i, txn := range txgroup {
		txn.Group = gid
		stxgroup[i] = txn.Sign(pps.accounts[senders[i]].sk)
	}
repeat:
	broadcastErr := client.BroadcastTransactionGroup(stxgroup)
	if broadcastErr != nil {
		if strings.Contains(broadcastErr.Error(), "broadcast queue full") {
			fmt.Printf("failed to send broadcast app creation txn group, broadcast queue full. sleeping & retrying.\n")
			waitForNextRoundOrSleep(client, 500*time.Millisecond)
			goto repeat
		}
		fmt.Printf("Cannot broadcast app creation txn group - %#v\n", stxgroup)
		err = broadcastErr
		return
	}
	return
}

var proto *config.ConsensusParams

func getProto(client libgoal.Client) (config.ConsensusParams, error) {
	if proto == nil {
		var err error
		status, err := client.Status()
		if err != nil {
			return config.ConsensusParams{}, err
		}
		currentProto, err := client.ConsensusParams(status.LastRound)
		if err != nil {
			return config.ConsensusParams{}, err
		}
		proto = &currentProto
	}

	return *proto, nil
}

func (pps *WorkerState) prepareApps(accounts map[string]*pingPongAccount, client libgoal.Client, cfg PpConfig) (appParams map[uint64]v1.AppParams, optIns map[uint64][]string, err error) {
	proto, err := getProto(client)
	if err != nil {
		return
	}

	toCreate := int(cfg.NumApp)
	appsPerAcct := proto.MaxAppsCreated
	// TODO : given that we've added unlimited app support, we should revise this
	// code so that we'll have control on how many app/account we want to create.
	// for now, I'm going to keep the previous max values until we have refactored this code.
	if appsPerAcct == 0 {
		appsPerAcct = config.Consensus[protocol.ConsensusV30].MaxAppsCreated
	}

	// create min(groupSize, maxAppsPerAcct) per account to optimize sending in batches
	groupSize := proto.MaxTxGroupSize
	if appsPerAcct > groupSize {
		appsPerAcct = groupSize
	}

	acctNeeded := toCreate / appsPerAcct
	if toCreate%appsPerAcct != 0 {
		acctNeeded++
	}
	if acctNeeded >= len(accounts) { // >= because cfg.SrcAccount is skipped
		err = fmt.Errorf("need %d accts to create %d apps but got only %d accts", acctNeeded, toCreate, len(accounts))
		return
	}
	maxOptIn := uint32(config.Consensus[protocol.ConsensusCurrentVersion].MaxAppsOptedIn)
	if maxOptIn > 0 && cfg.NumAppOptIn > maxOptIn {
		err = fmt.Errorf("each acct can only opt in to %d but %d requested", maxOptIn, cfg.NumAppOptIn)
		return
	}

	appAccounts := make([]v1.Account, len(accounts))
	accountsCount := 0
	for acctAddr := range accounts {
		if acctAddr == cfg.SrcAccount {
			continue
		}
		appAccounts[accountsCount], err = client.AccountInformation(acctAddr)
		if err != nil {
			fmt.Printf("Warning, cannot lookup acctAddr account %s", acctAddr)
			return
		}
		accountsCount++
		if accountsCount == acctNeeded {
			break
		}
	}
	appAccounts = appAccounts[:accountsCount]

	if !cfg.Quiet {
		fmt.Printf("Selected temp account:\n")
		for _, acct := range appAccounts {
			fmt.Printf("%s\n", acct.Address)
		}
	}

	// generate app program with roughly some number of operations
	prog, asm := genAppProgram(cfg.AppProgOps, cfg.AppProgHashes, cfg.AppProgHashSize, cfg.AppGlobKeys, cfg.AppLocalKeys)
	if !cfg.Quiet {
		fmt.Printf("generated program: \n%s\n", asm)
	}
	globSchema := basics.StateSchema{NumByteSlice: proto.MaxGlobalSchemaEntries}
	locSchema := basics.StateSchema{NumByteSlice: proto.MaxLocalSchemaEntries}

	// for each account, store the number of expected applications.
	accountsApplicationCount := make(map[string]int)

	// create apps
	for idx, appAccount := range appAccounts {
		begin := idx * appsPerAcct
		end := (idx + 1) * appsPerAcct
		if end > toCreate {
			end = toCreate
		}

		var txgroup []transactions.Transaction
		var senders []string
		for i := begin; i < end; i++ {
			var tx transactions.Transaction

			tx, err = client.MakeUnsignedAppCreateTx(transactions.NoOpOC, prog, prog, globSchema, locSchema, nil, nil, nil, nil, nil, 0)
			if err != nil {
				fmt.Printf("Cannot create app txn\n")
				panic(err)
				// TODO : if we fail here for too long, we should re-create new accounts, etc.
			}

			tx, err = client.FillUnsignedTxTemplate(appAccount.Address, 0, 0, cfg.MaxFee, tx)
			if err != nil {
				fmt.Printf("Cannot fill app creation txn\n")
				panic(err)
				// TODO : if we fail here for too long, we should re-create new accounts, etc.
			}

			// Ensure different txids
			tx.Note = pps.makeNextUniqueNoteField()

			txgroup = append(txgroup, tx)
			accounts[appAccount.Address].addBalance(-int64(tx.Fee.Raw))
			senders = append(senders, appAccount.Address)
			accountsApplicationCount[appAccount.Address]++
		}

		err = pps.sendAsGroup(txgroup, client, senders)
		if err != nil {
			balance, err2 := client.GetBalance(appAccount.Address)
			if err2 == nil {
				fmt.Printf("account %v balance is %d, logged balance is %d\n", appAccount.Address, balance, accounts[appAccount.Address].getBalance())
			} else {
				fmt.Printf("account %v balance cannot be determined : %v\n", appAccount.Address, err2)
			}
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
			if len(account.AppParams) >= accountsApplicationCount[appAccount.Address] {
				break
			}
			waitForNextRoundOrSleep(client, 500*time.Millisecond)
			// TODO : if we fail here for too long, we should re-create new accounts, etc.
		}
		for idx, v := range account.AppParams {
			appParams[idx] = v
			aidxs = append(aidxs, idx)
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
			if addr == cfg.SrcAccount {
				continue
			}
			var txgroup []transactions.Transaction
			var senders []string
			permAppIndices := rand.Perm(len(aidxs))
			for i := uint32(0); i < cfg.NumAppOptIn; i++ {
				j := permAppIndices[i]
				aidx := aidxs[j]
				var tx transactions.Transaction
				tx, err = client.MakeUnsignedAppOptInTx(aidx, nil, nil, nil, nil, nil)
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
				tx.Note = pps.makeNextUniqueNoteField()

				optIns[aidx] = append(optIns[aidx], addr)

				txgroup = append(txgroup, tx)
				senders = append(senders, addr)
				if len(txgroup) == groupSize {
					err = pps.sendAsGroup(txgroup, client, senders)
					if err != nil {
						return
					}
					txgroup = txgroup[:0]
					senders = senders[:0]
				}
			}
			// broadcast leftovers
			if len(txgroup) > 0 {
				err = pps.sendAsGroup(txgroup, client, senders)
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func takeTopAccounts(allAccounts map[string]*pingPongAccount, numAccounts uint32, srcAccount string) (accounts map[string]*pingPongAccount) {
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
		return amt1.getBalance() > amt2.getBalance()
	})

	// Now populate a new map with just the accounts needed
	accountsRequired := int(numAccounts + 1) // Participating and Src
	accounts = make(map[string]*pingPongAccount)
	accounts[srcAccount] = allAccounts[srcAccount]
	for _, addr := range allAddrs {
		accounts[addr] = allAccounts[addr]
		if len(accounts) == accountsRequired {
			break
		}
	}
	return
}

func generateAccounts(allAccounts map[string]*pingPongAccount, numAccounts uint32) {
	var seed crypto.Seed

	for accountsRequired := int(numAccounts+1) - len(allAccounts); accountsRequired > 0; accountsRequired-- {
		crypto.RandBytes(seed[:])
		privateKey := crypto.GenerateSignatureSecrets(seed)
		publicKey := basics.Address(privateKey.SignatureVerifier)

		allAccounts[publicKey.String()] = &pingPongAccount{
			sk: privateKey,
			pk: publicKey,
		}
	}
}
