// Copyright (C) 2019-2025 Algorand, Inc.
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
	"encoding/binary"
	"fmt"
	"log"
	"maps"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/passphrase"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	algodAcct "github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/util/db"
)

func deterministicAccounts(initCfg PpConfig) <-chan *crypto.SignatureSecrets {
	out := make(chan *crypto.SignatureSecrets)
	if initCfg.GeneratedAccountSampleMethod == "" || initCfg.GeneratedAccountSampleMethod == "random" {
		go randomDeterministicAccounts(initCfg, out)
	} else if initCfg.GeneratedAccountSampleMethod == "sequential" {
		go sequentialDeterministicAccounts(initCfg, out)
	} else if initCfg.GeneratedAccountSampleMethod == "mnemonic" {
		go mnemonicDeterministicAccounts(initCfg, out)
	}
	return out
}

func randomDeterministicAccounts(initCfg PpConfig, out chan *crypto.SignatureSecrets) {
	numAccounts := initCfg.NumPartAccounts
	totalAccounts := initCfg.GeneratedAccountsCount
	if totalAccounts < uint64(numAccounts)*4 {
		// simpler rand strategy for smaller totalAccounts
		order := rand.Perm(int(totalAccounts))[:numAccounts]
		for _, acct := range order {
			var seed crypto.Seed
			binary.LittleEndian.PutUint64(seed[:], uint64(acct))
			out <- crypto.GenerateSignatureSecrets(seed)
		}
	} else {
		// randomly select numAccounts from generatedAccountsCount
		// better for generatedAccountsCount much bigger than numAccounts
		selected := make(map[uint32]bool, numAccounts)
		for uint32(len(selected)) < numAccounts {
			acct := uint32(rand.Int31n(int32(totalAccounts)))
			if selected[acct] {
				continue // already picked this account
			}
			// generate deterministic secret key from integer ID
			// same uint64 seed used as netdeploy/remote/deployedNetwork.go
			var seed crypto.Seed
			binary.LittleEndian.PutUint64(seed[:], uint64(acct))
			out <- crypto.GenerateSignatureSecrets(seed)
			selected[acct] = true
		}
	}
	close(out)
}

func sequentialDeterministicAccounts(initCfg PpConfig, out chan *crypto.SignatureSecrets) {
	for i := uint32(0); i < initCfg.NumPartAccounts; i++ {
		acct := uint64(i) + uint64(initCfg.GeneratedAccountsOffset)
		var seed crypto.Seed
		binary.LittleEndian.PutUint64(seed[:], uint64(acct))
		out <- crypto.GenerateSignatureSecrets(seed)
	}
	close(out)
}

func mnemonicDeterministicAccounts(initCfg PpConfig, out chan *crypto.SignatureSecrets) {
	for _, mnemonic := range initCfg.GeneratedAccountsMnemonics {
		seedbytes, err := passphrase.MnemonicToKey(mnemonic)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot recover key seed from mnemonic: %v\n", err)
			os.Exit(1)
		}
		var seed crypto.Seed
		copy(seed[:], seedbytes)
		out <- crypto.GenerateSignatureSecrets(seed)
	}
	close(out)
}

// load accounts from ${ALGORAND_DATA}/${netname}-${version}/*.rootkey
func fileAccounts(ac *libgoal.Client) (out <-chan *crypto.SignatureSecrets, err error) {
	genID, err2 := ac.GenesisID()
	if err2 != nil {
		err = err2
		return
	}
	genesisDir := filepath.Join(ac.DataDir(), genID)
	files, err2 := os.ReadDir(genesisDir)
	if err2 != nil {
		err = err2
		return
	}

	ch := make(chan *crypto.SignatureSecrets)
	go enumerateFileAccounts(files, genesisDir, ch)
	return ch, nil
}

func enumerateFileAccounts(files []os.DirEntry, genesisDir string, out chan<- *crypto.SignatureSecrets) {
	for _, info := range files {
		var handle db.Accessor

		// If it can't be a participation key database, skip it
		if !config.IsRootKeyFilename(info.Name()) {
			continue
		}

		// Fetch a handle to this database
		handle, err := db.MakeErasableAccessor(filepath.Join(genesisDir, info.Name()))
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

		out <- root.Secrets()
	}
	close(out)
}

func (pps *WorkerState) ensureAccounts(ac *libgoal.Client) (err error) {
	if pps.accounts == nil {
		pps.accounts = make(map[string]*pingPongAccount)
	}

	if pps.cinfo.OptIns == nil {
		pps.cinfo.OptIns = make(map[any][]string, pps.cfg.NumAsset+pps.cfg.NumApp)
	}
	if pps.cinfo.AssetParams == nil {
		pps.cinfo.AssetParams = make(map[basics.AssetIndex]model.AssetParams, pps.cfg.NumAsset)
	}
	if pps.cinfo.AppParams == nil {
		pps.cinfo.AppParams = make(map[basics.AppIndex]model.ApplicationParams, pps.cfg.NumApp)
	}

	sources := make([]<-chan *crypto.SignatureSecrets, 0, 2)
	// read file accounts for local big source money
	var fileSource <-chan *crypto.SignatureSecrets
	fileSource, err = fileAccounts(ac)
	if err != nil {
		return
	}
	sources = append(sources, fileSource)
	if pps.cfg.DeterministicKeys {
		// add deterministic key accounts for re-use across runs
		detSource := deterministicAccounts(pps.cfg)
		sources = append(sources, detSource)
	}

	var srcAcctPresent bool
	var richestAccount string
	var richestBalance uint64

	for _, source := range sources {
		for secret := range source {
			publicKey := secret.SignatureVerifier
			accountAddress := basics.Address(publicKey)
			addr := accountAddress.String()

			if addr == pps.cfg.SrcAccount {
				srcAcctPresent = true
			}

			ai, aiErr := ac.AccountInformation(addr, true)
			if aiErr != nil {
				return aiErr
			}
			amt := ai.Amount

			if !srcAcctPresent && amt > richestBalance {
				richestAccount = addr
				richestBalance = amt
			}

			ppa := &pingPongAccount{
				sk: secret,
				pk: accountAddress,
			}
			ppa.balance.Store(amt)

			pps.integrateAccountInfo(addr, ppa, ai)

			if !pps.cfg.Quiet {
				fmt.Printf("Found local account: %s\n", ppa.String())
			}

			pps.accounts[addr] = ppa
		}
	}

	if !srcAcctPresent {
		if pps.cfg.SrcAccount != "" {
			err = fmt.Errorf("specified Source Account '%s' not found", pps.cfg.SrcAccount)
			return
		}

		if richestBalance >= pps.cfg.MinAccountFunds {
			pps.cfg.SrcAccount = richestAccount

			fmt.Printf("Identified richest account to use for Source Account: %s -> %v\n", richestAccount, richestBalance)
		} else {
			err = fmt.Errorf("no accounts found with sufficient stake (> %d)", pps.cfg.MinAccountFunds)
			return
		}
	} else {
		fmt.Printf("Located Source Account: %s -> %v\n", pps.cfg.SrcAccount, pps.accounts[pps.cfg.SrcAccount])
	}

	return
}

func (pps *WorkerState) integrateAccountInfo(addr string, ppa *pingPongAccount, ai model.Account) {
	ppa.balance.Store(ai.Amount)
	// assets this account has created
	if ai.CreatedAssets != nil {
		for _, ap := range *ai.CreatedAssets {
			assetID := ap.Index
			pps.cinfo.OptIns[assetID] = uniqueAppend(pps.cinfo.OptIns[assetID], addr)
			pps.cinfo.AssetParams[assetID] = ap.Params
		}
	}
	// assets held
	if ai.Assets != nil {
		for _, holding := range *ai.Assets {
			assetID := holding.AssetID
			pps.cinfo.OptIns[assetID] = uniqueAppend(pps.cinfo.OptIns[assetID], addr)
			if ppa.holdings == nil {
				ppa.holdings = make(map[basics.AssetIndex]uint64)
			}
			ppa.holdings[assetID] = holding.Amount
		}
	}
	// apps created by this account
	if ai.CreatedApps != nil {
		for _, ap := range *ai.CreatedApps {
			appID := ap.Id
			pps.cinfo.OptIns[appID] = uniqueAppend(pps.cinfo.OptIns[appID], addr)
			pps.cinfo.AppParams[appID] = ap.Params
		}
	}
	// apps opted into
	if ai.AppsLocalState != nil {
		for _, localState := range *ai.AppsLocalState {
			appID := localState.Id
			pps.cinfo.OptIns[appID] = uniqueAppend(pps.cinfo.OptIns[appID], addr)
		}
	}
}

type assetopti struct {
	assetID basics.AssetIndex
	params  model.AssetParams
	optins  []string // addr strings
}

type assetSet []assetopti

// Len is part of sort.Interface
func (as *assetSet) Len() int {
	return len(*as)
}

// Less is part of sort.Interface
// This is a reversed sort, higher values first
func (as *assetSet) Less(a, b int) bool {
	return len((*as)[a].optins) > len((*as)[b].optins)
}

// Swap is part of sort.Interface
func (as *assetSet) Swap(a, b int) {
	t := (*as)[a]
	(*as)[a] = (*as)[b]
	(*as)[b] = t
}

func (pps *WorkerState) prepareAssets(client *libgoal.Client) (err error) {
	if pps.cinfo.AssetParams == nil {
		pps.cinfo.AssetParams = make(map[basics.AssetIndex]model.AssetParams)
	}
	if pps.cinfo.OptIns == nil {
		pps.cinfo.OptIns = make(map[any][]string)
	}

	// create new assets as needed
	err = pps.makeNewAssets(client)
	if err != nil {
		return
	}

	// find the most-opted-in assets to work with
	assets := make([]assetopti, len(pps.cinfo.AssetParams))
	pos := 0
	for assetID, params := range pps.cinfo.AssetParams {
		assets[pos].assetID = assetID
		assets[pos].params = params
		assets[pos].optins = pps.cinfo.OptIns[assetID]
		pos++
	}
	ta := assetSet(assets)
	sort.Sort(&ta)
	if len(assets) > int(pps.cfg.NumAsset) {
		assets = assets[:pps.cfg.NumAsset]
		nap := make(map[basics.AssetIndex]model.AssetParams, pps.cfg.NumAsset)
		for _, asset := range assets {
			nap[asset.assetID] = asset.params
		}
		pps.cinfo.AssetParams = nap
	}

	// opt-in more accounts as needed
	for assetID := range pps.cinfo.AssetParams {
		for addr, acct := range pps.accounts {
			_, has := acct.holdings[assetID]
			if !has {
				tx, sendErr := client.MakeUnsignedAssetSendTx(assetID, 0, addr, "", "")
				if sendErr != nil {
					fmt.Printf("Cannot initiate asset optin %v in account %v\n", assetID, addr)
					err = sendErr
					continue
				}

				tx, err = client.FillUnsignedTxTemplate(addr, 0, 0, pps.cfg.MaxFee, tx)
				if err != nil {
					fmt.Printf("Cannot fill asset optin %v in account %v\n", assetID, addr)
					continue
				}
				tx.Note = pps.makeNextUniqueNoteField()

				pps.schedule(1)
				_, err = signAndBroadcastTransaction(acct, tx, client)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "signing and broadcasting asset optin failed with error %v\n", err)
					continue
				}
				pps.cinfo.OptIns[assetID] = uniqueAppend(pps.cinfo.OptIns[assetID], addr)
			}
		}
	}

	// Could distribute value here, but just waits till constructAssetTxn()
	return
}

const totalSupply = 10_000_000_000_000_000

func (pps *WorkerState) makeNewAssets(client *libgoal.Client) (err error) {
	if len(pps.cinfo.AssetParams) >= int(pps.cfg.NumAsset) {
		return
	}
	assetsNeeded := int(pps.cfg.NumAsset) - len(pps.cinfo.AssetParams)
	assetsToCreate := assetsNeeded // Save original count for later use
	newAssetAddrs := make(map[string]*pingPongAccount, assetsNeeded)
	for addr, acct := range pps.accounts {
		if assetsNeeded <= 0 {
			break
		}
		assetsNeeded--
		var meta [32]byte
		crypto.RandBytes(meta[:])
		assetName := fmt.Sprintf("pong%d_%d", len(pps.cinfo.AssetParams), rand.Intn(8999)+1000)
		if !pps.cfg.Quiet {
			fmt.Printf("Creating asset %s\n", assetName)
		}
		tx, createErr := client.MakeUnsignedAssetCreateTx(totalSupply, false, addr, addr, addr, addr, "ping", assetName, "", meta[:], 0)
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
		pps.schedule(1)
		_, err = signAndBroadcastTransaction(pps.accounts[addr], tx, client)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "signing and broadcasting asset creation failed with error %v\n", err)
			return
		}
		newAssetAddrs[addr] = acct
	}
	// wait for new assets to be created, fetch account data for them
	newAssets := make(map[basics.AssetIndex]model.AssetParams, assetsToCreate)
	timeout := time.Now().Add(10 * time.Second)
	for len(newAssets) < assetsToCreate {
		for addr, acct := range newAssetAddrs {
			ai, err := client.AccountInformation(addr, true)
			if err != nil {
				fmt.Printf("Warning: cannot lookup source account after assets creation")
				time.Sleep(1 * time.Second)
				continue
			}
			if ai.CreatedAssets != nil {
				for _, ap := range *ai.CreatedAssets {
					assetID := ap.Index
					pps.cinfo.OptIns[assetID] = uniqueAppend(pps.cinfo.OptIns[assetID], addr)
					_, has := pps.cinfo.AssetParams[assetID]
					if !has {
						newAssets[assetID] = ap.Params
					}
				}
			}
			if ai.Assets != nil {
				for _, holding := range *ai.Assets {
					assetID := holding.AssetID
					pps.cinfo.OptIns[assetID] = uniqueAppend(pps.cinfo.OptIns[assetID], addr)
					if acct.holdings == nil {
						acct.holdings = make(map[basics.AssetIndex]uint64)
					}
					acct.holdings[assetID] = holding.Amount
				}
			}
		}
		if time.Now().After(timeout) {
			// complain, but try to keep running on what assets we have
			log.Printf("WARNING took too long to create new assets")
			// TODO: error?
			break
		}
	}
	maps.Copy(pps.cinfo.AssetParams, newAssets)
	return nil
}

func signAndBroadcastTransaction(senderAccount *pingPongAccount, tx transactions.Transaction, client *libgoal.Client) (txID string, err error) {
	signedTx := tx.Sign(senderAccount.sk)
	txID, err = client.BroadcastTransaction(signedTx)
	if err != nil {
		fmt.Printf("Cannot broadcast transaction %+v\nerror %v \n", signedTx, err)
		return
	}
	senderAccount.addBalance(-int64(tx.Fee.Raw))
	return
}

func genAppProgram(numOps uint32, numHashes uint32, hashSize string, numGlobalKeys, numLocalKeys, numBoxUpdate, numBoxRead uint32) ([]byte, string) {
	if numBoxUpdate != 0 || numBoxRead != 0 {
		prologue := `#pragma version 8
			txn ApplicationID
			bz done
		`
		createBoxes := `
			byte "%d"
			int 1024
			box_create
			pop
		`
		updateBoxes := `
			byte "%d"
			int 0
			byte "1"
			box_replace
		`
		getBoxes := `
			byte "%d"
			box_get
			assert
			pop
		`
		done := `
			done:
			int 1
			return
		`

		progParts := []string{prologue}

		// note: only one of numBoxUpdate or numBoxRead should be nonzero
		if numBoxUpdate != 0 {
			for i := uint32(0); i < numBoxUpdate; i++ {
				progParts = append(progParts, fmt.Sprintf(createBoxes, i))
			}

			for i := uint32(0); i < numBoxUpdate; i++ {
				progParts = append(progParts, fmt.Sprintf(updateBoxes, i))
			}
		} else {
			for i := uint32(0); i < numBoxRead; i++ {
				progParts = append(progParts, fmt.Sprintf(createBoxes, i))
			}

			for i := uint32(0); i < numBoxRead; i++ {
				progParts = append(progParts, fmt.Sprintf(getBoxes, i))
			}
		}
		progParts = append(progParts, done)

		// assemble
		progAsm := strings.Join(progParts, "\n")
		ops, err := logic.AssembleString(progAsm)
		if err != nil {
			panic(err)
		}
		return ops.Program, progAsm
	}

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

func waitForNextRoundOrSleep(client *libgoal.Client, waitTime time.Duration) {
	status, err := client.Status()
	if err == nil {
		status, err = client.WaitForRound(status.LastRound)
		if err == nil {
			return
		}
	}
	time.Sleep(waitTime)
}

func (pps *WorkerState) sendAsGroup(txgroup []transactions.Transaction, client *libgoal.Client, senders []string) (err error) {
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

func getProto(client *libgoal.Client) (config.ConsensusParams, error) {
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

// ensure that cfg.NumPartAccounts have cfg.NumAppOptIn opted in selecting from cfg.NumApp
func (pps *WorkerState) prepareApps(client *libgoal.Client) (err error) {
	if pps.cinfo.AppParams == nil {
		pps.cinfo.AppParams = make(map[basics.AppIndex]model.ApplicationParams)
	}

	if pps.cinfo.OptIns == nil {
		pps.cinfo.OptIns = make(map[any][]string, pps.cfg.NumAsset+pps.cfg.NumApp)
	}

	// generate new apps
	// cycle through accts and create apps until the desired quantity is reached
	var txgroup []transactions.Transaction
	var senders []string
	var newAppAddrs []string
	appsPerAddr := make(map[string]int)
	totalAppCnt := len(pps.cinfo.AppParams)
	for totalAppCnt < int(pps.cfg.NumApp) {
		for addr, acct := range pps.accounts {
			if totalAppCnt >= int(pps.cfg.NumApp) {
				break
			}

			var tx transactions.Transaction
			tx, err = pps.newApp(addr, client)
			if err != nil {
				return
			}
			newAppAddrs = append(newAppAddrs, addr)
			acct.addBalance(-int64(pps.cfg.MaxFee))
			txgroup = append(txgroup, tx)
			senders = append(senders, addr)
			if len(txgroup) == int(pps.cfg.GroupSize) {
				pps.schedule(len(txgroup))
				err = pps.sendAsGroup(txgroup, client, senders)
				if err != nil {
					return
				}
				txgroup = txgroup[:0]
				senders = senders[:0]
			}

			appsPerAddr[addr]++
			totalAppCnt++
		}
	}
	if len(txgroup) > 0 {
		pps.schedule(len(txgroup))
		err = pps.sendAsGroup(txgroup, client, senders)
		if err != nil {
			return
		}
		txgroup = txgroup[:0]
		senders = senders[:0]
	}

	// update pps.cinfo.AppParams to ensure newly created apps are present
	for _, addr := range newAppAddrs {
		var ai model.Account
		for {
			ai, err = client.AccountInformation(addr, true)
			if err != nil {
				fmt.Printf("Warning, cannot lookup source account")
				return
			}
			if ai.CreatedApps != nil && len(*ai.CreatedApps) >= appsPerAddr[addr] {
				break
			}
			waitForNextRoundOrSleep(client, 500*time.Millisecond)
			// TODO : if we fail here for too long, we should re-create new accounts, etc.
		}
		ai, err = client.AccountInformation(addr, true)
		if err != nil {
			return
		}

		for _, ap := range *ai.CreatedApps {
			appID := ap.Id
			pps.cinfo.OptIns[appID] = uniqueAppend(pps.cinfo.OptIns[appID], addr)
			pps.cinfo.AppParams[appID] = ap.Params
		}
	}

	// opt-in more accounts to apps
	acctPerApp := (pps.cfg.NumAppOptIn * pps.cfg.NumPartAccounts) / pps.cfg.NumApp
	for appid := range pps.cinfo.AppParams {
		optins := pps.cinfo.OptIns[appid]
		for addr, acct := range pps.accounts {
			if len(optins) >= int(acctPerApp) {
				break
			}
			// opt-in the account to the app
			var tx transactions.Transaction
			tx, err = pps.appOptIn(addr, appid, client)
			if err != nil {
				return
			}
			acct.addBalance(-int64(pps.cfg.MaxFee))
			txgroup = append(txgroup, tx)
			senders = append(senders, addr)
			if len(txgroup) == int(pps.cfg.GroupSize) {
				pps.schedule(len(txgroup))
				err = pps.sendAsGroup(txgroup, client, senders)
				if err != nil {
					return
				}
				txgroup = txgroup[:0]
				senders = senders[:0]
			}

		}
	}
	if len(txgroup) > 0 {
		pps.schedule(len(txgroup))
		err = pps.sendAsGroup(txgroup, client, senders)
		if err != nil {
			return
		}
		//txgroup = txgroup[:0]
		//senders = senders[:0]
	}

	for appid := range pps.cinfo.AppParams {
		// use source account to fund all apps
		err = pps.appFundFromSourceAccount(appid, client)
		if err != nil {
			return
		}
	}

	return
}

func (pps *WorkerState) newApp(addr string, client *libgoal.Client) (tx transactions.Transaction, err error) {
	// generate app program with roughly some number of operations
	prog, asm := genAppProgram(pps.cfg.AppProgOps, pps.cfg.AppProgHashes, pps.cfg.AppProgHashSize, pps.cfg.AppGlobKeys, pps.cfg.AppLocalKeys, pps.cfg.NumBoxUpdate, pps.cfg.NumBoxRead)
	if !pps.cfg.Quiet {
		fmt.Printf("generated program: \n%s\n", asm)
	}
	globSchema := basics.StateSchema{NumByteSlice: proto.MaxGlobalSchemaEntries}
	locSchema := basics.StateSchema{NumByteSlice: proto.MaxLocalSchemaEntries}

	tx, err = client.MakeUnsignedAppCreateTx(transactions.NoOpOC, prog, prog, globSchema, locSchema, nil, libgoal.RefBundle{}, 0)
	if err != nil {
		fmt.Printf("Cannot create app txn\n")
		panic(err)
		// TODO : if we fail here for too long, we should re-create new accounts, etc.
	}

	tx, err = client.FillUnsignedTxTemplate(addr, 0, 0, pps.cfg.MaxFee, tx)
	if err != nil {
		fmt.Printf("Cannot fill app creation txn\n")
		panic(err)
		// TODO : if we fail here for too long, we should re-create new accounts, etc.
	}

	// Ensure different txids
	tx.Note = pps.makeNextUniqueNoteField()

	return tx, err
}

func (pps *WorkerState) appOptIn(addr string, appID basics.AppIndex, client *libgoal.Client) (tx transactions.Transaction, err error) {
	tx, err = client.MakeUnsignedAppOptInTx(appID, nil, libgoal.RefBundle{}, 0)
	if err != nil {
		fmt.Printf("Cannot create app txn\n")
		panic(err)
	}

	tx, err = client.FillUnsignedTxTemplate(addr, 0, 0, pps.cfg.MaxFee, tx)
	if err != nil {
		fmt.Printf("Cannot fill app creation txn\n")
		panic(err)
	}

	// Ensure different txids
	tx.Note = pps.makeNextUniqueNoteField()
	return
}

func (pps *WorkerState) appFundFromSourceAccount(appID basics.AppIndex, client *libgoal.Client) (err error) {
	// currently, apps only need to be funded if boxes are used
	if pps.getNumBoxes() > 0 {
		var srcFunds uint64
		srcFunds, err = client.GetBalance(pps.cfg.SrcAccount)
		if err != nil {
			return err
		}

		appAddr := appID.Address()
		mbr := proto.MinBalance +
			proto.BoxFlatMinBalance*uint64(pps.getNumBoxes()) +
			proto.BoxByteMinBalance*(proto.MaxBoxSize+uint64(proto.MaxAppKeyLen))*uint64(pps.getNumBoxes())

		pps.schedule(1)
		var txn transactions.Transaction
		txn, err = pps.sendPaymentFromSourceAccount(client, appAddr.String(), 0, mbr, pps.accounts[pps.cfg.SrcAccount])
		if err != nil {
			return err
		}

		srcFunds -= mbr
		srcFunds -= txn.Fee.Raw
		pps.accounts[pps.cfg.SrcAccount].setBalance(srcFunds)
	}

	return nil
}

func takeTopAccounts(allAccounts map[string]*pingPongAccount, numAccounts uint32, srcAccount string) (accounts map[string]*pingPongAccount) { //nolint:unused // TODO
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

// generate random ephemeral accounts
// TODO: don't do this and _always_ use the deterministic account mechanism?
func (pps *WorkerState) generateAccounts() {
	var seed crypto.Seed

	for accountsRequired := int(pps.cfg.NumPartAccounts+1) - len(pps.accounts); accountsRequired > 0; accountsRequired-- {
		crypto.RandBytes(seed[:])
		privateKey := crypto.GenerateSignatureSecrets(seed)
		publicKey := basics.Address(privateKey.SignatureVerifier)

		pps.accounts[publicKey.String()] = &pingPongAccount{
			sk: privateKey,
			pk: publicKey,
		}
	}
}

func uniqueAppend(they []string, x string) []string {
	if slices.Contains(they, x) {
		return they
	}
	return append(they, x)
}
