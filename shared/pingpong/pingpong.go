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

package pingpong

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/algorand/go-algorand/crypto"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
)

// CreatablesInfo has information about created assets, apps and opting in
type CreatablesInfo struct {
	AssetParams map[uint64]v1.AssetParams
	AppParams   map[uint64]v1.AppParams
	OptIns      map[uint64][]string
}

// PrepareAccounts to set up accounts and asset accounts required for Ping Pong run
func PrepareAccounts(ac libgoal.Client, initCfg PpConfig) (accounts map[string]uint64, cinfo CreatablesInfo, cfg PpConfig, err error) {
	cfg = initCfg
	accounts, cfg, err = ensureAccounts(ac, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ensure accounts failed %v\n", err)
		return
	}

	wallet, walletErr := ac.GetUnencryptedWalletHandle()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "unable to access wallet %v\n", walletErr)
		err = walletErr
		return
	}
	if cfg.NumAsset > 0 {
		// zero out max amount for asset transactions
		cfg.MaxAmt = 0

		var assetAccounts map[string]uint64
		assetAccounts, err = prepareNewAccounts(ac, cfg, wallet, accounts)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare new accounts failed: %v\n", err)
			return
		}

		cinfo.AssetParams, cinfo.OptIns, err = prepareAssets(assetAccounts, ac, cfg)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare assets failed %v\n", err)
			return
		}

		if !cfg.Quiet {
			for addr := range accounts {
				fmt.Printf("final prepareAccounts, account addr: %s, balance: %d\n", addr, accounts[addr])
			}
		}
	} else if cfg.NumApp > 0 {

		var appAccounts map[string]uint64
		appAccounts, err = prepareNewAccounts(ac, cfg, wallet, accounts)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare new accounts failed: %v\n", err)
			return
		}
		cinfo.AppParams, cinfo.OptIns, err = prepareApps(appAccounts, ac, cfg)
		if err != nil {
			return
		}
		if !cfg.Quiet {
			for addr := range accounts {
				fmt.Printf("final prepareAccounts, account addr: %s, balance: %d\n", addr, accounts[addr])
			}
		}
	} else {
		err = fundAccounts(accounts, ac, cfg)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
			return
		}
	}

	return
}

func prepareNewAccounts(client libgoal.Client, cfg PpConfig, wallet []byte, accounts map[string]uint64) (newAccounts map[string]uint64, err error) {
	// remove existing accounts except for src account
	for k := range accounts {
		if k != cfg.SrcAccount {
			delete(accounts, k)
		}
	}
	// create new accounts for testing
	newAccounts = make(map[string]uint64)
	newAccounts, err = generateAccounts(client, newAccounts, cfg.NumPartAccounts-1, wallet)

	for k := range newAccounts {
		accounts[k] = newAccounts[k]
	}
	err = fundAccounts(accounts, client, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
		return
	}

	return
}

// determine the min balance per participant account
func computeAccountMinBalance(client libgoal.Client, cfg PpConfig) (requiredBalance uint64, err error) {
	proto, err := getProto(client)
	if err != nil {
		return
	}

	minActiveAccountBalance := proto.MinBalance

	if cfg.NumApp > 0 {
		requiredBalance = (cfg.MinAccountFunds + (cfg.MaxAmt+cfg.MaxFee)*10) * 2
		fmt.Printf("required min balance for app accounts: %d\n", requiredBalance)
		return
	}
	var fee uint64 = 1000
	if cfg.MinFee > fee {
		fee = cfg.MinFee
	}
	if cfg.MaxFee != 0 {
		fee = cfg.MaxFee
	} else {
		// follow the same logic as constructTxn
		fee, err = client.SuggestedFee()
		if err != nil {
			return
		}
	}
	requiredBalance = minActiveAccountBalance

	// add cost of assets
	if cfg.NumAsset > 0 {
		assetCost := minActiveAccountBalance*uint64(cfg.NumAsset)*uint64(cfg.NumPartAccounts) + // assets*accounts
			(fee)*uint64(cfg.NumAsset) + // asset creations
			(fee)*uint64(cfg.NumAsset)*uint64(cfg.NumPartAccounts) + // asset opt-ins
			(fee)*uint64(cfg.NumAsset)*uint64(cfg.NumPartAccounts) // asset distributions
		requiredBalance += assetCost
	}
	if cfg.NumApp > 0 {
		creationCost := uint64(cfg.NumApp) * proto.AppFlatParamsMinBalance * uint64(proto.MaxAppsCreated)
		optInCost := uint64(cfg.NumApp) * proto.AppFlatOptInMinBalance * uint64(proto.MaxAppsOptedIn)
		maxGlobalSchema := basics.StateSchema{NumUint: proto.MaxGlobalSchemaEntries, NumByteSlice: proto.MaxGlobalSchemaEntries}
		maxLocalSchema := basics.StateSchema{NumUint: proto.MaxLocalSchemaEntries, NumByteSlice: proto.MaxLocalSchemaEntries}
		schemaCost := uint64(cfg.NumApp) * (maxGlobalSchema.MinBalance(&proto).Raw*uint64(proto.MaxAppsCreated) +
			maxLocalSchema.MinBalance(&proto).Raw*uint64(proto.MaxAppsOptedIn))
		requiredBalance += creationCost + optInCost + schemaCost
	}
	// add cost of transactions
	requiredBalance += (cfg.MaxAmt + fee) * 2 * cfg.TxnPerSec * uint64(math.Ceil(cfg.RefreshTime.Seconds()))

	// override computed value if less than configured value
	if cfg.MinAccountFunds > requiredBalance {
		requiredBalance = cfg.MinAccountFunds
	}

	return
}

func fundAccounts(accounts map[string]uint64, client libgoal.Client, cfg PpConfig) error {
	srcFunds := accounts[cfg.SrcAccount]

	startTime := time.Now()
	var totalSent uint64

	// Fee of 0 will make cause the function to use the suggested one by network
	fee := uint64(0)

	minFund, err := computeAccountMinBalance(client, cfg)
	if err != nil {
		return err
	}

	fmt.Printf("adjusting account balance to %d\n", minFund)
	for addr, balance := range accounts {
		if !cfg.Quiet {
			fmt.Printf("adjusting balance of account %v\n", addr)
		}
		if balance < minFund {
			toSend := minFund - balance
			if srcFunds <= toSend {
				return fmt.Errorf("source account %s has insufficient funds %d - needs %d", cfg.SrcAccount, srcFunds, toSend)
			}
			srcFunds -= toSend
			if !cfg.Quiet {
				fmt.Printf("adjusting balance of account %v by %d\n ", addr, toSend)
			}
			_, err := sendPaymentFromUnencryptedWallet(client, cfg.SrcAccount, addr, fee, toSend, nil)
			if err != nil {
				return err
			}
			accounts[addr] = minFund
			if !cfg.Quiet {
				fmt.Printf("account balance for key %s is %d\n", addr, accounts[addr])
			}

			totalSent++
			throttleTransactionRate(startTime, cfg, totalSent)
		}
	}
	return nil
}

func sendPaymentFromUnencryptedWallet(client libgoal.Client, from, to string, fee, amount uint64, note []byte) (transactions.Transaction, error) {
	wh, err := client.GetUnencryptedWalletHandle()
	if err != nil {
		return transactions.Transaction{}, err
	}
	// generate a random lease to avoid duplicate transaction failures
	var lease [32]byte
	crypto.RandBytes(lease[:])

	return client.SendPaymentFromWalletWithLease(wh, nil, from, to, fee, amount, note, "", lease, 0, 0)
}

func refreshAccounts(accounts map[string]uint64, client libgoal.Client, cfg PpConfig) error {
	for addr := range accounts {
		amount, err := client.GetBalance(addr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error refreshAccounts: %v\n", err)
			return err
		}

		accounts[addr] = amount
	}

	return fundAccounts(accounts, client, cfg)
}

// return a shuffled list of accounts with some minimum balance
func listSufficientAccounts(accounts map[string]uint64, minimumAmount uint64, except string) []string {
	out := make([]string, 0, len(accounts))
	for key, value := range accounts {
		if key == except {
			continue
		}
		if value >= minimumAmount {
			out = append(out, key)
		}
	}
	rand.Shuffle(len(out), func(i, j int) { t := out[i]; out[i] = out[j]; out[j] = t })
	return out
}

// RunPingPong starts ping pong process
func RunPingPong(ctx context.Context, ac libgoal.Client, accounts map[string]uint64, cinfo CreatablesInfo, cfg PpConfig) {
	// Infinite loop given:
	//  - accounts -> map of accounts to include in transfers (including src account, which we don't want to use)
	//  - cfg      -> configuration for how to proceed
	// LOOP {
	// 		for time.Now() < StopRunTime
	//			FromList = Randomize list of accounts
	//			ToList = Randomize list of accounts
	//			for i, from := range FromList
	//				Send(from, ToList[i], CalcAmount, CalcFee)
	//			If DelayBetween != 0 { sleep(delay) }
	//		If RestTime > 0 { sleep(RestTime) }
	//		If time-to-refresh
	//			accounts, cfg, err = PrepareAccounts()
	//			error = fundAccounts()
	//  }

	var runTime time.Duration
	if cfg.RunTime > 0 {
		runTime = cfg.RunTime
	} else {
		runTime = 10000 * time.Hour // Effectively 'forever'
	}
	var endTime time.Time
	if cfg.MaxRuntime > 0 {
		endTime = time.Now().Add(cfg.MaxRuntime)
	}
	restTime := cfg.RestTime
	refreshTime := time.Now().Add(cfg.RefreshTime)

	for {
		if ctx.Err() != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error bad context in RunPingPong: %v\n", ctx.Err())
			break
		}
		startTime := time.Now()
		stopTime := startTime.Add(runTime)

		var totalSent, totalSucceeded uint64
		for !time.Now().After(stopTime) {
			if cfg.MaxRuntime > 0 && time.Now().After(endTime) {
				fmt.Printf("Terminating after max run time of %.f seconds\n", cfg.MaxRuntime.Seconds())
				return
			}

			minimumAmount := cfg.MinAccountFunds + (cfg.MaxAmt+cfg.MaxFee)*2
			fromList := listSufficientAccounts(accounts, minimumAmount, cfg.SrcAccount)
			// in group tests txns are sent back and forth, so both parties need funds
			if cfg.GroupSize == 1 {
				minimumAmount = 0
			}
			toList := listSufficientAccounts(accounts, minimumAmount, cfg.SrcAccount)

			sent, succeeded, err := sendFromTo(fromList, toList, accounts, cinfo, ac, cfg)
			totalSent += sent
			totalSucceeded += succeeded
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "error sending transactions: %v\n", err)
			}

			if cfg.RefreshTime > 0 && time.Now().After(refreshTime) {
				err = refreshAccounts(accounts, ac, cfg)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "error refreshing: %v\n", err)
				}

				refreshTime = refreshTime.Add(cfg.RefreshTime)
			}

			throttleTransactionRate(startTime, cfg, totalSent)
		}

		timeDelta := time.Now().Sub(startTime)
		_, _ = fmt.Fprintf(os.Stdout, "Sent %d transactions (%d attempted) in %d seconds\n", totalSucceeded, totalSent, int(math.Round(timeDelta.Seconds())))
		if cfg.RestTime > 0 {
			_, _ = fmt.Fprintf(os.Stdout, "Pausing %d seconds before sending more transactions\n", int(math.Round(cfg.RestTime.Seconds())))
			time.Sleep(restTime)
		}
	}
}

func getCreatableID(cfg PpConfig, cinfo CreatablesInfo) (aidx uint64) {
	if cfg.NumAsset > 0 {
		rindex := rand.Intn(len(cinfo.AssetParams))
		i := 0
		for k := range cinfo.AssetParams {
			if i == rindex {
				aidx = k
				break
			}
			i++
		}
	} else if cfg.NumApp > 0 {
		rindex := rand.Intn(len(cinfo.AppParams))
		i := 0
		for k := range cinfo.AppParams {
			if i == rindex {
				aidx = k
				break
			}
			i++
		}
	}
	return
}

func sendFromTo(
	fromList, toList []string, accounts map[string]uint64,
	cinfo CreatablesInfo,
	client libgoal.Client, cfg PpConfig,
) (sentCount, successCount uint64, err error) {

	amt := cfg.MaxAmt
	fee := cfg.MaxFee

	assetsByCreator := make(map[string][]*v1.AssetParams)
	for _, p := range cinfo.AssetParams {
		c := p.Creator
		assetsByCreator[c] = append(assetsByCreator[c], &p)
	}
	for i, from := range fromList {
		if cfg.RandomizeAmt {
			amt = rand.Uint64()%cfg.MaxAmt + 1
		}

		if cfg.RandomizeFee {
			fee = rand.Uint64()%(cfg.MaxFee-cfg.MinFee) + cfg.MinFee
		}

		to := toList[i]
		if cfg.RandomizeDst {
			var addr basics.Address
			crypto.RandBytes(addr[:])
			to = addr.String()
		}

		// Broadcast transaction
		var sendErr error
		fromBalanceChange := int64(0)
		toBalanceChange := int64(0)
		if cfg.NumAsset > 0 {
			amt = 1
		}

		if cfg.GroupSize == 1 {
			// generate random assetID or appId if we send asset/app txns
			aidx := getCreatableID(cfg, cinfo)
			// Construct single txn
			txn, consErr := constructTxn(from, to, fee, amt, aidx, cinfo, client, cfg)
			if consErr != nil {
				err = consErr
				_, _ = fmt.Fprintf(os.Stderr, "constructTxn failed: %v\n", err)
				return
			}

			// would we have enough money after taking into account the current updated fees ?
			if accounts[from] <= (txn.Fee.Raw + amt + cfg.MinAccountFunds) {
				_, _ = fmt.Fprintf(os.Stdout, "Skipping sending %d : %s -> %s; Current cost too high.\n", amt, from, to)
				continue
			}

			fromBalanceChange = -int64(txn.Fee.Raw + amt)
			toBalanceChange = int64(amt)

			// Sign txn
			stxn, signErr := signTxn(from, txn, client, cfg)
			if signErr != nil {
				err = signErr
				_, _ = fmt.Fprintf(os.Stderr, "signTxn failed: %v\n", err)
				return
			}

			sentCount++
			_, sendErr = client.BroadcastTransaction(stxn)
			if sendErr != nil {
				fmt.Printf("Warning, cannot broadcast txn, %s\n", sendErr)
			}
		} else {
			// Generate txn group

			// In rekeying test there are two txns sent in a group
			// the first is  from -> to with RekeyTo=to
			// the second is from -> to with RekeyTo=from and AuthAddr=to
			// So that rekeying test only supports groups of two

			var txGroup []transactions.Transaction
			var txSigners []string
			for j := 0; j < int(cfg.GroupSize); j++ {
				var txn transactions.Transaction
				var signer string
				if j%2 == 0 {
					txn, err = constructTxn(from, to, fee, amt, 0, cinfo, client, cfg)
					fromBalanceChange -= int64(txn.Fee.Raw + amt)
					toBalanceChange += int64(amt)
					signer = from
				} else if cfg.GroupSize == 2 && cfg.Rekey {
					txn, err = constructTxn(from, to, fee, amt, 0, cinfo, client, cfg)
					fromBalanceChange -= int64(txn.Fee.Raw + amt)
					toBalanceChange += int64(amt)
					signer = to
				} else {
					txn, err = constructTxn(to, from, fee, amt, 0, cinfo, client, cfg)
					toBalanceChange -= int64(txn.Fee.Raw + amt)
					fromBalanceChange += int64(amt)
					signer = to
				}
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "group tx failed: %v\n", err)
					return
				}
				if cfg.RandomizeAmt {
					amt = rand.Uint64()%cfg.MaxAmt + 1
				}
				if cfg.Rekey {
					if from == signer {
						// rekey to the receiver the first txn of the rekeying pair
						txn.RekeyTo, err = basics.UnmarshalChecksumAddress(to)
					} else {
						// rekey to the sender the second txn of the rekeying pair
						txn.RekeyTo, err = basics.UnmarshalChecksumAddress(from)
					}
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "Address unmarshalling failed: %v\n", err)
						return
					}
				}
				txGroup = append(txGroup, txn)
				txSigners = append(txSigners, signer)
			}

			// would we have enough money after taking into account the current updated fees ?
			if int64(accounts[from])+fromBalanceChange <= int64(cfg.MinAccountFunds) {
				_, _ = fmt.Fprintf(os.Stdout, "Skipping sending %d : %s -> %s; Current cost too high.\n", amt, from, to)
				continue
			}
			if int64(accounts[to])+toBalanceChange <= int64(cfg.MinAccountFunds) {
				_, _ = fmt.Fprintf(os.Stdout, "Skipping sending back %d : %s -> %s; Current cost too high.\n", amt, to, from)
				continue
			}

			// Generate group ID
			gid, gidErr := client.GroupID(txGroup)
			if gidErr != nil {
				err = gidErr
				return
			}

			if !cfg.Quiet {
				_, _ = fmt.Fprintf(os.Stdout, "Sending TxnGroup: ID %v, size %v \n", gid, len(txGroup))
			}

			// Sign each transaction
			var stxGroup []transactions.SignedTxn
			for j, txn := range txGroup {
				txn.Group = gid
				stxn, signErr := signTxn(txSigners[j], txn, client, cfg)
				if signErr != nil {
					err = signErr
					return
				}
				stxGroup = append(stxGroup, stxn)
			}

			sentCount++
			sendErr = client.BroadcastTransactionGroup(stxGroup)
		}

		if sendErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error sending Transaction, sleeping .5 seconds: %v\n", sendErr)
			err = sendErr
			time.Sleep(500 * time.Millisecond)
			return
		}

		successCount++
		accounts[from] = uint64(fromBalanceChange + int64(accounts[from]))
		accounts[to] = uint64(toBalanceChange + int64(accounts[to]))
		if cfg.DelayBetweenTxn > 0 {
			time.Sleep(cfg.DelayBetweenTxn)
		}
	}
	return
}

func constructTxn(from, to string, fee, amt, aidx uint64, cinfo CreatablesInfo, client libgoal.Client, cfg PpConfig) (txn transactions.Transaction, err error) {
	var noteField []byte
	const pingpongTag = "pingpong"
	const tagLen = uint32(len(pingpongTag))
	const randomBaseLen = uint32(8)
	const maxNoteFieldLen = uint32(1024)
	var noteLength = uint32(tagLen) + randomBaseLen
	// if random note flag set, then append a random number of additional bytes
	if cfg.RandomNote {
		noteLength = noteLength + rand.Uint32()%(maxNoteFieldLen-noteLength)
	}
	noteField = make([]byte, noteLength, noteLength)
	copy(noteField, pingpongTag)
	crypto.RandBytes(noteField[tagLen:])

	// if random lease flag set, fill the lease field with random bytes
	var lease [32]byte
	if cfg.RandomLease {
		crypto.RandBytes(lease[:])
	}

	if cfg.NumApp > 0 { // Construct app transaction
		// select opted-in accounts for Txn.Accounts field
		var accounts []string
		if len(cinfo.OptIns[aidx]) > 0 {
			indices := rand.Perm(len(cinfo.OptIns[aidx]))
			limit := 4
			if len(indices) < limit {
				limit = len(indices)
			}
			for i := 0; i < limit; i++ {
				idx := indices[i]
				accounts = append(accounts, cinfo.OptIns[aidx][idx])
			}
		}
		txn, err = client.MakeUnsignedAppNoOpTx(aidx, nil, accounts, nil, nil)
		if err != nil {
			return
		}
		txn.Note = noteField[:]
		txn.Lease = lease
		txn, err = client.FillUnsignedTxTemplate(from, 0, 0, cfg.MaxFee, txn)
		if !cfg.Quiet {
			_, _ = fmt.Fprintf(os.Stdout, "Calling app %d : %s\n", aidx, from)
		}
	} else if cfg.NumAsset > 0 { // Construct asset transaction
		// select a pair of random opted-in accounts by aidx
		// use them as from/to addresses
		if len(cinfo.OptIns[aidx]) > 0 {
			indices := rand.Perm(len(cinfo.OptIns[aidx]))
			from = cinfo.OptIns[aidx][indices[0]]
			to = cinfo.OptIns[aidx][indices[1]]
		}
		txn, err = client.MakeUnsignedAssetSendTx(aidx, amt, to, "", "")
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout, "error making unsigned asset send tx %v\n", err)
			return
		}
		txn.Note = noteField[:]
		txn.Lease = lease
		txn, err = client.FillUnsignedTxTemplate(from, 0, 0, cfg.MaxFee, txn)
		if !cfg.Quiet {
			_, _ = fmt.Fprintf(os.Stdout, "Sending %d asset %d: %s -> %s\n", amt, aidx, from, to)
		}
	} else {
		txn, err = client.ConstructPayment(from, to, fee, amt, noteField[:], "", lease, 0, 0)
		if !cfg.Quiet {
			_, _ = fmt.Fprintf(os.Stdout, "Sending %d : %s -> %s\n", amt, from, to)
		}
	}

	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "error constructing transaction %v\n", err)
		return
	}
	// adjust transaction duration for 5 rounds. That would prevent it from getting stuck in the transaction pool for too long.
	txn.LastValid = txn.FirstValid + 5

	// if cfg.MaxFee == 0, automatically adjust the fee amount to required min fee
	if cfg.MaxFee == 0 {
		var suggestedFee uint64
		suggestedFee, err = client.SuggestedFee()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout, "error retrieving suggestedFee: %v\n", err)
			return
		}
		if suggestedFee > txn.Fee.Raw {
			txn.Fee.Raw = suggestedFee
		}
	}
	return
}

func signTxn(signer string, txn transactions.Transaction, client libgoal.Client, cfg PpConfig) (stxn transactions.SignedTxn, err error) {
	// Get wallet handle token
	var h []byte
	h, err = client.GetUnencryptedWalletHandle()
	if err != nil {
		return
	}

	var psig crypto.Signature

	if cfg.Rekey {
		stxn, err = client.SignTransactionWithWalletAndSigner(h, nil, signer, txn)
	} else if len(cfg.Program) > 0 {
		// If there's a program, sign it and use that in a lsig
		psig, err = client.SignProgramWithWallet(h, nil, signer, cfg.Program)
		if err != nil {
			return
		}
		// Fill in signed transaction
		stxn.Txn = txn
		stxn.Lsig.Logic = cfg.Program
		stxn.Lsig.Sig = psig
		stxn.Lsig.Args = cfg.LogicArgs
	} else {
		// Otherwise, just sign the transaction like normal
		stxn, err = client.SignTransactionWithWallet(h, nil, txn)
	}
	return
}
