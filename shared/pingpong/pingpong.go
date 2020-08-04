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
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
)

// PrepareAccounts to set up accounts and asset accounts required for Ping Pong run
func PrepareAccounts(ac libgoal.Client, initCfg PpConfig) (accounts map[string]uint64, assetParams map[uint64]v1.AssetParams, appParams map[uint64]v1.AppParams, cfg PpConfig, err error) {
	cfg = initCfg
	accounts, cfg, err = ensureAccounts(ac, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ensure accounts failed %v\n", err)
		return
	}

	if cfg.NumAsset > 0 {
		// zero out max amount for asset transactions
		cfg.MaxAmt = 0

		wallet, walletErr := ac.GetUnencryptedWalletHandle()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "unable to access wallet %v\n", walletErr)
			err = walletErr
			return
		}
		fmt.Printf("Generating %v new accounts for asset transfer test\n", cfg.NumPartAccounts)
		// remove existing accounts except for src account
		for k := range accounts {
			if k != cfg.SrcAccount {
				delete(accounts, k)
			}
		}
		// create new accounts for asset testing
		assetAccounts := make(map[string]uint64)
		assetAccounts, err = generateAccounts(ac, assetAccounts, cfg.NumPartAccounts-1, wallet)

		for addr := range assetAccounts {
			fmt.Printf("generated account %v\n", addr)
		}

		for k := range assetAccounts {
			accounts[k] = assetAccounts[k]
		}
		err = fundAccounts(accounts, ac, cfg)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
			return
		}

		assetParams, err = prepareAssets(assetAccounts, ac, cfg)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare assets failed %v\n", err)
			return
		}

		for k := range assetAccounts {
			accounts[k] = assetAccounts[k]
		}
	} else if cfg.NumApp > 0 {
		appParams, err = prepareApps(accounts, ac, cfg)
		if err != nil {
			return
		}
	}

	for addr := range accounts {
		fmt.Printf("**** participant account %v\n", addr)
	}

	err = fundAccounts(accounts, ac, cfg)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
		return
	}

	return
}

// determine the min balance per participant account
func computeAccountMinBalance(cfg PpConfig) (requiredBalance uint64) {
	const minActiveAccountBalance uint64 = 100000 // min balance for any active account

	var fee uint64 = 1000
	if cfg.MinFee > fee {
		fee = cfg.MinFee
	}
	if cfg.MaxFee != 0 {
		fee = cfg.MaxFee
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

	minFund := computeAccountMinBalance(cfg)

	fmt.Printf("adjusting account balance to %d\n", minFund)
	for addr, balance := range accounts {
		fmt.Printf("adjusting balance of account %v\n", addr)
		if balance < minFund {
			toSend := minFund - balance
			if srcFunds <= toSend {
				return fmt.Errorf("source account %s has insufficient funds %d - needs %d", cfg.SrcAccount, srcFunds, toSend)
			}
			srcFunds -= toSend
			_, err := client.SendPaymentFromUnencryptedWallet(cfg.SrcAccount, addr, fee, toSend, nil)
			if err != nil {
				return err
			}
			accounts[addr] = minFund

			totalSent++
			throttleTransactionRate(startTime, cfg, totalSent)
		}
	}
	return nil
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
func RunPingPong(ctx context.Context, ac libgoal.Client, accounts map[string]uint64, assetParam map[uint64]v1.AssetParams, appParam map[uint64]v1.AppParams, cfg PpConfig) {
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

			fromList := listSufficientAccounts(accounts, cfg.MinAccountFunds+(cfg.MaxAmt+cfg.MaxFee)*2, cfg.SrcAccount)
			toList := listSufficientAccounts(accounts, 0, cfg.SrcAccount)

			sent, succeded, err := sendFromTo(fromList, toList, accounts, assetParam, appParam, ac, cfg)
			totalSent += sent
			totalSucceeded += succeded
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

func sendFromTo(fromList, toList []string, accounts map[string]uint64, assetParams map[uint64]v1.AssetParams, appParams map[uint64]v1.AppParams, client libgoal.Client, cfg PpConfig) (sentCount, successCount uint64, err error) {
	amt := cfg.MaxAmt
	fee := cfg.MaxFee
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

		// app or asset ID
		var aidx uint64
		if cfg.GroupSize == 1 {
			if cfg.NumAsset > 0 { // generate random assetID if we send asset txns
				rindex := rand.Intn(len(assetParams))
				i := 0
				for k := range assetParams {
					if i == rindex {
						aidx = k
						break
					}
					i++
				}
			} else if cfg.NumApp > 0 {
				rindex := rand.Intn(len(appParams))
				i := 0
				for k := range appParams {
					if i == rindex {
						aidx = k
						break
					}
					i++
				}
			} else {
				aidx = 0
			}

			// Construct single txn
			txn, consErr := constructTxn(from, to, fee, amt, aidx, client, cfg)
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
		} else {
			// Generate txn group
			var txGroup []transactions.Transaction
			for j := 0; j < int(cfg.GroupSize); j++ {
				var txn transactions.Transaction
				if j%2 == 0 {
					txn, err = constructTxn(from, to, fee, amt, 0, client, cfg)
					fromBalanceChange -= int64(txn.Fee.Raw + amt)
					toBalanceChange += int64(amt)
				} else {
					txn, err = constructTxn(to, from, fee, amt, 0, client, cfg)
					toBalanceChange -= int64(txn.Fee.Raw + amt)
					fromBalanceChange += int64(amt)
				}
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "group tx failed: %v\n", err)
					return
				}
				txGroup = append(txGroup, txn)
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
				var lf string
				if j%2 == 0 {
					lf = from
				} else {
					lf = to
				}
				stxn, signErr := signTxn(lf, txn, client, cfg)
				if signErr != nil {
					err = signErr
					return
				}
				stxGroup = append(stxGroup, stxn)
			}

			sentCount++
			sendErr = client.BroadcastTransactionGroup(stxGroup)
		}

		if sendErr != nil && !cfg.Quiet {
			_, _ = fmt.Fprintf(os.Stderr, "error sending transaction: %v\n", sendErr)
		} else {
			successCount++
			accounts[from] = uint64(fromBalanceChange + int64(accounts[from]))
			accounts[to] = uint64(toBalanceChange + int64(accounts[to]))
		}
		if sendErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error sending Transaction, sleeping .5 seconds: %v\n", sendErr)
			err = sendErr
			time.Sleep(500 * time.Millisecond)
			return
		}
		if cfg.DelayBetweenTxn > 0 {
			time.Sleep(cfg.DelayBetweenTxn)
		}
	}
	return
}

func constructTxn(from, to string, fee, amt, aidx uint64, client libgoal.Client, cfg PpConfig) (txn transactions.Transaction, err error) {
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
		txn, err = client.MakeUnsignedAppNoOpTx(aidx, nil, nil, nil, nil)
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

func signTxn(from string, txn transactions.Transaction, client libgoal.Client, cfg PpConfig) (stxn transactions.SignedTxn, err error) {
	// Get wallet handle token
	var h []byte
	h, err = client.GetUnencryptedWalletHandle()
	if err != nil {
		return
	}

	var psig crypto.Signature

	if len(cfg.Program) > 0 {
		// If there's a program, sign it and use that in a lsig
		psig, err = client.SignProgramWithWallet(h, nil, from, cfg.Program)
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
		if err != nil {
			return
		}
	}
	return
}
