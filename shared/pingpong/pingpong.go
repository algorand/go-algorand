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
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
)

// PrepareAccounts to set up accounts required for Ping Pong run
func PrepareAccounts(ac libgoal.Client, initCfg PpConfig) (accounts map[string]uint64, cfg PpConfig, err error) {
	cfg = initCfg
	accounts, cfg, err = ensureAccounts(ac, cfg)
	if err != nil {
		return
	}

	err = fundAccounts(accounts, ac, cfg)
	if err != nil {
		return
	}

	return
}

func fundAccounts(accounts map[string]uint64, client libgoal.Client, cfg PpConfig) error {
	srcFunds := accounts[cfg.SrcAccount]

	// Fee of 0 will make cause the function to use the suggested one by network
	fee := uint64(0)

	for addr, balance := range accounts {
		if balance < cfg.MinAccountFunds {
			toSend := cfg.MinAccountFunds - balance
			if srcFunds <= toSend {
				return fmt.Errorf("source account has insufficient funds %d - needs %d", srcFunds, toSend)
			}
			srcFunds -= toSend
			_, err := client.SendPaymentFromUnencryptedWallet(cfg.SrcAccount, addr, fee, toSend, nil)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func refreshAccounts(accounts map[string]uint64, client libgoal.Client, cfg PpConfig) error {
	for addr := range accounts {
		amount, err := client.GetBalance(addr)
		if err != nil {
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
func RunPingPong(ctx context.Context, ac libgoal.Client, accounts map[string]uint64, cfg PpConfig) {
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
			break
		}
		startTime := time.Now()
		stopTime := startTime.Add(runTime)

		var totalSent, totalSucceeded uint64
		for !time.Now().After(stopTime) {
			fromList := listSufficientAccounts(accounts, cfg.MinAccountFunds+(cfg.MaxAmt+cfg.MaxFee)*2, cfg.SrcAccount)
			toList := listSufficientAccounts(accounts, 0, cfg.SrcAccount)

			sent, succeded, err := sendFromTo(fromList, toList, accounts, ac, cfg)
			totalSent += sent
			totalSucceeded += succeded
			if err != nil {
				fmt.Fprintf(os.Stderr, "error sending transactions: %v\n", err)
			}

			if cfg.RefreshTime > 0 && time.Now().After(refreshTime) {
				err = refreshAccounts(accounts, ac, cfg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error refreshing: %v\n", err)
				}

				refreshTime = refreshTime.Add(cfg.RefreshTime)
			}

			localTimeDelta := time.Now().Sub(startTime)
			currentTps := float64(totalSent) / localTimeDelta.Seconds()
			if currentTps > float64(cfg.TxnPerSec) {
				sleepSec := float64(totalSent)/float64(cfg.TxnPerSec) - localTimeDelta.Seconds()
				sleepTime := time.Duration(int64(math.Round(sleepSec*1000))) * time.Millisecond
				time.Sleep(sleepTime)
			}
		}
		timeDelta := time.Now().Sub(startTime)
		fmt.Fprintf(os.Stdout, "Sent %d transactions (%d attempted) in %d seconds\n", totalSucceeded, totalSent, int(math.Round(timeDelta.Seconds())))
		if cfg.RestTime > 0 {
			fmt.Fprintf(os.Stdout, "Pausing %d seconds before sending more transactions\n", int(math.Round(cfg.RestTime.Seconds())))
			time.Sleep(restTime)
		}
	}
}

func sendFromTo(fromList, toList []string, accounts map[string]uint64, client libgoal.Client, cfg PpConfig) (sentCount, successCount uint64, err error) {
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
		if cfg.GroupSize == 1 {

			if !cfg.Quiet {
				fmt.Fprintf(os.Stdout, "Sending %d : %s -> %s\n", amt, from, to)
			}

			// Construct single txn
			txn, consErr := constructTxn(from, to, fee, amt, client, cfg)
			if consErr != nil {
				err = consErr
				return
			}

			// would we have enough money after taking into account the current updated fees ?
			if accounts[from] <= (txn.Fee.Raw + amt + cfg.MinAccountFunds) {
				fmt.Fprintf(os.Stdout, "Skipping sending %d : %s -> %s; Current cost too high.\n", amt, from, to)
				continue
			}
			fromBalanceChange = -int64(txn.Fee.Raw + amt)
			toBalanceChange = int64(amt)

			// Sign txn
			stxn, signErr := signTxn(from, txn, client, cfg)
			if signErr != nil {
				err = signErr
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
					txn, err = constructTxn(from, to, fee, amt, client, cfg)
					fromBalanceChange -= int64(txn.Fee.Raw + amt)
					toBalanceChange += int64(amt)
				} else {
					txn, err = constructTxn(to, from, fee, amt, client, cfg)
					toBalanceChange -= int64(txn.Fee.Raw + amt)
					fromBalanceChange += int64(amt)
				}
				if err != nil {
					return
				}
				txGroup = append(txGroup, txn)
			}

			// would we have enough money after taking into account the current updated fees ?
			if int64(accounts[from])+fromBalanceChange <= int64(cfg.MinAccountFunds) {
				fmt.Fprintf(os.Stdout, "Skipping sending %d : %s -> %s; Current cost too high.\n", amt, from, to)
				continue
			}
			if int64(accounts[to])+toBalanceChange <= int64(cfg.MinAccountFunds) {
				fmt.Fprintf(os.Stdout, "Skipping sending back %d : %s -> %s; Current cost too high.\n", amt, to, from)
				continue
			}

			// Generate group ID
			gid, gidErr := client.GroupID(txGroup)
			if gidErr != nil {
				err = gidErr
				return
			}

			if !cfg.Quiet {
				fmt.Fprintf(os.Stdout, "Sending TxnGroup: ID %v, size %v \n", gid, len(txGroup))
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
			fmt.Fprintf(os.Stderr, "error sending transaction: %v\n", sendErr)
		} else {
			successCount++
			accounts[from] = uint64(fromBalanceChange + int64(accounts[from]))
			accounts[to] = uint64(toBalanceChange + int64(accounts[to]))
		}
		if sendErr != nil {
			err = sendErr
			return
		}
		if cfg.DelayBetweenTxn > 0 {
			time.Sleep(cfg.DelayBetweenTxn)
		}
	}
	return
}

func constructTxn(from, to string, fee, amt uint64, client libgoal.Client, cfg PpConfig) (txn transactions.Transaction, err error) {
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

	// Construct payment transaction
	txn, err = client.ConstructPayment(from, to, fee, amt, noteField[:], "", [32]byte{}, 0, 0)
	if err != nil {
		return
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
