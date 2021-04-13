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

	"github.com/algorand/go-algorand/config"
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

// WorkerState object holds a running pingpong worker
type WorkerState struct {
	cfg      PpConfig
	accounts map[string]uint64
	cinfo    CreatablesInfo

	nftStartTime  int64
	localNftIndex uint64
	nftHolders    map[string]int
}

// PrepareAccounts to set up accounts and asset accounts required for Ping Pong run
func (pps *WorkerState) PrepareAccounts(ac libgoal.Client) (err error) {
	pps.accounts, pps.cfg, err = ensureAccounts(ac, pps.cfg)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ensure accounts failed %v\n", err)
		return
	}
	cfg := pps.cfg

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
		assetAccounts, err = prepareNewAccounts(ac, cfg, wallet, pps.accounts)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare new accounts failed: %v\n", err)
			return
		}

		pps.cinfo.AssetParams, pps.cinfo.OptIns, err = pps.prepareAssets(assetAccounts, ac)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare assets failed %v\n", err)
			return
		}

		if !cfg.Quiet {
			for addr := range pps.accounts {
				fmt.Printf("final prepareAccounts, account addr: %s, balance: %d\n", addr, pps.accounts[addr])
			}
		}
	} else if cfg.NumApp > 0 {

		var appAccounts map[string]uint64
		appAccounts, err = prepareNewAccounts(ac, cfg, wallet, pps.accounts)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare new accounts failed: %v\n", err)
			return
		}
		pps.cinfo.AppParams, pps.cinfo.OptIns, err = prepareApps(appAccounts, ac, cfg)
		if err != nil {
			return
		}
		if !cfg.Quiet {
			for addr := range pps.accounts {
				fmt.Printf("final prepareAccounts, account addr: %s, balance: %d\n", addr, pps.accounts[addr])
			}
		}
	} else {
		err = fundAccounts(pps.accounts, ac, cfg)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
			return
		}
	}

	pps.cfg = cfg
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

var logPeriod = 5 * time.Second

// RunPingPong starts ping pong process
func (pps *WorkerState) RunPingPong(ctx context.Context, ac libgoal.Client) {
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

	cfg := pps.cfg
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

	var nftThrottler *throttler
	if pps.cfg.NftAsaPerSecond > 0 {
		nftThrottler = newThrottler(20, float64(pps.cfg.NftAsaPerSecond))
	}

	lastLog := time.Now()
	nextLog := lastLog.Add(logPeriod)

	for {
		if ctx.Err() != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error bad context in RunPingPong: %v\n", ctx.Err())
			break
		}
		startTime := time.Now()
		stopTime := startTime.Add(runTime)

		var totalSent, totalSucceeded, lastTotalSent uint64
		for {
			now := time.Now()
			if now.After(stopTime) {
				break
			}
			if now.After(nextLog) {
				dt := now.Sub(lastLog)
				fmt.Printf("%d sent, %0.2f/s (%d total)\n", totalSent-lastTotalSent, float64(totalSent-lastTotalSent)/dt.Seconds(), totalSent)
				lastTotalSent = totalSent
				for now.After(nextLog) {
					nextLog = nextLog.Add(logPeriod)
				}
				lastLog = now
			}

			if cfg.MaxRuntime > 0 && time.Now().After(endTime) {
				fmt.Printf("Terminating after max run time of %.f seconds\n", cfg.MaxRuntime.Seconds())
				return
			}

			if pps.cfg.NftAsaPerSecond > 0 {
				sent, err := pps.makeNftTraffic(ac)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error sending nft transactions: %v\n", err)
				}
				nftThrottler.maybeSleep(int(sent))
				totalSent += sent
				continue
			}

			minimumAmount := cfg.MinAccountFunds + (cfg.MaxAmt+cfg.MaxFee)*2
			fromList := listSufficientAccounts(pps.accounts, minimumAmount, cfg.SrcAccount)
			// in group tests txns are sent back and forth, so both parties need funds
			if cfg.GroupSize == 1 {
				minimumAmount = 0
			}
			toList := listSufficientAccounts(pps.accounts, minimumAmount, cfg.SrcAccount)

			sent, succeeded, err := pps.sendFromTo(fromList, toList, ac)
			totalSent += sent
			totalSucceeded += succeeded
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "error sending transactions: %v\n", err)
			}

			if cfg.RefreshTime > 0 && time.Now().After(refreshTime) {
				err = refreshAccounts(pps.accounts, ac, cfg)
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

// NewPingpong creates a new pingpong WorkerState
func NewPingpong(cfg PpConfig) *WorkerState {
	return &WorkerState{cfg: cfg, nftHolders: make(map[string]int)}
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

func (pps *WorkerState) fee() uint64 {
	cfg := pps.cfg
	fee := cfg.MaxFee
	if cfg.RandomizeFee {
		fee = rand.Uint64()%(cfg.MaxFee-cfg.MinFee) + cfg.MinFee
	}
	return fee
}

func (pps *WorkerState) makeNftTraffic(client libgoal.Client) (sentCount uint64, err error) {
	fee := pps.fee()
	if (len(pps.nftHolders) == 0) || ((float64(int(pps.cfg.NftAsaAccountInFlight)-len(pps.nftHolders)) / float64(pps.cfg.NftAsaAccountInFlight)) >= rand.Float64()) {
		var addr string
		var wallet []byte
		wallet, err = client.GetUnencryptedWalletHandle()
		if err != nil {
			return
		}
		addr, err = client.GenerateAddress(wallet)
		if err != nil {
			return
		}
		fmt.Printf("new NFT holder %s\n", addr)
		var proto config.ConsensusParams
		proto, err = getProto(client)
		if err != nil {
			return
		}
		// enough for the per-asa minbalance and more than enough for the txns to create them
		toSend := proto.MinBalance * uint64(pps.cfg.NftAsaPerAccount+1) * 2
		pps.nftHolders[addr] = 0
		_, err = sendPaymentFromUnencryptedWallet(client, pps.cfg.SrcAccount, addr, fee, toSend, nil)
		if err != nil {
			return
		}
		sentCount++
		// we ran one txn above already to fund the new addr,
		// we'll run a second txn below
	}
	// pick a random sender from nft holder sub accounts
	pick := rand.Intn(len(pps.nftHolders))
	pos := 0
	var sender string
	var senderNftCount int
	for addr, nftCount := range pps.nftHolders {
		sender = addr
		senderNftCount = nftCount
		if pos == pick {
			break
		}
		pos++

	}
	var meta [32]byte
	rand.Read(meta[:])
	assetName := pps.nftSpamAssetName()
	const totalSupply = 1
	txn, err := client.MakeUnsignedAssetCreateTx(totalSupply, false, sender, sender, sender, sender, "ping", assetName, "", meta[:], 0)
	if err != nil {
		fmt.Printf("Cannot make asset create txn with meta %v\n", meta)
		return
	}
	txn, err = client.FillUnsignedTxTemplate(sender, 0, 0, pps.cfg.MaxFee, txn)
	if err != nil {
		fmt.Printf("Cannot fill asset creation txn\n")
		return
	}
	if senderNftCount+1 >= int(pps.cfg.NftAsaPerAccount) {
		delete(pps.nftHolders, sender)
	} else {
		pps.nftHolders[sender] = senderNftCount + 1
	}
	stxn, err := signTxn(sender, txn, client, pps.cfg)
	if err != nil {
		return
	}
	sentCount++
	_, err = client.BroadcastTransaction(stxn)
	return
}

func (pps *WorkerState) sendFromTo(
	fromList, toList []string,
	client libgoal.Client,
) (sentCount, successCount uint64, err error) {
	accounts := pps.accounts
	cinfo := pps.cinfo
	cfg := pps.cfg

	amt := cfg.MaxAmt

	assetsByCreator := make(map[string][]*v1.AssetParams)
	for _, p := range cinfo.AssetParams {
		c := p.Creator
		assetsByCreator[c] = append(assetsByCreator[c], &p)
	}
	for i, from := range fromList {
		if cfg.RandomizeAmt {
			amt = rand.Uint64()%cfg.MaxAmt + 1
		}

		fee := pps.fee()

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
			txn, consErr := pps.constructTxn(from, to, fee, amt, aidx, client)
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
					txn, err = pps.constructTxn(from, to, fee, amt, 0, client)
					fromBalanceChange -= int64(txn.Fee.Raw + amt)
					toBalanceChange += int64(amt)
					signer = from
				} else if cfg.GroupSize == 2 && cfg.Rekey {
					txn, err = pps.constructTxn(from, to, fee, amt, 0, client)
					fromBalanceChange -= int64(txn.Fee.Raw + amt)
					toBalanceChange += int64(amt)
					signer = to
				} else {
					txn, err = pps.constructTxn(to, from, fee, amt, 0, client)
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

func (pps *WorkerState) nftSpamAssetName() string {
	if pps.nftStartTime == 0 {
		pps.nftStartTime = time.Now().Unix()
	}
	pps.localNftIndex++
	return fmt.Sprintf("nft%d_%d", pps.nftStartTime, pps.localNftIndex)
}

func (pps *WorkerState) constructTxn(from, to string, fee, amt, aidx uint64, client libgoal.Client) (txn transactions.Transaction, err error) {
	cfg := pps.cfg
	cinfo := pps.cinfo
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

type timeCount struct {
	when  time.Time
	count int
}

type throttler struct {
	times []timeCount

	next int

	// target x per-second
	xps float64

	// rough proportional + integral control
	iterm float64
}

func newThrottler(windowSize int, targetPerSecond float64) *throttler {
	return &throttler{times: make([]timeCount, windowSize), xps: targetPerSecond, iterm: 0.0}
}

func (t *throttler) maybeSleep(count int) {
	now := time.Now()
	t.times[t.next].when = now
	t.times[t.next].count = count
	nn := (t.next + 1) % len(t.times)
	t.next = nn
	if t.times[nn].when.IsZero() {
		return
	}
	dt := now.Sub(t.times[nn].when)
	countsum := 0
	for i, tc := range t.times {
		if i != nn {
			countsum += tc.count
		}
	}
	rate := float64(countsum) / dt.Seconds()
	if rate > t.xps {
		// rate too high, slow down
		desiredSeconds := float64(countsum) / t.xps
		extraSeconds := desiredSeconds - dt.Seconds()
		t.iterm += 0.1 * extraSeconds / float64(len(t.times))
		time.Sleep(time.Duration(int64(1000000000.0 * (extraSeconds + t.iterm) / float64(len(t.times)))))

	} else {
		t.iterm *= 0.95
	}
}
