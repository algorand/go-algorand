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

// Package pingpong provides a transaction generating utility for performance testing.
//
//nolint:unused,structcheck,deadcode,varcheck // ignore unused pingpong code
package pingpong

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
)

// CreatablesInfo has information about created assets, apps and opting in
type CreatablesInfo struct {
	AssetParams map[basics.AssetIndex]model.AssetParams
	AppParams   map[basics.AppIndex]model.ApplicationParams
	OptIns      map[any][]string
}

// pingPongAccount represents the account state for each account in the pingpong application
// This includes the current balance and public/private keys tied to the account
type pingPongAccount struct {
	balance      atomic.Uint64
	balanceRound uint64

	deadlock.Mutex
	sk *crypto.SignatureSecrets
	pk basics.Address

	// asset holdings
	holdings map[basics.AssetIndex]uint64
}

func (ppa *pingPongAccount) getBalance() uint64 {
	return ppa.balance.Load()
}

func (ppa *pingPongAccount) setBalance(balance uint64) {
	ppa.balance.Store(balance)
}

func (ppa *pingPongAccount) addBalance(offset int64) {
	if offset >= 0 {
		ppa.balance.Add(uint64(offset))
		return
	}
	for {
		v := ppa.balance.Load()
		nv := v - uint64(-offset)
		done := ppa.balance.CompareAndSwap(v, nv)
		if done {
			return
		}
	}
}

func (ppa *pingPongAccount) getAsset(aid basics.AssetIndex) (v uint64, ok bool) {
	ppa.Lock()
	defer ppa.Unlock()
	v, ok = ppa.holdings[aid]
	return
}
func (ppa *pingPongAccount) setAsset(aid basics.AssetIndex, value uint64) {
	ppa.Lock()
	defer ppa.Unlock()
	ppa.holdings[aid] = value
}
func (ppa *pingPongAccount) addAsset(aid basics.AssetIndex, dv int64) {
	ppa.Lock()
	defer ppa.Unlock()
	v := ppa.holdings[aid]
	if dv >= 0 {
		v += uint64(dv)
	} else {
		v -= uint64(-dv)
	}
	ppa.holdings[aid] = v
}

func (ppa *pingPongAccount) String() string {
	ppa.Lock()
	defer ppa.Unlock()
	var ow strings.Builder
	fmt.Fprintf(&ow, "%s %d", ppa.pk.String(), ppa.balance.Load())
	if len(ppa.holdings) > 0 {
		fmt.Fprintf(&ow, "[")
		first := true
		for assetID, av := range ppa.holdings {
			if first {
				first = false
			} else {
				fmt.Fprintf(&ow, ", ")
			}
			fmt.Fprintf(&ow, "a%d=%d", assetID, av)
		}
		fmt.Fprintf(&ow, "]")
	}
	return ow.String()
}

type txidSendTime struct {
	txid string
	when time.Time
}

// WorkerState object holds a running pingpong worker
type WorkerState struct {
	cfg            PpConfig
	accounts       map[string]*pingPongAccount
	randomAccounts []string
	cinfo          CreatablesInfo

	nftStartTime       int64
	localNftIndex      uint64
	nftHolders         map[string]int
	incTransactionSalt uint64

	nextSendTime       time.Time
	scheduleActionTime time.Duration
	scheduleCalls      uint64
	scheduleSteps      uint64

	refreshAddrs []string
	refreshPos   int

	client *libgoal.Client

	// TotalLatencyOut stuff
	sentTxid      chan txidSendTime
	latencyBlocks chan bookkeeping.Block
	latencyOuts   []io.Writer // latencyOuts is a chain of *os.File, gzip, etc. Write to last element. .Close() last to first.
}

// returns the number of boxes per app
func (pps *WorkerState) getNumBoxes() uint32 {
	// only one of NumBoxUpdate and NumBoxRead should be nonzero. There isn't
	// currently support for mixed box workloads so these numbers should not be
	// added together.
	if pps.cfg.NumBoxUpdate > 0 {
		return pps.cfg.NumBoxUpdate
	}
	return pps.cfg.NumBoxRead
}

// PrepareAccounts to set up accounts and asset accounts required for Ping Pong run
func (pps *WorkerState) PrepareAccounts(ac *libgoal.Client) (err error) {
	pps.client = ac
	pps.nextSendTime = time.Now()
	durPerTxn := time.Second / time.Duration(pps.cfg.TxnPerSec)
	fmt.Printf("duration per txn %s\n", durPerTxn)

	err = pps.ensureAccounts(ac)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ensure accounts failed %v\n", err)
		return
	}

	// create new ephemeral random accounts
	pps.generateAccounts()

	err = pps.fundAccounts(ac)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
		return
	}

	if pps.cfg.NumAsset > 0 {
		err = pps.prepareAssets(ac)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare assets failed %v\n", err)
			return
		}
	}
	if pps.cfg.NumApp > 0 {
		err = pps.prepareApps(ac)
		if err != nil {
			return
		}
	}
	return
}

// determine the min balance per participant account
func computeAccountMinBalance(client *libgoal.Client, cfg PpConfig) (fundingRequiredBalance uint64, runningRequiredBalance uint64, err error) {
	proto, err := getProto(client)
	if err != nil {
		return
	}

	minActiveAccountBalance := proto.MinBalance

	var fee uint64
	if cfg.MaxFee != 0 {
		fee = cfg.MaxFee
	} else {
		// follow the same logic as constructTxn
		fee, err = client.SuggestedFee()
		if err != nil {
			return
		}
		fee *= uint64(cfg.GroupSize)
	}

	fundingRequiredBalance = minActiveAccountBalance
	runningRequiredBalance = minActiveAccountBalance

	// add cost of assets
	if cfg.NumAsset > 0 {
		assetCost := minActiveAccountBalance*uint64(cfg.NumAsset)*uint64(cfg.NumPartAccounts) + // assets*accounts
			(fee)*uint64(cfg.NumAsset) + // asset creations
			(fee)*uint64(cfg.NumAsset)*uint64(cfg.NumPartAccounts) + // asset opt-ins
			(fee)*uint64(cfg.NumAsset)*uint64(cfg.NumPartAccounts) // asset distributions
		fundingRequiredBalance += assetCost
		runningRequiredBalance += assetCost
	}
	if cfg.NumApp > 0 {
		maxAppsCreated := proto.MaxAppsCreated
		maxAppsOptedIn := proto.MaxAppsOptedIn
		// TODO : given that we've added unlimited app support, we should revise this
		// code so that we'll have control on how many app/account we want to create.
		// for now, I'm going to keep the previous max values until we have refactored this code.
		if maxAppsCreated == 0 {
			maxAppsCreated = config.Consensus[protocol.ConsensusV30].MaxAppsCreated
		}
		if maxAppsOptedIn == 0 {
			maxAppsOptedIn = config.Consensus[protocol.ConsensusV30].MaxAppsOptedIn
		}

		creationCost := uint64(cfg.NumApp) * proto.AppFlatParamsMinBalance * uint64(maxAppsCreated)
		optInCost := uint64(cfg.NumApp) * proto.AppFlatOptInMinBalance * uint64(maxAppsOptedIn)
		maxGlobalSchema := basics.StateSchema{NumUint: proto.MaxGlobalSchemaEntries, NumByteSlice: proto.MaxGlobalSchemaEntries}
		maxLocalSchema := basics.StateSchema{NumUint: proto.MaxLocalSchemaEntries, NumByteSlice: proto.MaxLocalSchemaEntries}
		schemaCost := uint64(cfg.NumApp) * (maxGlobalSchema.MinBalance(proto.BalanceRequirements()).Raw*uint64(maxAppsCreated) +
			maxLocalSchema.MinBalance(proto.BalanceRequirements()).Raw*uint64(maxAppsOptedIn))
		fundingRequiredBalance += creationCost + optInCost + schemaCost
		runningRequiredBalance += creationCost + optInCost + schemaCost
	}
	// add cost of transactions
	fundingRequiredBalance += (cfg.MaxAmt + fee) * 2 * cfg.TxnPerSec * uint64(math.Ceil(cfg.RefreshTime.Seconds()))

	// override computed value if less than configured value
	if cfg.MinAccountFunds > fundingRequiredBalance {
		fundingRequiredBalance = cfg.MinAccountFunds
	}

	return
}

func (pps *WorkerState) scheduleAction() bool {
	if pps.refreshPos >= len(pps.refreshAddrs) {
		if pps.refreshAddrs == nil {
			pps.refreshAddrs = make([]string, 0, len(pps.accounts))
		} else {
			pps.refreshAddrs = pps.refreshAddrs[:0]
		}
		for addr := range pps.accounts {
			pps.refreshAddrs = append(pps.refreshAddrs, addr)
		}
		pps.refreshPos = 0
	}
	if pps.cfg.NumApp > 0 || pps.cfg.NumAsset > 0 {
		addr := pps.refreshAddrs[pps.refreshPos]
		ai, err := pps.client.AccountInformation(addr, true)
		if err == nil {
			ppa := pps.accounts[addr]

			pps.integrateAccountInfo(addr, ppa, ai)
		} else {
			if !pps.cfg.Quiet {
				fmt.Printf("background refresh err: %v\n", err)
			}
			return false
		}
	}
	pps.refreshPos++
	return true
}

const durationEpsilon = time.Microsecond * 10
const scheduleActionTimeAlpha = 6

// schedule consuming n txn time slots
func (pps *WorkerState) schedule(n int) {
	pps.scheduleCalls++
	now := time.Now()
	ok := true
	timePerStep := time.Second / time.Duration(pps.cfg.TxnPerSec)
	nextSendTime := pps.nextSendTime
	if n > 1 {
		nextSendTime = nextSendTime.Add(timePerStep * time.Duration(n-1))
	}
	for {
		if now.After(nextSendTime) {
			break
		}
		dur := nextSendTime.Sub(now)
		if dur < durationEpsilon {
			break
		}
		if dur < pps.scheduleActionTime || !ok {
			time.Sleep(dur)
			now = time.Now()
		} else {
			ok = pps.scheduleAction()
			nn := time.Now()
			dt := nn.Sub(now)
			// alpha blend to keep running approximation
			pps.scheduleActionTime = ((pps.scheduleActionTime * scheduleActionTimeAlpha) + dt) / (scheduleActionTimeAlpha + 1)
			now = nn
		}
	}

	steps := 0
	for now.After(nextSendTime) {
		if steps > 0 {
			dt := now.Sub(nextSendTime)
			if dt < timePerStep/2 {
				// good enough
				break
			}
		}
		pps.scheduleSteps++
		nextSendTime = nextSendTime.Add(timePerStep)
		steps++
	}
	pps.nextSendTime = nextSendTime
	//fmt.Printf("schedule now=%s next=%s\n", now, pps.nextSendTime)
}

func (pps *WorkerState) recordTxidSent(txid string, err error) {
	if err != nil {
		return
	}
	if pps.sentTxid == nil {
		return
	}
	rec := txidSendTime{
		txid: txid,
		when: time.Now(),
	}
	select {
	case pps.sentTxid <- rec:
		// ok!
	default:
		// drop, oh well
	}
}

func (pps *WorkerState) fundAccounts(client *libgoal.Client) error {
	var srcFunds, minFund uint64
	var err error
	var tx transactions.Transaction
	srcFunds, err = client.GetBalance(pps.cfg.SrcAccount)

	if err != nil {
		return err
	}

	var totalSent uint64

	// Fee of 0 will make cause the function to use the suggested one by network
	fee := uint64(0)

	minFund, _, err = computeAccountMinBalance(client, pps.cfg)
	if err != nil {
		return err
	}
	fmt.Printf("adjusting account balance to %d\n", minFund)

	srcAcct := pps.accounts[pps.cfg.SrcAccount]

	accountsAdjusted := 1
	for accountsAdjusted > 0 {
		accountsAdjusted = 0
		adjStart := time.Now()
		for addr, acct := range pps.accounts {
			if addr == pps.cfg.SrcAccount {
				continue
			}
		repeat:
			if acct.getBalance() >= minFund {
				continue
			}
			if !pps.cfg.Quiet {
				fmt.Printf("adjusting balance of account %v\n", addr)
			}
			toSend := minFund - acct.getBalance()
			if srcFunds <= toSend {
				return fmt.Errorf("source account %s has insufficient funds %d - needs %d", pps.cfg.SrcAccount, srcFunds, toSend)
			}
			srcFunds -= toSend
			if !pps.cfg.Quiet {
				fmt.Printf("adjusting balance of account %v by %d\n ", addr, toSend)
			}

			pps.schedule(1)
			tx, err = pps.sendPaymentFromSourceAccount(client, addr, fee, toSend, srcAcct)
			if err != nil {
				if strings.Contains(err.Error(), "broadcast queue full") {
					fmt.Printf("failed to send payment, broadcast queue full. sleeping & retrying.\n")
					waitForNextRoundOrSleep(client, 500*time.Millisecond)
					goto repeat
				}
				return err
			}
			srcFunds -= tx.Fee.Raw
			accountsAdjusted++
			if !pps.cfg.Quiet {
				fmt.Printf("account balance for key %s will be %d\n", addr, minFund)
			}
			acct.setBalance(minFund)
			totalSent++
		}
		pps.accounts[pps.cfg.SrcAccount].setBalance(srcFunds)
		waitStart := time.Now()
		// wait until all the above transactions are sent, or that we have no more transactions
		// in our pending transaction pool coming from the source account.
		err = waitPendingTransactions([]string{pps.cfg.SrcAccount}, client)
		if err != nil {
			return err
		}
		waitStop := time.Now()
		if !pps.cfg.Quiet {
			fmt.Printf("%d sent (%s); waited %s\n", accountsAdjusted, waitStart.Sub(adjStart).String(), waitStop.Sub(waitStart).String())
		}
	}
	return err
}

func (pps *WorkerState) sendPaymentFromSourceAccount(client *libgoal.Client, to string, fee, amount uint64, srcAcct *pingPongAccount) (transactions.Transaction, error) {
	// generate a unique note to avoid duplicate transaction failures
	note := pps.makeNextUniqueNoteField()

	var txn transactions.Transaction
	var stxn transactions.SignedTxn
	var err error
	txn, err = client.ConstructPayment(srcAcct.pk.String(), to, fee, amount, note, "", [32]byte{}, 0, 0)

	if err != nil {
		return transactions.Transaction{}, err
	}

	stxn, err = signTxn(srcAcct, txn, pps.cfg)

	if err != nil {
		return transactions.Transaction{}, err
	}

	_, err = client.BroadcastTransaction(stxn)
	if err != nil {
		return transactions.Transaction{}, err
	}

	return txn, nil
}

// waitPendingTransactions waits until all the pending transactions coming from the given
// accounts map have been cleared out of the transaction pool. A prerequisite for this is that
// there is no other source who might be generating transactions that would come from these account
// addresses.
func waitPendingTransactions(accounts []string, client *libgoal.Client) error {
	for _, from := range accounts {
	repeat:
		pendingTxns, err := client.GetParsedPendingTransactionsByAddress(from, 0)
		if err != nil {
			fmt.Printf("failed to check pending transaction pool status : %v\n", err)
			return err
		}
		for _, txn := range pendingTxns.TopTransactions {
			if txn.Txn.Sender.String() != from {
				// we found a transaction where the receiver was the given account. We don't
				// care about these.
				continue
			}
			// the transaction is still in the transaction pool.
			// this would wait for the next round, when we will perform the check again.
			waitForNextRoundOrSleep(client, 500*time.Millisecond)
			goto repeat
		}
	}
	return nil
}

func (pps *WorkerState) refreshAccounts(client *libgoal.Client) error {
	addrs := make([]string, 0, len(pps.accounts))
	for addr := range pps.accounts {
		addrs = append(addrs, addr)
	}
	// wait until all the pending transactions have been sent; otherwise, getting the balance
	// is pretty much meaningless.
	fmt.Printf("waiting for all transactions to be accepted before refreshing accounts.\n")
	err := waitPendingTransactions(addrs, client)
	if err != nil {
		return err
	}

	balanceUpdates := make(map[string]uint64, len(addrs))
	for _, addr := range addrs {
		amount, err := client.GetBalance(addr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error refreshAccounts: %v\n", err)
			return err
		}
		balanceUpdates[addr] = amount
	}

	for addr, amount := range balanceUpdates {
		pps.accounts[addr].setBalance(amount)
	}

	return pps.fundAccounts(client)
}

// return a shuffled list of accounts with some minimum balance
func listSufficientAccounts(accounts map[string]*pingPongAccount, minimumAmount uint64, except string) []string {
	out := make([]string, 0, len(accounts))
	for key, value := range accounts {
		if key == except {
			continue
		}
		if value.getBalance() >= minimumAmount {
			out = append(out, key)
		}
	}
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

var logPeriod = 5 * time.Second

// RunPingPong starts ping pong process
func (pps *WorkerState) RunPingPong(ctx context.Context, ac *libgoal.Client) {
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

	if pps.cfg.TotalLatencyOut != "" {
		pps.startTxLatency(ctx, ac)
	}
	pps.nextSendTime = time.Now()
	ac.SetSuggestedParamsCacheAge(200 * time.Millisecond)
	pps.client = ac

	var runTime time.Duration
	if pps.cfg.RunTime > 0 {
		runTime = pps.cfg.RunTime
	} else {
		runTime = 10000 * time.Hour // Effectively 'forever'
	}
	var endTime time.Time
	if pps.cfg.MaxRuntime > 0 {
		endTime = time.Now().Add(pps.cfg.MaxRuntime)
	}
	refreshTime := time.Now().Add(pps.cfg.RefreshTime)

	lastLog := time.Now()
	nextLog := lastLog.Add(logPeriod)

	nextSendTime := time.Now()
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
				fmt.Printf("%d sent, %0.2f/s (%d total) (%d sc %d sts)\n", totalSent-lastTotalSent, float64(totalSent-lastTotalSent)/dt.Seconds(), totalSent, pps.scheduleCalls, pps.scheduleSteps)
				lastTotalSent = totalSent
				for now.After(nextLog) {
					nextLog = nextLog.Add(logPeriod)
				}
				lastLog = now
			}

			if pps.cfg.MaxRuntime > 0 && time.Now().After(endTime) {
				fmt.Printf("Terminating after max run time of %.f seconds\n", pps.cfg.MaxRuntime.Seconds())
				return
			}

			minimumAmount := pps.cfg.MinAccountFunds + (pps.cfg.MaxAmt+pps.cfg.MaxFee)*2
			fromList := listSufficientAccounts(pps.accounts, minimumAmount, pps.cfg.SrcAccount)
			// in group tests txns are sent back and forth, so both parties need funds
			var toList []string
			if pps.cfg.GroupSize == 1 {
				minimumAmount = 0
				toList = listSufficientAccounts(pps.accounts, minimumAmount, pps.cfg.SrcAccount)
			} else {
				// same selection with another shuffle
				toList = make([]string, len(fromList))
				copy(toList, fromList)
				rand.Shuffle(len(toList), func(i, j int) { toList[i], toList[j] = toList[j], toList[i] })
			}

			sent, succeeded, err := pps.sendFromTo(fromList, toList, ac, &nextSendTime)
			totalSent += sent
			totalSucceeded += succeeded
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "error sending transactions, sleeping .5 seconds: %v\n", err)
				pps.nextSendTime = time.Now().Add(500 * time.Millisecond)
				pps.schedule(1)
			}

			if pps.cfg.RefreshTime > 0 && time.Now().After(refreshTime) {
				err = pps.refreshAccounts(ac)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "error refreshing: %v\n", err)
				}

				refreshTime = refreshTime.Add(pps.cfg.RefreshTime)
			}
		}

		timeDelta := time.Since(startTime)
		_, _ = fmt.Fprintf(os.Stdout, "Sent %d transactions (%d attempted) in %d seconds\n", totalSucceeded, totalSent, int(math.Round(timeDelta.Seconds())))
	}
}

// NewPingpong creates a new pingpong WorkerState
func NewPingpong(cfg PpConfig) *WorkerState {
	return &WorkerState{
		cfg:            cfg,
		nftHolders:     make(map[string]int),
		randomAccounts: make([]string, 0, cfg.MaxRandomDst),
	}
}

func (pps *WorkerState) randAssetID() (aidx basics.AssetIndex) {
	if len(pps.cinfo.AssetParams) == 0 {
		return 0
	}
	rindex := rand.Intn(len(pps.cinfo.AssetParams))
	i := 0
	for k := range pps.cinfo.AssetParams {
		if i == rindex {
			return k
		}
		i++
	}
	return
}
func (pps *WorkerState) randAppID() (aidx basics.AppIndex) {
	if len(pps.cinfo.AppParams) == 0 {
		return 0
	}
	rindex := rand.Intn(len(pps.cinfo.AppParams))
	i := 0
	for k := range pps.cinfo.AppParams {
		if i == rindex {
			return k
		}
		i++
	}
	return
}

func (pps *WorkerState) fee() uint64 {
	fee := pps.cfg.MaxFee
	if pps.cfg.RandomizeFee {
		fee = rand.Uint64()%(pps.cfg.MaxFee-pps.cfg.MinFee) + pps.cfg.MinFee
	}
	return fee
}

func (pps *WorkerState) acct(from string) *pingPongAccount {
	return pps.accounts[from]
}

func (pps *WorkerState) sendFromTo(
	fromList, toList []string,
	client *libgoal.Client, nextSendTime *time.Time,
) (sentCount, successCount uint64, err error) {
	var minAccountRunningBalance uint64
	_, minAccountRunningBalance, err = computeAccountMinBalance(client, pps.cfg)
	if err != nil {
		return 0, 0, err
	}
	belowMinBalanceAccounts := make(map[string] /*basics.Address*/ bool)

	for i, from := range fromList {

		// keep going until the balances of at least 20% of the accounts is too low.
		if len(belowMinBalanceAccounts)*5 > len(fromList) {
			fmt.Printf("quitting sendFromTo: too many accounts below threshold")
			return
		}

		if belowMinBalanceAccounts[from] {
			continue
		}

		fee := pps.fee()

		to := toList[i]
		if len(belowMinBalanceAccounts) > 0 && (crypto.RandUint64()%100 < 50) {
			// make 50% of the calls attempt to refund low-balanced accounts.
			// ( if there is any )
			// pick the first low balance account
			for acct := range belowMinBalanceAccounts {
				to = acct
				break
			}
		} else if pps.cfg.RandomizeDst {
			// check if we need to create a new random account, or use an existing one
			if uint64(len(pps.randomAccounts)) >= pps.cfg.MaxRandomDst {
				// use pre-created random account
				i := rand.Int63n(int64(len(pps.randomAccounts)))
				to = pps.randomAccounts[i]
			} else {
				// create new random account
				var addr basics.Address
				crypto.RandBytes(addr[:])
				to = addr.String()
				// push new account
				pps.randomAccounts = append(pps.randomAccounts, to)
			}
		}

		// Broadcast transaction
		var sendErr error

		var fromAcct *pingPongAccount
		var update txnUpdate
		var updates []txnUpdate
		if pps.cfg.GroupSize == 1 {
			var txn transactions.Transaction
			var consErr error
			// Construct single txn
			txn, from, update, consErr = pps.constructTxn(from, to, fee, client)
			if consErr != nil {
				err = consErr
				_, _ = fmt.Fprintf(os.Stderr, "constructTxn failed: %v\n", err)
				return
			}

			// would we have enough money after taking into account the current updated fees ?
			fromAcct = pps.acct(from)
			if fromAcct == nil {
				err = fmt.Errorf("tx %v from %s -> no acct", txn, from)
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
				return
			}

			if fromAcct.getBalance() <= (txn.Fee.Raw + pps.cfg.MaxAmt + minAccountRunningBalance) {
				_, _ = fmt.Fprintf(os.Stdout, "Skipping sending %d: %s -> %s; Current cost too high(%d <= %d + %d  + %d).\n", pps.cfg.MaxAmt, from, to, fromAcct.getBalance(), txn.Fee.Raw, pps.cfg.MaxAmt, minAccountRunningBalance)
				belowMinBalanceAccounts[from] = true
				continue
			}

			// Sign txn
			stxn, signErr := signTxn(fromAcct, txn, pps.cfg)
			if signErr != nil {
				err = signErr
				_, _ = fmt.Fprintf(os.Stderr, "signTxn failed: %v\n", err)
				return
			}

			sentCount++
			pps.schedule(1)
			var txid string
			if pps.cfg.AsyncSending {
				sendErr = client.BroadcastTransactionAsync(stxn)
				if sendErr == nil {
					txid = stxn.Txn.ID().String()
				}
			} else {
				txid, sendErr = client.BroadcastTransaction(stxn)
			}
			pps.recordTxidSent(txid, sendErr)
		} else {
			// Generate txn group

			// In rekeying test there are two txns sent in a group
			// the first is  from -> to with RekeyTo=to
			// the second is from -> to with RekeyTo=from and AuthAddr=to
			// So that rekeying test only supports groups of two

			var txGroup []transactions.Transaction
			var txSigners []string
			for j := 0; j < int(pps.cfg.GroupSize); j++ {
				var txn transactions.Transaction
				var signer string
				if j%2 == 0 {
					txn, signer, update, err = pps.constructTxn(from, to, fee, client)
				} else if pps.cfg.GroupSize == 2 && pps.cfg.Rekey {
					txn, _, update, err = pps.constructTxn(from, to, fee, client)
					signer = to
				} else {
					txn, signer, update, err = pps.constructTxn(to, from, fee, client)
				}
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "group tx failed: %v\n", err)
					return
				}
				if pps.cfg.Rekey {
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
				updates = append(updates, update)
			}

			// Generate group ID
			gid, gidErr := client.GroupID(txGroup)
			if gidErr != nil {
				err = gidErr
				return
			}

			if !pps.cfg.Quiet {
				_, _ = fmt.Fprintf(os.Stdout, "Sending TxnGroup: ID %v, size %v \n", gid, len(txGroup))
			}

			// Sign each transaction
			stxGroup := make([]transactions.SignedTxn, len(txGroup))
			var signErr error
			for j, txn := range txGroup {
				txn.Group = gid
				signer := pps.acct(txSigners[j])
				stxGroup[j], signErr = signTxn(signer, txn, pps.cfg)
				if signErr != nil {
					err = signErr
					return
				}
			}

			sentCount += uint64(len(txGroup))
			pps.schedule(len(txGroup))
			sendErr = client.BroadcastTransactionGroup(stxGroup)
			txid := txGroup[0].ID().String()
			pps.recordTxidSent(txid, sendErr)
		}

		if sendErr != nil {
			err = sendErr
			return
		}

		// assume that if it was accepted by an algod, it got processed
		// (this is a bad assumption, we should be checking pending status or reading blocks to see if our txid were committed)
		if len(updates) > 0 {
			for _, ud := range updates {
				ud.apply(pps)
			}
		} else if update != nil {
			update.apply(pps)
		}

		successCount++
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
func (pps *WorkerState) makeNextUniqueNoteField() []byte {
	noteField := make([]byte, binary.MaxVarintLen64)
	usedBytes := binary.PutUvarint(noteField, pps.incTransactionSalt)
	pps.incTransactionSalt++
	return noteField[:usedBytes]
}

var errNotOptedIn = errors.New("not opted in")

func (pps *WorkerState) constructTxn(from, to string, fee uint64, client *libgoal.Client) (txn transactions.Transaction, sender string, update txnUpdate, err error) {
	var noteField []byte
	const pingpongTag = "pingpong"
	const tagLen = len(pingpongTag)
	// if random note flag set, then append a random number of additional bytes
	if pps.cfg.RandomNote {
		const maxNoteFieldLen = 1024
		noteLength := tagLen + int(rand.Uint32())%(maxNoteFieldLen-tagLen)
		noteField = make([]byte, noteLength)
		copy(noteField, pingpongTag)
		crypto.RandBytes(noteField[tagLen:])
	} else {
		noteField = pps.makeNextUniqueNoteField()
	}

	// if random lease flag set, fill the lease field with random bytes
	var lease [32]byte
	if pps.cfg.RandomLease {
		crypto.RandBytes(lease[:])
	}

	// weighted random selection of traffic type
	// TODO: construct*Txn() have the same signature, make this data structures and loop over them?
	totalWeight := pps.cfg.WeightPayment + pps.cfg.WeightAsset + pps.cfg.WeightApp
	target := rand.Float64() * totalWeight
	if target < pps.cfg.WeightAsset && pps.cfg.NumAsset > 0 {
		txn, sender, update, err = pps.constructAssetTxn(fee, client, noteField, lease)
		if err != errNotOptedIn {
			goto weightdone
		}
	}
	target -= pps.cfg.WeightAsset
	if target < pps.cfg.WeightApp && pps.cfg.NumApp > 0 {
		txn, sender, update, err = pps.constructAppTxn(from, fee, client, noteField, lease)
		if err != errNotOptedIn {
			goto weightdone
		}
	}
	target -= pps.cfg.WeightApp
	if target < pps.cfg.WeightNFTCreation && pps.cfg.NftAsaPerSecond > 0 {
		txn, sender, update, err = pps.constructNFTGenTxn(from, to, fee, client, noteField, lease)
		if err != errNotOptedIn {
			goto weightdone
		}
	}
	// TODO: other traffic types here
	// fallback on payment
	txn, sender, update, err = pps.constructPaymentTxn(from, to, fee, client, noteField, lease)
weightdone:

	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "error constructing transaction %v\n", err)
		return
	}
	// adjust transaction duration for 5 rounds. That would prevent it from getting stuck in the transaction pool for too long.
	txn.LastValid = txn.FirstValid + 5

	// if pps.cfg.MaxFee == 0, automatically adjust the fee amount to required min fee
	if pps.cfg.MaxFee == 0 {
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

type txnUpdate interface {
	apply(pps *WorkerState)
}

func (pps *WorkerState) constructPaymentTxn(from, to string, fee uint64, client *libgoal.Client, noteField []byte, lease [32]byte) (txn transactions.Transaction, sender string, update txnUpdate, err error) {
	amt := pps.cfg.MaxAmt
	if pps.cfg.RandomizeAmt {
		amt = uint64(rand.Int63n(int64(pps.cfg.MaxAmt-1))) + 1
	}
	txn, err = client.ConstructPayment(from, to, fee, amt, noteField, "", lease, 0, 0)
	if !pps.cfg.Quiet {
		_, _ = fmt.Fprintf(os.Stdout, "Sending %d : %s -> %s\n", amt, from, to)
	}
	update = &paymentUpdate{
		from: from,
		to:   to,
		amt:  amt,
		fee:  fee,
	}
	return txn, from, update, err
}

type paymentUpdate struct {
	from string
	to   string
	amt  uint64
	fee  uint64
}

func (au *paymentUpdate) apply(pps *WorkerState) {
	pps.accounts[au.from].balance.Add(-(au.fee + au.amt))
	// update account balance
	to := pps.accounts[au.to]
	if to != nil {
		to.balance.Add(au.amt)
	}
}

// return true with probability 1/i
func pReplace(i int) bool {
	if i <= 1 {
		return true
	}
	return rand.Intn(i) == 0
}

func (pps *WorkerState) constructAssetTxn(fee uint64, client *libgoal.Client, noteField []byte, lease [32]byte) (txn transactions.Transaction, sender string, update txnUpdate, err error) {
	// select a pair of random opted-in accounts by aidx
	// use them as from/to addresses
	amt := uint64(1)
	aidx := pps.randAssetID()
	if aidx == 0 {
		err = fmt.Errorf("no known assets")
		return
	}
	if len(pps.cinfo.OptIns[aidx]) == 0 {
		panic("This probably never happens.  If it does, investigate this.")

		/*
			   This code was here, but it makes no sense.  After selecting an
			   _asset_ id, it performs an _app_ opt-in.  Best guess is that this
			   never runs - enough accounts are opted in during setup that the len=0
			   condition above never occurs.  The code used to compile because we
			   conflated asset and app id as `uint64`.

				// Opt-in another
				// TODO: continue opt-in up to some amount? gradually?
				txn, err = pps.appOptIn(from, aidx, client)
				if err != nil {
					return
				}
				update = &appOptInUpdate{
					addr: from,
					aidx: aidx,
				}
				return txn, from, update, nil
		*/
	}

	optInsForAsset := pps.cinfo.OptIns[aidx]

	var richest *pingPongAccount
	var richestv uint64
	var fromAcct *pingPongAccount
	var toAcct *pingPongAccount
	for i, addr := range optInsForAsset {
		acct := pps.accounts[addr]
		if acct.holdings[aidx] > richestv {
			richestv = acct.holdings[aidx]
			richest = acct
			continue
		}
		if (acct.holdings[aidx] > 1000) && (fromAcct == nil || pReplace(i)) {
			fromAcct = acct
			continue
		}
		if toAcct == nil || pReplace(i) {
			toAcct = acct
			continue
		}
	}
	if richest == nil {
		err = fmt.Errorf("don't know any account holding asset %d", aidx)
		return
	}
	if fromAcct == nil {
		fromAcct = richest
	}
	if toAcct == nil {
		toAcct = fromAcct
	}

	to := toAcct.pk.String()
	from := fromAcct.pk.String()
	sender = from
	if to != from {
		if toAcct.holdings[aidx] < 1000 && fromAcct.holdings[aidx] > 11000 {
			amt = 10000
		}
	}
	txn, err = client.MakeUnsignedAssetSendTx(aidx, amt, to, "", "")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "error making unsigned asset send tx %v\n", err)
		return
	}
	txn.Note = noteField[:]
	txn.Lease = lease
	txn, err = client.FillUnsignedTxTemplate(sender, 0, 0, fee, txn)
	if !pps.cfg.Quiet {
		_, _ = fmt.Fprintf(os.Stdout, "Sending %d asset %d: %s -> %s\n", amt, aidx, sender, to)
	}
	update = &assetUpdate{
		from: from,
		to:   to,
		aidx: aidx,
		amt:  amt,
		fee:  fee,
	}
	return txn, sender, update, err
}

/* This was part of the mystery in constructAppTxn, which was conflating app and
   asset IDs. Commenting out because it does not compile now that we more
   strongly segregate app/asset indexes.

type appOptInUpdate struct {
	addr string
	aidx basics.AppIndex
}

func (au *appOptInUpdate) apply(pps *WorkerState) {
	pps.accounts[au.addr].holdings[au.aidx] = 0
	pps.cinfo.OptIns[au.aidx] = uniqueAppend(pps.cinfo.OptIns[au.aidx], au.addr)
}
*/

type nopUpdate struct {
}

func (au *nopUpdate) apply(pps *WorkerState) {
}

var nopUpdateSingleton = &nopUpdate{}

type assetUpdate struct {
	from string
	to   string
	aidx basics.AssetIndex
	amt  uint64
	fee  uint64
}

func (au *assetUpdate) apply(pps *WorkerState) {
	pps.accounts[au.from].balance.Add(-au.fee)
	pps.accounts[au.from].holdings[au.aidx] -= au.amt
	to := pps.accounts[au.to]
	if to.holdings == nil {
		to.holdings = make(map[basics.AssetIndex]uint64)
	}
	to.holdings[au.aidx] += au.amt
}

func (pps *WorkerState) constructAppTxn(from string, fee uint64, client *libgoal.Client, noteField []byte, lease [32]byte) (txn transactions.Transaction, sender string, update txnUpdate, err error) {
	// select opted-in accounts for Txn.Accounts field
	var accounts []string
	aidx := pps.randAppID()
	if aidx == 0 {
		err = fmt.Errorf("no known apps")
		return
	}

	// construct box ref array
	var boxRefs []basics.BoxRef
	for i := range pps.getNumBoxes() {
		boxRefs = append(boxRefs, basics.BoxRef{App: 0, Name: fmt.Sprintf("%d", i)})
	}

	appOptIns := pps.cinfo.OptIns[aidx]
	sender = from
	if len(appOptIns) > 0 {
		indices := rand.Perm(len(appOptIns))
		limit := min(len(indices), 5)
		for i := 0; i < limit; i++ {
			idx := indices[i]
			accounts = append(accounts, appOptIns[idx])
		}
		// change `from` to an account that's opted-in. creator also allowed.
		if pps.cinfo.AppParams[aidx].Creator != from &&
			!slices.Contains(appOptIns, from) {
			from = accounts[0]
			sender = from
		}
		accounts = accounts[1:]
	}
	addresses := make([]basics.Address, 0, len(accounts))
	for _, acct := range accounts {
		var addr basics.Address
		addr, err = basics.UnmarshalChecksumAddress(acct)
		if err != nil {
			return
		}
		addresses = append(addresses, addr)
	}
	refs := libgoal.RefBundle{
		Accounts: addresses,
		Boxes:    boxRefs,
	}
	txn, err = client.MakeUnsignedAppNoOpTx(aidx, nil, refs, 0)
	if err != nil {
		return
	}
	txn.Note = noteField[:]
	txn.Lease = lease
	txn, err = client.FillUnsignedTxTemplate(from, 0, 0, fee, txn)
	if !pps.cfg.Quiet {
		_, _ = fmt.Fprintf(os.Stdout, "Calling app %d : %s\n", aidx, from)
	}
	update = &appUpdate{
		from: from,
		fee:  fee,
	}
	return txn, sender, update, err
}

type appUpdate struct {
	from string
	fee  uint64
}

func (au *appUpdate) apply(pps *WorkerState) {
	pps.accounts[au.from].balance.Add(-au.fee)
}

func (pps *WorkerState) constructNFTGenTxn(from, to string, fee uint64, client *libgoal.Client, noteField []byte, lease [32]byte) (txn transactions.Transaction, sender string, update txnUpdate, err error) {
	if (len(pps.nftHolders) == 0) || ((float64(int(pps.cfg.NftAsaAccountInFlight)-len(pps.nftHolders)) / float64(pps.cfg.NftAsaAccountInFlight)) >= rand.Float64()) {
		var addr string

		var seed [32]byte
		crypto.RandBytes(seed[:])
		privateKey := crypto.GenerateSignatureSecrets(seed)
		publicKey := basics.Address(privateKey.SignatureVerifier)

		pps.accounts[publicKey.String()] = &pingPongAccount{
			sk: privateKey,
			pk: publicKey,
		}
		addr = publicKey.String()

		fmt.Printf("new NFT holder %s\n", addr)
		var proto config.ConsensusParams
		proto, err = getProto(client)
		if err != nil {
			return
		}
		// enough for the per-asa minbalance and more than enough for the txns to create them
		amount := proto.MinBalance * uint64(pps.cfg.NftAsaPerAccount+1) * 2
		pps.nftHolders[addr] = 0
		srcAcct := pps.acct(pps.cfg.SrcAccount)
		sender = srcAcct.pk.String()
		txn, err = client.ConstructPayment(sender, to, fee, amount, noteField, "", [32]byte{}, 0, 0)
		update = &paymentUpdate{
			from: from,
			to:   to,
			fee:  fee,
			amt:  amount,
		}
		return txn, sender, update, err
	}
	// pick a random sender from nft holder sub accounts
	pick := rand.Intn(len(pps.nftHolders))
	pos := 0
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
	txn, err = client.MakeUnsignedAssetCreateTx(totalSupply, false, sender, sender, sender, sender, "ping", assetName, "", meta[:], 0)
	if err != nil {
		fmt.Printf("Cannot make asset create txn with meta %v\n", meta)
		return
	}
	txn, err = client.FillUnsignedTxTemplate(sender, 0, 0, fee, txn)
	if err != nil {
		fmt.Printf("Cannot fill asset creation txn\n")
		return
	}
	if senderNftCount+1 >= int(pps.cfg.NftAsaPerAccount) {
		delete(pps.nftHolders, sender)
	} else {
		pps.nftHolders[sender] = senderNftCount + 1
	}
	update = &nftgenUpdate{
		from: from,
		fee:  fee,
	}
	return txn, sender, update, err
}

type nftgenUpdate struct {
	from string
	fee  uint64
}

func (au *nftgenUpdate) apply(pps *WorkerState) {
	pps.accounts[au.from].balance.Add(-au.fee)
}

func signTxn(signer *pingPongAccount, txn transactions.Transaction, cfg PpConfig) (stxn transactions.SignedTxn, err error) {

	var psig crypto.Signature

	if cfg.Rekey {
		stxn, err = txn.Sign(signer.sk), nil

	} else if len(cfg.Program) > 0 && rand.Float64() < cfg.ProgramProbability {
		// If there's a program, sign it and use that in a lsig
		progb := logic.Program(cfg.Program)
		psig = signer.sk.Sign(&progb)

		// Fill in signed transaction
		stxn.Txn = txn
		stxn.Lsig.Logic = cfg.Program
		stxn.Lsig.Sig = psig
		stxn.Lsig.Args = cfg.LogicArgs
	} else {

		// Otherwise, just sign the transaction like normal
		stxn, err = txn.Sign(signer.sk), nil
	}
	return
}

func (pps *WorkerState) startTxLatency(ctx context.Context, ac *libgoal.Client) {
	fout, err := os.Create(pps.cfg.TotalLatencyOut)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v", pps.cfg.TotalLatencyOut, err)
		return
	}
	pps.latencyOuts = append(pps.latencyOuts, fout)
	if strings.HasSuffix(pps.cfg.TotalLatencyOut, ".gz") {
		gzout := gzip.NewWriter(fout)
		pps.latencyOuts = append(pps.latencyOuts, gzout)
	} else {
		bw := bufio.NewWriter(fout)
		pps.latencyOuts = append(pps.latencyOuts, bw)
	}
	pps.sentTxid = make(chan txidSendTime, 1000)
	pps.latencyBlocks = make(chan bookkeeping.Block, 1)
	go pps.txidLatency(ctx)
	go pps.txidLatencyBlockWaiter(ctx, ac)
}

type txidSendTimeIndexed struct {
	txidSendTime
	index int
}

const txidLatencySampleSize = 10000

// thread which handles measuring total send-to-commit latency
func (pps *WorkerState) txidLatency(ctx context.Context) {
	byTxid := make(map[string]txidSendTimeIndexed, txidLatencySampleSize)
	txidList := make([]string, 0, txidLatencySampleSize)
	out := pps.latencyOuts[len(pps.latencyOuts)-1]
	for {
		select {
		case st := <-pps.sentTxid:
			if len(txidList) < txidLatencySampleSize {
				index := len(txidList)
				txidList = append(txidList, st.txid)
				byTxid[st.txid] = txidSendTimeIndexed{
					st,
					index,
				}
			} else {
				// random replacement
				evict := rand.Intn(len(txidList))
				delete(byTxid, txidList[evict])
				txidList[evict] = st.txid
				byTxid[st.txid] = txidSendTimeIndexed{
					st,
					evict,
				}
			}
		case bl := <-pps.latencyBlocks:
			now := time.Now()
			txns, err := bl.DecodePaysetFlat()
			if err != nil {
				fmt.Fprintf(os.Stderr, "block[%d] payset err %v", bl.Round(), err)
				return
			}
			for _, stxn := range txns {
				txid := stxn.ID().String()
				st, ok := byTxid[txid]
				if ok {
					dt := now.Sub(st.when)
					fmt.Fprintf(out, "%d\n", dt.Nanoseconds())
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

type flusher interface {
	Flush() error
}

func (pps *WorkerState) txidLatencyDone() {
	for i := len(pps.latencyOuts); i >= 0; i-- {
		xo := pps.latencyOuts[i]
		if fl, ok := xo.(flusher); ok {
			err := fl.Flush()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v", pps.cfg.TotalLatencyOut, err)
			}
		}
		if cl, ok := xo.(io.Closer); ok {
			err := cl.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v", pps.cfg.TotalLatencyOut, err)
			}
		}
	}
}

const errRestartTime = time.Second

func (pps *WorkerState) txidLatencyBlockWaiter(ctx context.Context, ac *libgoal.Client) {
	defer close(pps.latencyBlocks)
	done := ctx.Done()
	isDone := func(err error) bool {
		select {
		case <-done:
			return true
		default:
		}
		fmt.Fprintf(os.Stderr, "block waiter st : %v", err)
		time.Sleep(errRestartTime)
		return false
	}
restart:
	select {
	case <-done:
		return
	default:
	}
	st, err := ac.Status()
	if err != nil {
		if isDone(err) {
			return
		}
		goto restart
	}
	nextRound := st.LastRound
	for {
		select {
		case <-done:
			return
		default:
		}
		st, err = ac.WaitForRound(nextRound)
		if err != nil {
			if isDone(err) {
				return
			}
			goto restart
		}
		bb, err := ac.BookkeepingBlock(st.LastRound)
		if err != nil {
			if isDone(err) {
				return
			}
			goto restart
		}
		pps.latencyBlocks <- bb
		nextRound = st.LastRound
	}
}
