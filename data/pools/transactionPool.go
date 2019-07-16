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

package pools

import (
	"errors"
	"fmt"
	"sort"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

// Ledger allows retrieving the amount of spendable MicroAlgos
// and also checking if a transaction has already been committed.
type Ledger interface {
	Lookup(basics.Round, basics.Address) (basics.AccountData, error)
	Committed(transactions.SignedTxn) (bool, error)
	ConsensusParams(basics.Round) (config.ConsensusParams, error)
	BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error)
	Latest() basics.Round
}

// TransactionPool is a struct maintaining a sanitized pool of transactions that are available for inclusion in
// a Block.  We sanitize it by preventing duplicates and limiting the number of transactions retained for each account
type TransactionPool struct {
	mu                              deadlock.RWMutex
	txPriorityQueue                 *txPriorityQueue
	pendingTxns                     map[transactions.Txid]transactions.SignedTxn // note: digests do not include signatures to reduce spam
	expiredTxCount                  map[basics.Round]int
	exponentialPriorityGrowthFactor uint64
	algosPendingSpend               accountsToPendingTransactions
	ledger                          Ledger
	statusCache                     *statusCache
	logStats                        bool
	size                            int
}

// MakeTransactionPool is the constructor, it uses Ledger to ensure that no account has pending transactions that together overspend.
// The pool can contain up to transactionPoolSize transactions.
// When the transaction pool is full, the priority of a new transaction must be at least exponentialPriorityGrowthFactor
// times greater than the minimum-priority of a transaction already in the pool (otherwise the new transaction is discarded).
//
// The pool also contains status information for the last transactionPoolSize
// transactions that were removed from the pool without being committed.
func MakeTransactionPool(ledger Ledger, exponentialPriorityGrowthFactor uint64, transactionPoolSize int, logStats bool) *TransactionPool {
	pool := TransactionPool{
		txPriorityQueue:                 makeTxPriorityQueue(transactionPoolSize),
		pendingTxns:                     make(map[transactions.Txid]transactions.SignedTxn),
		expiredTxCount:                  make(map[basics.Round]int),
		exponentialPriorityGrowthFactor: exponentialPriorityGrowthFactor,
		algosPendingSpend:               make(map[basics.Address]pendingTransactions),
		ledger:                          ledger,
		statusCache:                     makeStatusCache(transactionPoolSize),
		logStats:                        logStats,
		size:                            transactionPoolSize,
	}
	return &pool
}

// TODO I moved this number to be a constant in the module, we should consider putting it in the local config
const expiredHistory = 10

// NumExpired returns the number of transactions that expired at the end of a round (only meaningful if cleanup has
// been called for that round)
func (pool *TransactionPool) NumExpired(round basics.Round) int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.expiredTxCount[round]
}

// PendingTxIDs return the IDs of all pending transactions (in no particular order)
func (pool *TransactionPool) PendingTxIDs() []transactions.Txid {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	ids := make([]transactions.Txid, len(pool.pendingTxns))
	i := 0
	for id := range pool.pendingTxns {
		ids[i] = id
		i++
	}
	return ids
}

// Pending returns an array of transactions valid for the given round, sorted by priority in decreasing order
// If no txns, returns empty slice.
func (pool *TransactionPool) Pending() []transactions.SignedTxn {
	pool.mu.Lock()

	txns := make([]transactions.SignedTxn, len(pool.pendingTxns))
	sorti := make([]int, len(pool.pendingTxns))
	i := 0
	for _, txn := range pool.pendingTxns {
		txns[i] = txn
		sorti[i] = i
		i++
	}

	pool.mu.Unlock()

	// TODO: return unsorted pending, let calling code sort or not as needed, or make a heap, or whatever
	sort.SliceStable(sorti, func(i, j int) bool {
		return txns[sorti[j]].PtrPriority().LessThan(txns[sorti[i]].PtrPriority())
	})
	out := make([]transactions.SignedTxn, len(pool.pendingTxns))
	for i, p := range sorti {
		out[i] = txns[p]
	}
	return out
}

// PendingUnsorted returns an array of transactions valid for the given round.
// If no txns, returns empty slice.
func (pool *TransactionPool) PendingUnsorted() []transactions.SignedTxn {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	txns := make([]transactions.SignedTxn, len(pool.pendingTxns))
	i := 0
	for _, txn := range pool.pendingTxns {
		txns[i] = txn
		i++
	}
	return txns
}

// PendingCount returns the number of transactions currently pending in the pool.
func (pool *TransactionPool) PendingCount() int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return len(pool.pendingTxns)
}

// Test checks whether a transaction could be remembered in the pool, but does not actually store this transaction
// in the pool
func (pool *TransactionPool) Test(t transactions.SignedTxn) error {
	t.InitCaches()

	pool.mu.RLock()
	defer pool.mu.RUnlock()

	_, _, _, err := pool.test(t)
	return err
}

func (pool *TransactionPool) test(t transactions.SignedTxn) (accountDeductions, bool, transactions.Txid, error) {
	// check if we already have this transaction in the pool.
	if _, has := pool.pendingTxns[t.ID()]; has {
		return accountDeductions{}, false, transactions.Txid{}, errors.New("TransactionPool.test: transaction already in the pool")
	}

	var minTransactionID transactions.Txid
	isFull := len(pool.pendingTxns) >= pool.size

	if isFull {
		// transaction pool is full.
		var minPriority transactions.TxnPriority
		minTransactionID, minPriority = pool.txPriorityQueue.getMin()

		if t.Priority().LessThan(minPriority.Mul(pool.exponentialPriorityGrowthFactor)) {
			return accountDeductions{}, isFull, transactions.Txid{}, fmt.Errorf("TransactionPool.test: transaction pool is full and tx priority too low: min in pool %v vs. %v", minPriority, t.Priority())
		}
	}

	// check if we have committed the transaction recently already
	committed, err := pool.ledger.Committed(t)
	if err != nil {
		return accountDeductions{}, isFull, transactions.Txid{}, fmt.Errorf("TransactionPool.test: failed to call Committed(): %v", err)
	}
	if committed {
		return accountDeductions{}, isFull, transactions.Txid{}, fmt.Errorf("TransactionPool.test: transaction with ID %v has already been committed", t.ID())
	}

	// compute the deductions following this transaction
	deductions, err := pool.computeDeductions(t)
	if err != nil {
		return accountDeductions{}, isFull, transactions.Txid{}, err
	}

	return deductions, isFull, minTransactionID, nil
}

// Remember stores the provided transaction
// Precondition: Only Remember() properly-signed and well-formed transactions (i.e., ensure t.WellFormed())
func (pool *TransactionPool) Remember(t transactions.SignedTxn) error {
	t.InitCaches()

	pool.mu.Lock()
	defer pool.mu.Unlock()

	deductions, isFull, minTransactionID, err := pool.test(t)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember: %v", err)
	}

	if isFull {
		// remove old transaction. we want to do that before adding the new entry to ensure we
		// won't exceed (temporarly) the total number of pending transactions.
		pool.remove(minTransactionID, fmt.Errorf("transaction evicted due to low priority"))
	}

	// push to the priority queue
	if !pool.txPriorityQueue.Push(t) {
		// this should never happen, since we already tested that above.
		logging.Base().Errorf("TransactionPool.Remember: Attempted to push a transaction %v into the priority queue while it's already there", t)
		return fmt.Errorf("TransactionPool.Remember: cannot push txn %v as it's already in the pool", t)
	}

	// we're almost done; the transaction was already saved into the priority queue. now, save the transaction
	// into the pending transactions list.
	pool.pendingTxns[t.ID()] = t
	// last, update the spent algos from the sender account
	pool.algosPendingSpend.accountForTransactionDeductions(t.Txn, deductions)

	return nil
}

func (pool *TransactionPool) computeDeductions(t transactions.SignedTxn) (accountDeductions, error) {
	// compute how this transaction would affect the number of MicroAlgos pending spend by the sender
	algosPendingSpend, err := pool.algosPendingSpend.deductionsWithTransaction(t.Txn)

	// make sure that the sender has the balance to cover all their pending transactions
	if err != nil {
		return algosPendingSpend, fmt.Errorf("TransactionPool.Remember: failed to compute balance - %v", err)
	}
	lastRound := pool.ledger.Latest()
	record, err := pool.ledger.Lookup(lastRound, t.Txn.Src())
	if err != nil {
		return algosPendingSpend, err
	}

	remainder, overflow := basics.OSubA(record.MicroAlgos, algosPendingSpend.amount)
	if overflow {
		return algosPendingSpend, fmt.Errorf("TransactionPool.Remember: Insufficient funds - The total pending transactions from the address require %d microAlgos but the account only has %d microAlgos", algosPendingSpend.amount.Raw, record.MicroAlgos.Raw)
	}

	// get the min balance
	consensusParams, err := pool.ledger.ConsensusParams(lastRound)
	if err != nil {
		return algosPendingSpend, err
	}

	hdr, err := pool.ledger.BlockHdr(lastRound)
	if err != nil {
		return algosPendingSpend, err
	}

	// check that sender's account does not go below min balance
	if t.Txn.CloseRemainderTo == (basics.Address{}) {
		// if the account is not closed, then remainder should be above min
		if t.Txn.Sender != hdr.FeeSink && t.Txn.Sender != hdr.RewardsPool {
			if remainder.LessThan(basics.MicroAlgos{Raw: consensusParams.MinBalance}) {
				return algosPendingSpend, fmt.Errorf("TransactionPool.Remember: Insufficient funds - sender's account will have only %v microAlgos left out of %d required", remainder, consensusParams.MinBalance)
			}
		}
	} else if t.Txn.CloseRemainderTo != hdr.FeeSink && t.Txn.CloseRemainderTo != hdr.RewardsPool {
		// account is being closed, make sure that the account getting the remainder does not go below min balance
		closeRemainderBalance, err := pool.ledger.Lookup(lastRound, t.Txn.CloseRemainderTo)
		// some error accessing the account balance.
		if err != nil {
			return algosPendingSpend, err
		}

		// if the account does not already exist, make sure it does not go below min
		if closeRemainderBalance.MicroAlgos.IsZero() {
			if remainder.LessThan(basics.MicroAlgos{Raw: consensusParams.MinBalance}) {
				return algosPendingSpend, fmt.Errorf("TransactionPool.Remember: Insufficient funds - The transaction's remainder %v is lower than the minimum required, %d, for an account", remainder, consensusParams.MinBalance)
			}
		}
	}

	// check that recipient's account does not go below min balance
	if t.Txn.Receiver != (basics.Address{}) && t.Txn.Receiver != hdr.FeeSink && t.Txn.Receiver != hdr.RewardsPool {
		receiverBalance, err := pool.ledger.Lookup(lastRound, t.Txn.Receiver)
		// some error accessing the account balance.
		if err != nil {
			return algosPendingSpend, err
		}

		// if the account does not already exist, make sure it does not go below min
		if receiverBalance.MicroAlgos.IsZero() {
			if t.Txn.Amount.LessThan(basics.MicroAlgos{Raw: consensusParams.MinBalance}) {
				return algosPendingSpend, fmt.Errorf("TransactionPool.Remember: Insufficient funds - receiver's account will have only %v microAlgos out of %d required", t.Txn.Amount, consensusParams.MinBalance)
			}
		}
	}
	return algosPendingSpend, nil
}

// Lookup returns the error associated with a transaction that used
// to be in the pool.  If no status information is available (e.g., because
// it was too long ago, or the transaction committed successfully), then
// found is false.  If the transaction is still in the pool, txErr is empty.
func (pool *TransactionPool) Lookup(txid transactions.Txid) (tx transactions.SignedTxn, txErr string, found bool) {
	if pool == nil {
		return transactions.SignedTxn{}, "", false
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	tx, inPool := pool.pendingTxns[txid]
	if inPool {
		return tx, "", true
	}

	return pool.statusCache.check(txid)
}

// Verified returns whether a given SignedTxn is already in the
// pool, and, since only verified transactions should be added
// to the pool, whether that transaction is verified (i.e., Verify
// returned success).  This is used as an optimization to avoid
// re-checking signatures on transactions that we have already
// verified.
func (pool *TransactionPool) Verified(txn transactions.SignedTxn) bool {
	if pool == nil {
		return false
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	pendingSigTxn, ok := pool.pendingTxns[txn.ID()]
	if !ok {
		return false
	}

	return pendingSigTxn.Sig == txn.Sig && pendingSigTxn.Msig.Equal(txn.Msig)
}

// OnNewBlock excises transactions from the pool that are included in the specified Block or if they've expired
func (pool *TransactionPool) OnNewBlock(block bookkeeping.Block) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	var stats telemetryspec.ProcessBlockMetrics

	remove := make(map[transactions.Txid]error, 0)

	// collect transactions that appear in the last block
	payset, err := block.DecodePayset()
	if err != nil {
		return
	}

	for _, tx := range payset {
		txid := tx.ID()
		_, ok := pool.pendingTxns[txid]
		if ok {
			remove[txid] = nil
			stats.KnownCommittedCount++
		} else {
			stats.UnknownCommittedCount++
		}
	}

	// collect expired transactions
	expired := 0
	for txid, tx := range pool.pendingTxns {
		err := tx.Txn.Alive(block)
		if err != nil {
			remove[txid] = err
			expired++
			stats.ExpiredCount++
		}
	}

	// remove all collected transactions
	for txid, txErr := range remove {
		pool.remove(txid, txErr)
	}

	// remove transactions from senders in this block until everyone can spend what they have given the last block
	for _, tx := range payset {
		account := tx.Txn.Src()
		pendingSpend := pool.algosPendingSpend[account]
		record, err := pool.ledger.Lookup(pool.ledger.Latest(), account)
		if err != nil {
			logging.Base().Errorf("TransactionPool.OnNewBlock: Cannot get balance for %v: %v", account, err)
			break
		}
		spendable := record.MicroAlgos

		if spendable.LessThan(pendingSpend.deductions.amount) {
			txids := make([]transactions.Txid, 0)
			for txid := range pendingSpend.txids {
				txids = append(txids, txid)
			}

			// sort in increasing order of priority
			sort.SliceStable(txids, func(i, j int) bool {
				return pool.pendingTxns[txids[i]].Priority().LessThan(pool.pendingTxns[txids[j]].Priority())
			})

			// remove transactions, beginning with the lowest priority one until the sender can spend all their pending transactions
			for _, txid := range txids {
				if pool.algosPendingSpend[account].deductions.amount.GreaterThan(spendable) {
					pool.remove(txid, fmt.Errorf("pending spend %d exceeds spendable %d",
						pool.algosPendingSpend[account].deductions.amount.Raw, spendable.Raw))
					stats.RemovedInvalidCount++
				} else {
					break
				}
			}
		}
	}

	// save exipred history and clean old statistics about expired transactions
	proto := config.Consensus[block.CurrentProtocol]
	pool.expiredTxCount[block.Round()] = expired
	delete(pool.expiredTxCount, block.Round()-expiredHistory*basics.Round(proto.MaxTxnLife))

	if pool.logStats {
		var details struct {
			Round uint64
		}
		details.Round = uint64(block.Round())
		logging.Base().Metrics(telemetryspec.Transaction, stats, details)
	}
}

// Remove removes a transaction from the pool, and remembers its error
// status (txErr), if not nil.
func (pool *TransactionPool) Remove(txid transactions.Txid, txErr error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.remove(txid, txErr)
}

func (pool *TransactionPool) remove(txid transactions.Txid, txErr error) {
	tx, has := pool.pendingTxns[txid]
	if !has {
		return
	}
	if err := pool.algosPendingSpend.remove(tx.Txn); err != nil {
		logging.Base().Errorf("TransactionPool::remove: %v", err)
	}
	pool.txPriorityQueue.Remove(txid)
	delete(pool.pendingTxns, txid)

	// If the transaction was removed due to an error (instead of being
	// committed to the ledger), remember the error in the statusCache.
	if txErr != nil {
		pool.statusCache.put(tx, txErr.Error())
	}
}
