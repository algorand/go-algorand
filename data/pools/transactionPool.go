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
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

// TransactionPool is a struct maintaining a sanitized pool of transactions that are available for inclusion in
// a Block.  We sanitize it by preventing duplicates and limiting the number of transactions retained for each account
type TransactionPool struct {
	mu                              deadlock.RWMutex
	txPriorityQueue                 *txPriorityQueue
	pendingTxns                     map[transactions.Txid]transactions.SignedTxn // note: digests do not include signatures to reduce spam
	expiredTxCount                  map[basics.Round]int
	exponentialPriorityGrowthFactor uint64
	pendingBlockEvaluator           *ledger.BlockEvaluator
	pendingBlockEvaluatorRound	basics.Round
	ledger                          *ledger.Ledger
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
func MakeTransactionPool(ledger *ledger.Ledger, exponentialPriorityGrowthFactor uint64, transactionPoolSize int, logStats bool) *TransactionPool {
	pool := TransactionPool{
		txPriorityQueue:                 makeTxPriorityQueue(transactionPoolSize),
		pendingTxns:                     make(map[transactions.Txid]transactions.SignedTxn),
		expiredTxCount:                  make(map[basics.Round]int),
		exponentialPriorityGrowthFactor: exponentialPriorityGrowthFactor,
		ledger:                          ledger,
		statusCache:                     makeStatusCache(transactionPoolSize),
		logStats:                        logStats,
		size:                            transactionPoolSize,
	}
	pool.recomputeBlockEvaluator()
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

	_, _, err := pool.test(t)
	return err
}

func (pool *TransactionPool) test(t transactions.SignedTxn) (bool, transactions.Txid, error) {
	// check if we already have this transaction in the pool.
	if _, has := pool.pendingTxns[t.ID()]; has {
		return false, transactions.Txid{}, errors.New("TransactionPool.test: transaction already in the pool")
	}

	var minTransactionID transactions.Txid
	isFull := len(pool.pendingTxns) >= pool.size

	if isFull {
		// transaction pool is full.
		var minPriority transactions.TxnPriority
		minTransactionID, minPriority = pool.txPriorityQueue.getMin()

		if t.Priority().LessThan(minPriority.Mul(pool.exponentialPriorityGrowthFactor)) {
			return isFull, transactions.Txid{}, fmt.Errorf("TransactionPool.test: transaction pool is full and tx priority too low: min in pool %v vs. %v", minPriority, t.Priority())
		}
	}

	return isFull, minTransactionID, nil
}

// Remember stores the provided transaction
// Precondition: Only Remember() properly-signed and well-formed transactions (i.e., ensure t.WellFormed())
func (pool *TransactionPool) Remember(t transactions.SignedTxn) error {
	t.InitCaches()

	pool.mu.Lock()
	defer pool.mu.Unlock()

	isFull, minTransactionID, err := pool.test(t)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember: %v", err)
	}

	if isFull {
		// remove old transaction. we want to do that before adding the new entry to ensure we
		// won't exceed (temporarly) the total number of pending transactions.
		pool.remove(minTransactionID, fmt.Errorf("transaction evicted due to low priority"))
	}

	if pool.pendingBlockEvaluator == nil {
		return fmt.Errorf("TransactionPool.Remember: no pending block evaluator")
	}

	err = pool.addToPendingBlockEvaluator(t)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember: %v", err)
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

	return nil
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
	var knownCommitted uint
	var unknownCommitted uint

	payset, err := block.DecodePayset()
	if err == nil {
		for _, tx := range payset {
			txid := tx.ID()
			_, ok := pool.pendingTxns[txid]
			if ok {
				knownCommitted++
			} else {
				unknownCommitted++
			}
		}
	}

	if pool.pendingBlockEvaluator == nil || block.Round() >= pool.pendingBlockEvaluator.Round() {
		stats = pool.recomputeBlockEvaluator()
	}

	stats.KnownCommittedCount = knownCommitted
	stats.UnknownCommittedCount = unknownCommitted

	proto := config.Consensus[block.CurrentProtocol]
	pool.expiredTxCount[block.Round()] = int(stats.ExpiredCount)
	delete(pool.expiredTxCount, block.Round()-expiredHistory*basics.Round(proto.MaxTxnLife))

	if pool.logStats {
		var details struct {
			Round uint64
		}
		details.Round = uint64(block.Round())
		logging.Base().Metrics(telemetryspec.Transaction, stats, details)
	}
}

// alwaysVerifiedPool implements ledger.VerifiedTxnCache and returns every
// transaction as verified.
type alwaysVerifiedPool struct{}

func (*alwaysVerifiedPool) Verified(txn transactions.SignedTxn) bool {
	return true
}

func (pool *TransactionPool) addToPendingBlockEvaluatorOnce(tx *transactions.SignedTxn) error {
	if tx.LastValid < pool.pendingBlockEvaluatorRound {
		return fmt.Errorf("Transaction valid for %d..%d which is before %d", tx.FirstValid, tx.LastValid, simulatedNextRound)
	}

	return pool.pendingBlockEvaluator.Transaction(tx, nil)
}

func (pool *TransactionPool) addToPendingBlockEvaluator(tx *transactions.SignedTxn) error {
	err := pool.addToPendingBlockEvaluatorOnce(tx)
	if err == ledger.ErrNoSpace {
		pool.pendingBlockEvaluatorRound++
		pool.pendingBlockEvaluator.ResetTxnBytes()
		err = pool.addToPendingBlockEvaluatorOnce(tx)
	}
	return err
}

// recomputeBlockEvaluator constructs a new BlockEvaluator and feeds all
// in-pool transactions to it (removing any transactions that are rejected
// by the BlockEvaluator).
func (pool *TransactionPool) recomputeBlockEvaluator() (stats telemetryspec.ProcessBlockMetrics) {
	pool.pendingBlockEvaluator = nil

	latest := pool.ledger.Latest()
	prev, err := pool.ledger.BlockHdr(latest)
	if err != nil {
		logging.Base().Warnf("TransactionPool.recomputeBlockEvaluator: cannot get prev header for %d: %v",
			latest, err)
		return
	}

	next := bookkeeping.MakeBlock(prev)
	pool.pendingBlockEvaluatorRound = next.Round()
	pool.pendingBlockEvaluator, err = pool.ledger.StartEvaluator(next.BlockHeader, &alwaysVerifiedPool{}, nil)
	if err != nil {
		logging.Base().Warnf("TransactionPool.recomputeBlockEvaluator: cannot start evaluator: %v", err)
		return
	}

	// Feed the transactions in priority order, so that higher-priority
	// transactions go in first, and lower-priority transactions are more
	// likely to get dropped.
	txns := make([]transactions.SignedTxn, len(pool.pendingTxns))
	sorti := make([]int, len(pool.pendingTxns))
	i := 0
	for _, txn := range pool.pendingTxns {
		txns[i] = txn
		sorti[i] = i
		i++
	}

	sort.SliceStable(sorti, func(i, j int) bool {
		return txns[sorti[j]].PtrPriority().LessThan(txns[sorti[i]].PtrPriority())
	})

	out := make([]transactions.SignedTxn, len(pool.pendingTxns))
	for i, p := range sorti {
		out[i] = txns[p]
	}

	for _, tx := range out {
		err := pool.addToPendingBlockEvaluator(tx)
		if err != nil {
			pool.remove(tx.ID(), err)

			switch err.(type) {
			case transactions.TxnDeadError:
				stats.ExpiredCount++
			default:
				stats.RemovedInvalidCount++
			}
		}
	}

	return
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
	pool.txPriorityQueue.Remove(txid)
	delete(pool.pendingTxns, txid)

	// If the transaction was removed due to an error (instead of being
	// committed to the ledger), remember the error in the statusCache.
	if txErr != nil {
		pool.statusCache.put(tx, txErr.Error())
	}
}
