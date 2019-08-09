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
	"fmt"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/util/condvar"
)

// TransactionPool is a struct maintaining a sanitized pool of transactions that are available for inclusion in
// a Block.  We sanitize it by preventing duplicates and limiting the number of transactions retained for each account
type TransactionPool struct {
	mu                     deadlock.RWMutex
	cond                   sync.Cond
	pendingTxns            []transactions.SignedTxn
	pendingTxids           map[transactions.Txid]transactions.SignedTxn
	expiredTxCount         map[basics.Round]int
	pendingBlockEvaluator  *ledger.BlockEvaluator
	numPendingWholeBlocks  basics.Round
	feeThresholdMultiplier uint64
	ledger                 *ledger.Ledger
	statusCache            *statusCache
	logStats               bool
}

// MakeTransactionPool is the constructor, it uses Ledger to ensure that no account has pending transactions that together overspend.
//
// The pool also contains status information for the last transactionPoolStatusSize
// transactions that were removed from the pool without being committed.
func MakeTransactionPool(ledger *ledger.Ledger, transactionPoolStatusSize int, logStats bool) *TransactionPool {
	pool := TransactionPool{
		pendingTxids:   make(map[transactions.Txid]transactions.SignedTxn),
		expiredTxCount: make(map[basics.Round]int),
		ledger:         ledger,
		statusCache:    makeStatusCache(transactionPoolStatusSize),
		logStats:       logStats,
	}
	pool.cond.L = &pool.mu
	pool.recomputeBlockEvaluator()
	return &pool
}

// TODO I moved this number to be a constant in the module, we should consider putting it in the local config
const expiredHistory = 10

// timeoutOnNewBlock determines how long Test() and Remember() wait for
// OnNewBlock() to process a new block that appears to be in the ledger.
const timeoutOnNewBlock = time.Second

// NumExpired returns the number of transactions that expired at the end of a round (only meaningful if cleanup has
// been called for that round)
func (pool *TransactionPool) NumExpired(round basics.Round) int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.expiredTxCount[round]
}

// PendingTxIDs return the IDs of all pending transactions
func (pool *TransactionPool) PendingTxIDs() []transactions.Txid {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	ids := make([]transactions.Txid, len(pool.pendingTxns))
	i := 0
	for txid := range pool.pendingTxids {
		ids[i] = txid
		i++
	}
	return ids
}

// Pending returns a list of transactions that should be proposed
// in the next block, in order.
func (pool *TransactionPool) Pending() []transactions.SignedTxn {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	txns := make([]transactions.SignedTxn, len(pool.pendingTxns))
	i := 0
	for _, tx := range pool.pendingTxns {
		txns[i] = tx
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

// Test checks whether a transaction could be remembered in the pool,
// but does not actually store this transaction in the pool.
func (pool *TransactionPool) Test(t transactions.SignedTxn) error {
	t.InitCaches()

	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.test(t)
}

// test checks whether a transaction could be remembered in the pool,
// but does not actually store this transaction in the pool.
//
// test assumes that pool.mu is locked.  It might release the lock
// while it waits for OnNewBlock() to be called.
func (pool *TransactionPool) test(t transactions.SignedTxn) error {
	if pool.pendingBlockEvaluator == nil {
		return fmt.Errorf("TransactionPool.test: no pending block evaluator")
	}

	// Make sure that the latest block has been processed by OnNewBlock().
	// If not, we might be in a race, so wait a little bit for OnNewBlock()
	// to catch up to the ledger.
	latest := pool.ledger.Latest()
	waitExpires := time.Now().Add(timeoutOnNewBlock)
	for pool.pendingBlockEvaluator.Round() <= latest && time.Now().Before(waitExpires) {
		condvar.TimedWait(&pool.cond, timeoutOnNewBlock)
	}

	tentativeRound := pool.pendingBlockEvaluator.Round() + pool.numPendingWholeBlocks
	err := pool.pendingBlockEvaluator.TestTransaction(t, nil)
	if err == ledger.ErrNoSpace {
		tentativeRound++
	} else if err != nil {
		return err
	}

	if t.Txn.LastValid < tentativeRound {
		return transactions.TxnDeadError{
			Round:      tentativeRound,
			FirstValid: t.Txn.FirstValid,
			LastValid:  t.Txn.LastValid,
		}
	}

	// The baseline threshold fee per byte is 1, the smallest fee we can
	// represent.  This amounts to a fee of 100 for a 100-byte txn, which
	// is well below MinTxnFee (1000).  This means that, when the pool
	// is not under load, the total MinFee dominates for small txns,
	// but once the pool comes under load, the fee-per-byte will quickly
	// come to dominate.
	feePerByte := uint64(1)

	// The threshold is multiplied by the feeThresholdMultiplier that
	// tracks the load on the transaction pool over time.  If the pool
	// is mostly idle, feeThresholdMultiplier will be 0, and all txns
	// are accepted (assuming the BlockEvaluator approves them, which
	// requires a flat MinTxnFee).
	feePerByte = feePerByte * pool.feeThresholdMultiplier

	// The threshold grows exponentially if there are multiple blocks
	// pending in the pool.
	if pool.numPendingWholeBlocks > 1 {
		feePerByte = feePerByte << (pool.numPendingWholeBlocks - 1)
	}

	feeThreshold := feePerByte * uint64(t.GetEncodedLength())
	if t.Txn.Fee.Raw < feeThreshold {
		return fmt.Errorf("fee %d below threshold %d (%d per byte * %d bytes)",
			t.Txn.Fee, feeThreshold, feePerByte, t.GetEncodedLength())
	}

	return nil
}

// Remember stores the provided transaction
// Precondition: Only Remember() properly-signed and well-formed transactions (i.e., ensure t.WellFormed())
func (pool *TransactionPool) Remember(t transactions.SignedTxn) error {
	t.InitCaches()

	pool.mu.Lock()
	defer pool.mu.Unlock()

	err := pool.test(t)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember: %v", err)
	}

	if pool.pendingBlockEvaluator == nil {
		return fmt.Errorf("TransactionPool.Remember: no pending block evaluator")
	}

	err = pool.remember(t)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember: %v", err)
	}

	return nil
}

// remember tries to add the transaction to the pool, bypassing the fee priority checks.
func (pool *TransactionPool) remember(t transactions.SignedTxn) error {
	err := pool.addToPendingBlockEvaluator(t)
	if err != nil {
		return err
	}

	pool.pendingTxns = append(pool.pendingTxns, t)
	pool.pendingTxids[t.ID()] = t
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

	tx, inPool := pool.pendingTxids[txid]
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
	pendingSigTxn, ok := pool.pendingTxids[txn.ID()]
	if !ok {
		return false
	}

	return pendingSigTxn.Sig == txn.Sig && pendingSigTxn.Msig.Equal(txn.Msig)
}

// OnNewBlock excises transactions from the pool that are included in the specified Block or if they've expired
func (pool *TransactionPool) OnNewBlock(block bookkeeping.Block) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	defer pool.cond.Broadcast()

	var stats telemetryspec.ProcessBlockMetrics
	var knownCommitted uint
	var unknownCommitted uint

	payset, err := block.DecodePayset()
	if err == nil {
		for _, tx := range payset {
			txid := tx.ID()
			_, ok := pool.pendingTxids[txid]
			if ok {
				knownCommitted++
			} else {
				unknownCommitted++
			}
		}
	}

	if pool.pendingBlockEvaluator == nil || block.Round() >= pool.pendingBlockEvaluator.Round() {
		// Adjust the pool fee threshold.  The rules are:
		// - If there was less than one full block in the pool, reduce
		//   the multiplier by 2x.  It will eventually go to 0, so that
		//   only the flat MinTxnFee matters if the pool is idle.
		// - If there were less than two full blocks in the pool, keep
		//   the multiplier as-is.
		// - If there were two or more full blocks in the pool, grow
		//   the multiplier by 2x (or increment by 1, if 0).
		switch pool.numPendingWholeBlocks {
		case 0:
			pool.feeThresholdMultiplier = pool.feeThresholdMultiplier / 2

		case 1:
			// Keep the fee multiplier the same.

		default:
			if pool.feeThresholdMultiplier == 0 {
				pool.feeThresholdMultiplier = 1
			} else {
				pool.feeThresholdMultiplier = pool.feeThresholdMultiplier * 2
			}
		}

		// Recompute the pool by starting from the new latest block.
		// This has the side-effect of discarding transactions that
		// have been committed (or that are otherwise no longer valid).
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

func (pool *TransactionPool) addToPendingBlockEvaluatorOnce(tx transactions.SignedTxn) error {
	r := pool.pendingBlockEvaluator.Round() + pool.numPendingWholeBlocks
	if tx.Txn.LastValid < r {
		return transactions.TxnDeadError{
			Round:      r,
			FirstValid: tx.Txn.FirstValid,
			LastValid:  tx.Txn.LastValid,
		}
	}

	return pool.pendingBlockEvaluator.Transaction(tx, nil)
}

func (pool *TransactionPool) addToPendingBlockEvaluator(tx transactions.SignedTxn) error {
	err := pool.addToPendingBlockEvaluatorOnce(tx)
	if err == ledger.ErrNoSpace {
		pool.numPendingWholeBlocks++
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
	pool.numPendingWholeBlocks = 0
	pool.pendingBlockEvaluator, err = pool.ledger.StartEvaluator(next.BlockHeader, &alwaysVerifiedPool{}, nil)
	if err != nil {
		logging.Base().Warnf("TransactionPool.recomputeBlockEvaluator: cannot start evaluator: %v", err)
		return
	}

	// Feed the transactions in order.
	txns := pool.pendingTxns
	pool.pendingTxns = nil
	pool.pendingTxids = make(map[transactions.Txid]transactions.SignedTxn)

	for _, tx := range txns {
		err := pool.remember(tx)
		if err != nil {
			pool.statusCache.put(tx, err.Error())

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
