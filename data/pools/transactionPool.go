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
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/condvar"
)

// A TransactionPool prepares valid blocks for proposal and caches
// validated transaction groups.
//
// At all times, a TransactionPool maintains a queue of transaction
// groups slated for proposal.  TransactionPool.Remember adds a
// properly-signed and well-formed transaction group to this queue
// only if its fees are sufficiently high and its state changes are
// consistent with the prior transactions in the queue.
//
// TransactionPool.AssembleBlock constructs a valid block for
// proposal given a deadline.
type TransactionPool struct {
	// const
	logProcessBlockStats bool
	logAssembleStats     bool
	expFeeFactor         uint64
	txPoolMaxSize        int
	ledger               *ledger.Ledger

	mu                     deadlock.Mutex
	cond                   sync.Cond
	expiredTxCount         map[basics.Round]int
	pendingBlockEvaluator  *ledger.BlockEvaluator
	numPendingWholeBlocks  basics.Round
	feeThresholdMultiplier uint64
	statusCache            *statusCache

	assemblyMu       deadlock.Mutex
	assemblyCond     sync.Cond
	assemblyDeadline time.Time
	assemblyResults  poolAsmResults

	// pendingMu protects pendingTxGroups and pendingTxids
	pendingMu           deadlock.RWMutex
	pendingTxGroups     [][]transactions.SignedTxn
	pendingVerifyParams [][]verify.Params
	pendingTxids        map[transactions.Txid]txPoolVerifyCacheVal

	// Calls to remember() add transactions to rememberedTxGroups and
	// rememberedTxids.  Calling rememberCommit() adds them to the
	// pendingTxGroups and pendingTxids.  This allows us to batch the
	// changes in OnNewBlock() without preventing a concurrent call
	// to Pending() or Verified().
	rememberedTxGroups     [][]transactions.SignedTxn
	rememberedVerifyParams [][]verify.Params
	rememberedTxids        map[transactions.Txid]txPoolVerifyCacheVal
}

// MakeTransactionPool makes a transaction pool.
func MakeTransactionPool(ledger *ledger.Ledger, cfg config.Local) *TransactionPool {
	if cfg.TxPoolExponentialIncreaseFactor < 1 {
		cfg.TxPoolExponentialIncreaseFactor = 1
	}
	pool := TransactionPool{
		pendingTxids:         make(map[transactions.Txid]txPoolVerifyCacheVal),
		rememberedTxids:      make(map[transactions.Txid]txPoolVerifyCacheVal),
		expiredTxCount:       make(map[basics.Round]int),
		ledger:               ledger,
		statusCache:          makeStatusCache(cfg.TxPoolSize),
		logProcessBlockStats: cfg.EnableProcessBlockStats,
		logAssembleStats:     cfg.EnableAssembleStats,
		expFeeFactor:         cfg.TxPoolExponentialIncreaseFactor,
		txPoolMaxSize:        cfg.TxPoolSize,
	}
	pool.cond.L = &pool.mu
	pool.assemblyCond.L = &pool.assemblyMu
	pool.recomputeBlockEvaluator(make(map[transactions.Txid]basics.Round))
	return &pool
}

type txPoolVerifyCacheVal struct {
	txn    transactions.SignedTxn
	params verify.Params
}

type poolAsmResults struct {
	ok    bool
	blk   *ledger.ValidatedBlock
	stats telemetryspec.AssembleBlockMetrics
	err   error
}

// TODO I moved this number to be a constant in the module, we should consider putting it in the local config
const expiredHistory = 10

// timeoutOnNewBlock determines how long Test() and Remember() wait for
// OnNewBlock() to process a new block that appears to be in the ledger.
const timeoutOnNewBlock = time.Second

// assemblyWaitEps is the extra time AssembleBlock() waits past the
// deadline before giving up.
const assemblyWaitEps = 10 * time.Millisecond

// ErrTxPoolStaleBlockAssembly returned by AssembleBlock when requested block number is older than the current transaction pool round
// i.e. typically it means that we're trying to make a proposal for an older round than what the ledger is currently pointing at.
var ErrTxPoolStaleBlockAssembly = fmt.Errorf("AssembleBlock: requested block assembly specified a round that is older than current transaction pool round")

// Reset resets the content of the transaction pool
func (pool *TransactionPool) Reset() {
	pool.pendingTxids = make(map[transactions.Txid]txPoolVerifyCacheVal)
	pool.pendingVerifyParams = nil
	pool.pendingTxGroups = nil
	pool.rememberedTxids = make(map[transactions.Txid]txPoolVerifyCacheVal)
	pool.rememberedVerifyParams = nil
	pool.rememberedTxGroups = nil
	pool.expiredTxCount = make(map[basics.Round]int)
	pool.numPendingWholeBlocks = 0
	pool.pendingBlockEvaluator = nil
	pool.statusCache.reset()
	pool.recomputeBlockEvaluator(make(map[transactions.Txid]basics.Round))
}

// NumExpired returns the number of transactions that expired at the
// end of a round (only meaningful if cleanup has been called for that
// round).
func (pool *TransactionPool) NumExpired(round basics.Round) int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.expiredTxCount[round]
}

// PendingTxIDs return the IDs of all pending transactions.
func (pool *TransactionPool) PendingTxIDs() []transactions.Txid {
	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()

	ids := make([]transactions.Txid, len(pool.pendingTxids))
	i := 0
	for txid := range pool.pendingTxids {
		ids[i] = txid
		i++
	}
	return ids
}

// Pending returns a list of transaction groups that should be proposed
// in the next block, in order.
func (pool *TransactionPool) Pending() [][]transactions.SignedTxn {
	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()
	// note that this operation is safe for the sole reason that arrays in go are immutable.
	// if the underlaying array need to be expanded, the actual underlaying array would need
	// to be reallocated.
	return pool.pendingTxGroups
}

// rememberCommit() saves the changes added by remember to
// pendingTxGroups and pendingTxids.  The caller is assumed to
// be holding pool.mu.  flush indicates whether previous
// pendingTxGroups and pendingTxids should be flushed out and
// replaced altogether by rememberedTxGroups and rememberedTxids.
func (pool *TransactionPool) rememberCommit(flush bool) {
	pool.pendingMu.Lock()
	defer pool.pendingMu.Unlock()

	if flush {
		pool.pendingTxGroups = pool.rememberedTxGroups
		pool.pendingVerifyParams = pool.rememberedVerifyParams
		pool.pendingTxids = pool.rememberedTxids
	} else {
		pool.pendingTxGroups = append(pool.pendingTxGroups, pool.rememberedTxGroups...)
		pool.pendingVerifyParams = append(pool.pendingVerifyParams, pool.rememberedVerifyParams...)
		for txid, txn := range pool.rememberedTxids {
			pool.pendingTxids[txid] = txn
		}
	}

	pool.rememberedTxGroups = nil
	pool.rememberedVerifyParams = nil
	pool.rememberedTxids = make(map[transactions.Txid]txPoolVerifyCacheVal)
}

// PendingCount returns the number of transactions currently pending in the pool.
func (pool *TransactionPool) PendingCount() int {
	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()
	return pool.pendingCountNoLock()
}

// pendingCountNoLock is a helper for PendingCount that returns the number of
// transactions pending in the pool
func (pool *TransactionPool) pendingCountNoLock() int {
	var count int
	for _, txgroup := range pool.pendingTxGroups {
		count += len(txgroup)
	}
	return count
}

// checkPendingQueueSize test to see if there is more room in the pending
// group transaction list. As long as we haven't surpassed the size limit, we
// should be good to go.
func (pool *TransactionPool) checkPendingQueueSize() error {
	pendingSize := len(pool.Pending())
	if pendingSize >= pool.txPoolMaxSize {
		return fmt.Errorf("TransactionPool.Test: transaction pool have reached capacity")
	}
	return nil
}

func (pool *TransactionPool) checkSufficientFee(txgroup []transactions.SignedTxn) error {
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

	// The feePerByte should be bumped to 1 to make the exponentially
	// threshold growing valid.
	if feePerByte == 0 && pool.numPendingWholeBlocks > 1 {
		feePerByte = uint64(1)
	}

	// The threshold grows exponentially if there are multiple blocks
	// pending in the pool.
	// golang has no convenient integer exponentiation, so we just
	// do this in a loop
	for i := 0; i < int(pool.numPendingWholeBlocks)-1; i++ {
		feePerByte *= pool.expFeeFactor
	}

	for _, t := range txgroup {
		feeThreshold := feePerByte * uint64(t.GetEncodedLength())
		if t.Txn.Fee.Raw < feeThreshold {
			return fmt.Errorf("fee %d below threshold %d (%d per byte * %d bytes)",
				t.Txn.Fee, feeThreshold, feePerByte, t.GetEncodedLength())
		}
	}

	return nil
}

// Test performs basic duplicate detection and well-formedness checks
// on a transaction group without storing the group.
func (pool *TransactionPool) Test(txgroup []transactions.SignedTxn) error {
	if err := pool.checkPendingQueueSize(); err != nil {
		return err
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	if pool.pendingBlockEvaluator == nil {
		return fmt.Errorf("Test: pendingBlockEvaluator is nil")
	}

	return pool.pendingBlockEvaluator.TestTransactionGroup(txgroup)
}

type poolIngestParams struct {
	recomputing bool // if unset, perform fee checks and wait until ledger is caught up
	stats       *telemetryspec.AssembleBlockMetrics
}

// remember attempts to add a transaction group to the pool.
func (pool *TransactionPool) remember(txgroup []transactions.SignedTxn, verifyParams []verify.Params) error {
	params := poolIngestParams{
		recomputing: false,
	}
	return pool.ingest(txgroup, verifyParams, params)
}

// add tries to add the transaction group to the pool, bypassing the fee
// priority checks.
func (pool *TransactionPool) add(txgroup []transactions.SignedTxn, verifyParams []verify.Params, stats *telemetryspec.AssembleBlockMetrics) error {
	params := poolIngestParams{
		recomputing: true,
		stats:       stats,
	}
	return pool.ingest(txgroup, verifyParams, params)
}

// ingest checks whether a transaction group could be remembered in the pool,
// and stores this transaction if valid.
//
// ingest assumes that pool.mu is locked.  It might release the lock
// while it waits for OnNewBlock() to be called.
func (pool *TransactionPool) ingest(txgroup []transactions.SignedTxn, verifyParams []verify.Params, params poolIngestParams) error {
	if pool.pendingBlockEvaluator == nil {
		return fmt.Errorf("TransactionPool.ingest: no pending block evaluator")
	}

	if !params.recomputing {
		// Make sure that the latest block has been processed by OnNewBlock().
		// If not, we might be in a race, so wait a little bit for OnNewBlock()
		// to catch up to the ledger.
		latest := pool.ledger.Latest()
		waitExpires := time.Now().Add(timeoutOnNewBlock)
		for pool.pendingBlockEvaluator.Round() <= latest && time.Now().Before(waitExpires) {
			condvar.TimedWait(&pool.cond, timeoutOnNewBlock)
			if pool.pendingBlockEvaluator == nil {
				return fmt.Errorf("TransactionPool.ingest: no pending block evaluator")
			}
		}

		err := pool.checkSufficientFee(txgroup)
		if err != nil {
			return err
		}
	}

	err := pool.addToPendingBlockEvaluator(txgroup, params.recomputing, params.stats)
	if err != nil {
		return err
	}

	pool.rememberedTxGroups = append(pool.rememberedTxGroups, txgroup)
	pool.rememberedVerifyParams = append(pool.rememberedVerifyParams, verifyParams)
	for i, t := range txgroup {
		pool.rememberedTxids[t.ID()] = txPoolVerifyCacheVal{txn: t, params: verifyParams[i]}
	}

	return nil
}

// RememberOne stores the provided transaction.
// Precondition: Only RememberOne() properly-signed and well-formed transactions (i.e., ensure t.WellFormed())
func (pool *TransactionPool) RememberOne(t transactions.SignedTxn, verifyParams verify.Params) error {
	return pool.Remember([]transactions.SignedTxn{t}, []verify.Params{verifyParams})
}

// Remember stores the provided transaction group.
// Precondition: Only Remember() properly-signed and well-formed transactions (i.e., ensure t.WellFormed())
func (pool *TransactionPool) Remember(txgroup []transactions.SignedTxn, verifyParams []verify.Params) error {
	if err := pool.checkPendingQueueSize(); err != nil {
		return err
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	err := pool.remember(txgroup, verifyParams)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember: %v", err)
	}

	pool.rememberCommit(false)
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
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()

	cacheval, inPool := pool.pendingTxids[txid]
	tx = cacheval.txn
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
func (pool *TransactionPool) Verified(txn transactions.SignedTxn, params verify.Params) bool {
	if pool == nil {
		return false
	}
	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()
	cacheval, ok := pool.pendingTxids[txn.ID()]
	if !ok {
		return false
	}

	if cacheval.params != params {
		return false
	}
	pendingSigTxn := cacheval.txn
	return pendingSigTxn.Sig == txn.Sig && pendingSigTxn.Msig.Equal(txn.Msig) && pendingSigTxn.Lsig.Equal(&txn.Lsig) && (pendingSigTxn.AuthAddr == txn.AuthAddr)
}

// OnNewBlock excises transactions from the pool that are included in the specified Block or if they've expired
func (pool *TransactionPool) OnNewBlock(block bookkeeping.Block, delta ledger.StateDelta) {
	var stats telemetryspec.ProcessBlockMetrics
	var knownCommitted uint
	var unknownCommitted uint

	commitedTxids := delta.Txids
	if pool.logProcessBlockStats {
		pool.pendingMu.RLock()
		for txid := range commitedTxids {
			if _, ok := pool.pendingTxids[txid]; ok {
				knownCommitted++
			} else {
				unknownCommitted++
			}
		}
		pool.pendingMu.RUnlock()
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	defer pool.cond.Broadcast()

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
			pool.feeThresholdMultiplier = pool.feeThresholdMultiplier / pool.expFeeFactor

		case 1:
			// Keep the fee multiplier the same.

		default:
			if pool.feeThresholdMultiplier == 0 {
				pool.feeThresholdMultiplier = 1
			} else {
				pool.feeThresholdMultiplier = pool.feeThresholdMultiplier * pool.expFeeFactor
			}
		}

		// Recompute the pool by starting from the new latest block.
		// This has the side-effect of discarding transactions that
		// have been committed (or that are otherwise no longer valid).
		stats = pool.recomputeBlockEvaluator(commitedTxids)
	}

	stats.KnownCommittedCount = knownCommitted
	stats.UnknownCommittedCount = unknownCommitted

	proto := config.Consensus[block.CurrentProtocol]
	pool.expiredTxCount[block.Round()] = int(stats.ExpiredCount)
	delete(pool.expiredTxCount, block.Round()-expiredHistory*basics.Round(proto.MaxTxnLife))

	if pool.logProcessBlockStats {
		var details struct {
			Round uint64
		}
		details.Round = uint64(block.Round())
		logging.Base().Metrics(telemetryspec.Transaction, stats, details)
	}
}

func (pool *TransactionPool) addToPendingBlockEvaluatorOnce(txgroup []transactions.SignedTxn, recomputing bool, stats *telemetryspec.AssembleBlockMetrics) error {
	r := pool.pendingBlockEvaluator.Round() + pool.numPendingWholeBlocks
	for _, tx := range txgroup {
		if tx.Txn.LastValid < r {
			return transactions.TxnDeadError{
				Round:      r,
				FirstValid: tx.Txn.FirstValid,
				LastValid:  tx.Txn.LastValid,
			}
		}
	}

	txgroupad := make([]transactions.SignedTxnWithAD, len(txgroup))
	for i, tx := range txgroup {
		txgroupad[i].SignedTxn = tx
	}
	err := pool.pendingBlockEvaluator.TransactionGroup(txgroupad)

	if recomputing {
		pool.assemblyMu.Lock()
		defer pool.assemblyMu.Unlock()
		if !pool.assemblyResults.ok {
			if err == ledger.ErrNoSpace || (pool.assemblyDeadline != time.Time{} && time.Now().After(pool.assemblyDeadline)) {
				pool.assemblyResults.ok = true

				stats.StopReason = telemetryspec.AssembleBlockTimeout
				if err == ledger.ErrNoSpace {
					stats.StopReason = telemetryspec.AssembleBlockFull
				}
				pool.assemblyResults.stats = *stats

				lvb, gerr := pool.pendingBlockEvaluator.GenerateBlock()
				if gerr != nil {
					rnd := pool.pendingBlockEvaluator.Round()
					pool.assemblyResults.err = fmt.Errorf("could not generate block for %d: %v", rnd, gerr)
				} else {
					pool.assemblyResults.blk = lvb
				}
				pool.assemblyCond.Broadcast()
			}
		}
	}
	return err
}

func (pool *TransactionPool) addToPendingBlockEvaluator(txgroup []transactions.SignedTxn, recomputing bool, stats *telemetryspec.AssembleBlockMetrics) error {
	err := pool.addToPendingBlockEvaluatorOnce(txgroup, recomputing, stats)
	if err == ledger.ErrNoSpace {
		pool.numPendingWholeBlocks++
		pool.pendingBlockEvaluator.ResetTxnBytes()
		err = pool.addToPendingBlockEvaluatorOnce(txgroup, recomputing, stats)
	}
	return err
}

// recomputeBlockEvaluator constructs a new BlockEvaluator and feeds all
// in-pool transactions to it (removing any transactions that are rejected
// by the BlockEvaluator).
func (pool *TransactionPool) recomputeBlockEvaluator(committedTxIds map[transactions.Txid]basics.Round) (stats telemetryspec.ProcessBlockMetrics) {
	pool.pendingBlockEvaluator = nil

	latest := pool.ledger.Latest()
	prev, err := pool.ledger.BlockHdr(latest)
	if err != nil {
		logging.Base().Warnf("TransactionPool.recomputeBlockEvaluator: cannot get prev header for %d: %v",
			latest, err)
		return
	}

	// Process upgrade to see if we support the next protocol version
	_, upgradeState, err := bookkeeping.ProcessUpgradeParams(prev)
	if err != nil {
		logging.Base().Warnf("TransactionPool.recomputeBlockEvaluator: error processing upgrade params for next round: %v", err)
		return
	}

	// Ensure we know about the next protocol version (MakeBlock will panic
	// if we don't, and we would rather stall locally than panic)
	_, ok := config.Consensus[upgradeState.CurrentProtocol]
	if !ok {
		logging.Base().Warnf("TransactionPool.recomputeBlockEvaluator: next protocol version %v is not supported", upgradeState.CurrentProtocol)
		return
	}

	// Grab the transactions to be played through the new block evaluator
	pool.pendingMu.RLock()
	txgroups := pool.pendingTxGroups
	verifyParams := pool.pendingVerifyParams
	pendingCount := pool.pendingCountNoLock()
	pool.pendingMu.RUnlock()

	pool.assemblyMu.Lock()
	pool.assemblyResults = poolAsmResults{}
	pool.assemblyMu.Unlock()

	next := bookkeeping.MakeBlock(prev)
	pool.numPendingWholeBlocks = 0
	pool.pendingBlockEvaluator, err = pool.ledger.StartEvaluator(next.BlockHeader, pendingCount)
	if err != nil {
		logging.Base().Warnf("TransactionPool.recomputeBlockEvaluator: cannot start evaluator: %v", err)
		return
	}

	var asmStats telemetryspec.AssembleBlockMetrics
	asmStats.StartCount = len(txgroups)
	asmStats.StopReason = telemetryspec.AssembleBlockEmpty

	// Feed the transactions in order
	for i, txgroup := range txgroups {
		if len(txgroup) == 0 {
			asmStats.InvalidCount++
			continue
		}
		if _, alreadyCommitted := committedTxIds[txgroup[0].ID()]; alreadyCommitted {
			asmStats.EarlyCommittedCount++
			continue
		}
		err := pool.add(txgroup, verifyParams[i], &asmStats)
		if err != nil {
			for _, tx := range txgroup {
				pool.statusCache.put(tx, err.Error())
			}

			switch err.(type) {
			case ledger.TransactionInLedgerError:
				asmStats.CommittedCount++
				stats.RemovedInvalidCount++
			case transactions.TxnDeadError:
				asmStats.InvalidCount++
				stats.ExpiredCount++
			case transactions.MinFeeError:
				asmStats.InvalidCount++
				stats.RemovedInvalidCount++
				logging.Base().Infof("Cannot re-add pending transaction to pool: %v", err)
			default:
				asmStats.InvalidCount++
				stats.RemovedInvalidCount++
				logging.Base().Warnf("Cannot re-add pending transaction to pool: %v", err)
			}
		}
	}

	pool.assemblyMu.Lock()
	if !pool.assemblyResults.ok {
		pool.assemblyResults.ok = true
		pool.assemblyResults.stats = asmStats
		lvb, err := pool.pendingBlockEvaluator.GenerateBlock()
		if err != nil {
			rnd := pool.pendingBlockEvaluator.Round()
			pool.assemblyResults.err = fmt.Errorf("could not generate block for %d (end): %v", rnd, err)
		} else {
			pool.assemblyResults.blk = lvb
		}
		pool.assemblyCond.Broadcast()
	}
	pool.assemblyMu.Unlock()

	pool.rememberCommit(true)
	return
}

// AssembleBlock assembles a block for a given round, trying not to
// take longer than deadline to finish.
func (pool *TransactionPool) AssembleBlock(round basics.Round, deadline time.Time) (assembled *ledger.ValidatedBlock, err error) {
	var stats telemetryspec.AssembleBlockMetrics

	if pool.logAssembleStats {
		start := time.Now()
		defer func() {
			if err != nil {
				return
			}

			// Measure time here because we want to know how close to deadline we are
			dt := time.Now().Sub(start)
			stats.Nanoseconds = dt.Nanoseconds()

			payset := assembled.Block().Payset
			if len(payset) != 0 {
				totalFees := uint64(0)

				for i, txib := range payset {
					fee := txib.Txn.Fee.Raw
					encodedLen := len(protocol.Encode(&txib))

					stats.IncludedCount++
					totalFees += fee

					if i == 0 {
						stats.MinFee = fee
						stats.MaxFee = fee
						stats.MinLength = encodedLen
						stats.MaxLength = encodedLen
					} else {
						if fee < stats.MinFee {
							stats.MinFee = fee
						} else if fee > stats.MaxFee {
							stats.MaxFee = fee
						}
						if encodedLen < stats.MinLength {
							stats.MinLength = encodedLen
						} else if encodedLen > stats.MaxLength {
							stats.MaxLength = encodedLen
						}
					}
					stats.TotalLength += uint64(encodedLen)
				}

				stats.AverageFee = totalFees / uint64(stats.IncludedCount)
			}

			var details struct {
				Round uint64
			}
			details.Round = uint64(round)
			logging.Base().Metrics(telemetryspec.Transaction, stats, details)
		}()
	}

	pool.assemblyMu.Lock()
	defer pool.assemblyMu.Unlock()

	pool.assemblyDeadline = deadline
	deadline = deadline.Add(assemblyWaitEps)
	for time.Now().Before(deadline) && (!pool.assemblyResults.ok || pool.assemblyResults.blk.Block().Round() < round) {
		condvar.TimedWait(&pool.assemblyCond, deadline.Sub(time.Now()))
	}
	pool.assemblyDeadline = time.Time{}

	if !pool.assemblyResults.ok {
		return nil, fmt.Errorf("AssembleBlock: ran out of time for round %d", round)
	}
	if pool.assemblyResults.err != nil {
		return nil, fmt.Errorf("AssemblyBlock: encountered error for round %d: %v", round, pool.assemblyResults.err)
	}
	if pool.assemblyResults.blk.Block().Round() > round {
		logging.Base().Infof("AssembleBlock: requested round is behind transaction pool round %d < %d", round, pool.assemblyResults.blk.Block().Round())
		return nil, ErrTxPoolStaleBlockAssembly
	} else if pool.assemblyResults.blk.Block().Round() != round {
		return nil, fmt.Errorf("AssembleBlock: assembled block round does not match: %d != %d",
			pool.assemblyResults.blk.Block().Round(), round)
	}

	stats = pool.assemblyResults.stats
	return pool.assemblyResults.blk, nil
}
