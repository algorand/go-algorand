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

package pools

import (
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
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
	pendingBlockEvaluator  BlockEvaluator
	evalTracer             logic.EvalTracer
	numPendingWholeBlocks  basics.Round
	feePerByte             atomic.Uint64
	feeThresholdMultiplier uint64
	statusCache            *statusCache

	assemblyMu       deadlock.Mutex
	assemblyCond     sync.Cond
	assemblyDeadline time.Time
	// assemblyRound indicates which round number we're currently waiting for or waited for last.
	assemblyRound   basics.Round
	assemblyResults poolAsmResults

	// pendingMu protects pendingTxGroups and pendingTxids
	pendingMu       deadlock.RWMutex
	pendingTxGroups [][]transactions.SignedTxn
	pendingTxids    map[transactions.Txid]transactions.SignedTxn

	// Calls to remember() add transactions to rememberedTxGroups and
	// rememberedTxids.  Calling rememberCommit() adds them to the
	// pendingTxGroups and pendingTxids.  This allows us to batch the
	// changes in OnNewBlock() without preventing a concurrent call
	// to PendingTxGroups() or Verified().
	rememberedTxGroups [][]transactions.SignedTxn
	rememberedTxids    map[transactions.Txid]transactions.SignedTxn

	log logging.Logger
	vac VotingAccountSupplier

	// proposalAssemblyTime is the ProposalAssemblyTime configured for this node.
	proposalAssemblyTime time.Duration

	// stateproofOverflowed indicates that a stateproof transaction was allowed to
	// exceed the txPoolMaxSize. This flag is reset to false OnNewBlock
	stateproofOverflowed bool

	// shutdown is set to true when the pool is being shut down. It is checked in exported methods
	// to prevent pool operations like remember and recomputing the block evaluator
	// from using down stream resources like ledger that may be shutting down.
	shutdown bool
}

// BlockEvaluator defines the block evaluator interface exposed by the ledger package.
type BlockEvaluator interface {
	TestTransactionGroup(txgroup []transactions.SignedTxn) error
	Round() basics.Round
	PaySetSize() int
	TransactionGroup(txads []transactions.SignedTxnWithAD) error
	Transaction(txn transactions.SignedTxn, ad transactions.ApplyData) error
	GenerateBlock(addrs []basics.Address) (*ledgercore.UnfinishedBlock, error)
	ResetTxnBytes()
}

// VotingAccountSupplier provides a list of possible participating account addresses valid for a given round.
type VotingAccountSupplier interface {
	VotingAccountsForRound(basics.Round) []basics.Address
}

var errPoolShutdown = errors.New("transaction pool is shutting down")

// MakeTransactionPool makes a transaction pool.
func MakeTransactionPool(ledger *ledger.Ledger, cfg config.Local, log logging.Logger, vac VotingAccountSupplier) *TransactionPool {
	if cfg.TxPoolExponentialIncreaseFactor < 1 {
		cfg.TxPoolExponentialIncreaseFactor = 1
	}
	pool := TransactionPool{
		pendingTxids:         make(map[transactions.Txid]transactions.SignedTxn),
		rememberedTxids:      make(map[transactions.Txid]transactions.SignedTxn),
		expiredTxCount:       make(map[basics.Round]int),
		ledger:               ledger,
		statusCache:          makeStatusCache(cfg.TxPoolSize),
		logProcessBlockStats: cfg.EnableProcessBlockStats,
		logAssembleStats:     cfg.EnableAssembleStats,
		expFeeFactor:         cfg.TxPoolExponentialIncreaseFactor,
		txPoolMaxSize:        cfg.TxPoolSize,
		proposalAssemblyTime: cfg.ProposalAssemblyTime,
		log:                  log,
		vac:                  vac,
	}
	if cfg.EnableDeveloperAPI {
		pool.evalTracer = logic.EvalErrorDetailsTracer{}
	}
	pool.cond.L = &pool.mu
	pool.assemblyCond.L = &pool.assemblyMu
	pool.recomputeBlockEvaluator(nil, 0)
	return &pool
}

// poolAsmResults is used to syncronize the state of the block assembly process. The structure reading/writing is syncronized
// via the pool.assemblyMu lock.
type poolAsmResults struct {
	// the ok variable indicates whether the assembly for the block roundStartedEvaluating was complete ( i.e. ok == true ) or
	// whether it's still in-progress.
	ok    bool
	blk   *ledgercore.UnfinishedBlock
	stats telemetryspec.AssembleBlockMetrics
	err   error
	// roundStartedEvaluating is the round which we were attempted to evaluate last. It's a good measure for
	// which round we started evaluating, but not a measure to whether the evaluation is complete.
	roundStartedEvaluating basics.Round
	// assemblyCompletedOrAbandoned is *not* protected via the pool.assemblyMu lock and should be accessed only from the OnNewBlock goroutine.
	// it's equivalent to the "ok" variable, and used for avoiding taking the lock.
	assemblyCompletedOrAbandoned bool
}

const (
	// TODO I moved this number to be a constant in the module, we should consider putting it in the local config
	expiredHistory = 10

	// timeoutOnNewBlock determines how long Test() and Remember() wait for
	// OnNewBlock() to process a new block that appears to be in the ledger.
	timeoutOnNewBlock = time.Second

	// assemblyWaitEps is the extra time AssembleBlock() waits past the
	// deadline before giving up.
	assemblyWaitEps = 150 * time.Millisecond

	// The following two constants are used by the isAssemblyTimedOut function, and used to estimate the projected
	// duration it would take to execute the GenerateBlock() function
	generateBlockBaseDuration        = 2 * time.Millisecond
	generateBlockTransactionDuration = 2155 * time.Nanosecond
)

// Reset resets the content of the transaction pool
func (pool *TransactionPool) Reset() {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	defer pool.cond.Broadcast()
	pool.pendingTxids = make(map[transactions.Txid]transactions.SignedTxn)
	pool.pendingTxGroups = nil
	pool.rememberedTxids = make(map[transactions.Txid]transactions.SignedTxn)
	pool.rememberedTxGroups = nil
	pool.expiredTxCount = make(map[basics.Round]int)
	pool.numPendingWholeBlocks = 0
	pool.pendingBlockEvaluator = nil
	pool.statusCache.reset()
	pool.recomputeBlockEvaluator(nil, 0)
}

func (pool *TransactionPool) getVotingAccountsForRound(rnd basics.Round) []basics.Address {
	if pool.vac == nil {
		return nil
	}
	return pool.vac.VotingAccountsForRound(rnd)
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

// PendingTxGroups returns a list of transaction groups that should be proposed
// in the next block, in order.
func (pool *TransactionPool) PendingTxGroups() [][]transactions.SignedTxn {
	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()
	// note that this operation is safe for the sole reason that arrays in go are immutable.
	// if the underlaying array need to be expanded, the actual underlaying array would need
	// to be reallocated.
	return pool.pendingTxGroups
}

// pendingTxIDsCount returns the number of pending transaction ids that are still waiting
// in the transaction pool. This is identical to the number of transaction ids that would
// be retrieved by a call to PendingTxIDs()
func (pool *TransactionPool) pendingTxIDsCount() int {
	pool.pendingMu.RLock()
	defer pool.pendingMu.RUnlock()
	return len(pool.pendingTxids)
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
		pool.stateproofOverflowed = false
		pool.pendingTxids = pool.rememberedTxids
		pool.ledger.VerifiedTransactionCache().UpdatePinned(pool.pendingTxids)
	} else {
		pool.pendingTxGroups = append(pool.pendingTxGroups, pool.rememberedTxGroups...)

		maps.Copy(pool.pendingTxids, pool.rememberedTxids)
	}

	pool.rememberedTxGroups = nil
	pool.rememberedTxids = make(map[transactions.Txid]transactions.SignedTxn)
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

// checkPendingQueueSize tests to see if we can grow the pending group transaction list
// by adding len(txnGroup) more transactions. The limits comes from the total number of transactions
// and not from the total number of transaction groups.
// As long as we haven't surpassed the size limit, we should be good to go.
func (pool *TransactionPool) checkPendingQueueSize(txnGroup []transactions.SignedTxn) error {
	pendingSize := pool.pendingTxIDsCount()
	txCount := len(txnGroup)
	if pendingSize+txCount > pool.txPoolMaxSize {
		// Allow the state proof transaction to go over the txPoolMaxSize if it already didn't
		if len(txnGroup) == 1 && txnGroup[0].Txn.Type == protocol.StateProofTx {
			pool.pendingMu.Lock()
			defer pool.pendingMu.Unlock()
			if !pool.stateproofOverflowed {
				pool.stateproofOverflowed = true
				return nil
			}
		}
		return ErrPendingQueueReachedMaxCap
	}
	return nil
}

// FeePerByte returns the current minimum microalgos per byte a transaction
// needs to pay in order to get into the pool.
func (pool *TransactionPool) FeePerByte() uint64 {
	return pool.feePerByte.Load()
}

// computeFeePerByte computes and returns the current minimum microalgos per byte a transaction
// needs to pay in order to get into the pool. It also updates the atomic counter that holds
// the current fee per byte
func (pool *TransactionPool) computeFeePerByte() uint64 {
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

	// Update the counter for fast reads
	pool.feePerByte.Store(feePerByte)

	return feePerByte
}

// checkSufficientFee take a set of signed transactions and verifies that each transaction has
// sufficient fee to get into the transaction pool
func (pool *TransactionPool) checkSufficientFee(txgroup []transactions.SignedTxn) error {
	// Special case: the state proof transaction, if issued from the
	// special state-proof-sender address, in a singleton group, pays
	// no fee.
	if len(txgroup) == 1 {
		t := txgroup[0].Txn
		if t.Type == protocol.StateProofTx && t.Sender == transactions.StateProofSender && t.Fee.IsZero() {
			return nil
		}
	}

	// get the current fee per byte
	feePerByte := pool.computeFeePerByte()

	for _, t := range txgroup {
		feeThreshold := feePerByte * uint64(t.GetEncodedLength())
		if t.Txn.Fee.Raw < feeThreshold {
			return &ErrTxPoolFeeError{
				fee:           t.Txn.Fee,
				feeThreshold:  feeThreshold,
				feePerByte:    feePerByte,
				encodedLength: t.GetEncodedLength(),
			}
		}
	}

	return nil
}

// Test performs basic duplicate detection and well-formedness checks
// on a transaction group without storing the group.
func (pool *TransactionPool) Test(txgroup []transactions.SignedTxn) error {
	if err := pool.checkPendingQueueSize(txgroup); err != nil {
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
func (pool *TransactionPool) remember(txgroup []transactions.SignedTxn) error {
	params := poolIngestParams{
		recomputing: false,
	}
	return pool.ingest(txgroup, params)
}

// add tries to add the transaction group to the pool, bypassing the fee
// priority checks.
func (pool *TransactionPool) add(txgroup []transactions.SignedTxn, stats *telemetryspec.AssembleBlockMetrics) error {
	params := poolIngestParams{
		recomputing: true,
		stats:       stats,
	}
	return pool.ingest(txgroup, params)
}

// ingest checks whether a transaction group could be remembered in the pool,
// and stores this transaction if valid.
//
// ingest assumes that pool.mu is locked.  It might release the lock
// while it waits for OnNewBlock() to be called.
func (pool *TransactionPool) ingest(txgroup []transactions.SignedTxn, params poolIngestParams) error {
	if pool.pendingBlockEvaluator == nil {
		return ErrNoPendingBlockEvaluator
	}

	if pool.shutdown {
		return errPoolShutdown
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
				return ErrNoPendingBlockEvaluator
			}
			// recheck if the pool is shutting down since TimedWait above releases the lock
			if pool.shutdown {
				return errPoolShutdown
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
	for _, t := range txgroup {
		pool.rememberedTxids[t.ID()] = t
	}
	return nil
}

// RememberOne stores the provided transaction.
// Precondition: Only RememberOne() properly-signed and well-formed transactions (i.e., ensure t.WellFormed())
func (pool *TransactionPool) RememberOne(t transactions.SignedTxn) error {
	return pool.Remember([]transactions.SignedTxn{t})
}

// Remember stores the provided transaction group.
// Precondition: Only Remember() properly-signed and well-formed transactions (i.e., ensure t.WellFormed())
func (pool *TransactionPool) Remember(txgroup []transactions.SignedTxn) error {
	if err := pool.checkPendingQueueSize(txgroup); err != nil {
		return err
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	err := pool.remember(txgroup)
	if err != nil {
		return fmt.Errorf("TransactionPool.Remember: %w", err)
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

	tx, inPool := pool.pendingTxids[txid]
	if inPool {
		return tx, "", true
	}

	return pool.statusCache.check(txid)
}

// OnNewBlock excises transactions from the pool that are included in the specified Block or if they've expired
func (pool *TransactionPool) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	var stats telemetryspec.ProcessBlockMetrics
	var knownCommitted uint
	var unknownCommitted uint

	committedTxids := delta.Txids
	if pool.logProcessBlockStats {
		pool.pendingMu.RLock()
		for txid := range committedTxids {
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
	if pool.shutdown {
		return
	}

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
		stats = pool.recomputeBlockEvaluator(committedTxids, knownCommitted)
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
		pool.log.Metrics(telemetryspec.Transaction, stats, details)
	}
}

// isAssemblyTimedOut determines if we should keep attempting complete the block assembly by adding more transactions to the pending evaluator,
// or whether we've ran out of time. It takes into consideration the assemblyDeadline that was set by the AssembleBlock function as well as the
// projected time it's going to take to call the GenerateBlock function before the block assembly would be ready.
// The function expects that the pool.assemblyMu lock would be taken before being called.
func (pool *TransactionPool) isAssemblyTimedOut() bool {
	if pool.assemblyDeadline.IsZero() {
		// we have no deadline, so no reason to timeout.
		return false
	}
	generateBlockDuration := generateBlockBaseDuration + time.Duration(pool.pendingBlockEvaluator.PaySetSize())*generateBlockTransactionDuration
	return time.Now().After(pool.assemblyDeadline.Add(-generateBlockDuration))
}

func (pool *TransactionPool) addToPendingBlockEvaluatorOnce(txgroup []transactions.SignedTxn, recomputing bool, stats *telemetryspec.AssembleBlockMetrics) error {
	r := pool.pendingBlockEvaluator.Round() + pool.numPendingWholeBlocks
	for _, tx := range txgroup {
		if tx.Txn.LastValid < r {
			return &bookkeeping.TxnDeadError{
				Round:      r,
				FirstValid: tx.Txn.FirstValid,
				LastValid:  tx.Txn.LastValid,
				Early:      false,
			}
		}
	}

	txgroupad := transactions.WrapSignedTxnsWithAD(txgroup)

	transactionGroupStartsTime := time.Time{}
	if recomputing {
		transactionGroupStartsTime = time.Now()
	}

	err := pool.pendingBlockEvaluator.TransactionGroup(txgroupad)

	if recomputing {
		if !pool.assemblyResults.assemblyCompletedOrAbandoned {
			transactionGroupDuration := time.Since(transactionGroupStartsTime)
			pool.assemblyMu.Lock()
			defer pool.assemblyMu.Unlock()
			if evalRnd := pool.pendingBlockEvaluator.Round(); pool.assemblyRound > evalRnd {
				// the block we're assembling now isn't the one the the AssembleBlock is waiting for. While it would be really cool
				// to finish generating the block, it would also be pointless to spend time on it.
				// we're going to set the ok and assemblyCompletedOrAbandoned to "true" so we can complete this loop asap
				pool.assemblyResults.ok = true
				pool.assemblyResults.assemblyCompletedOrAbandoned = true
				stats.StopReason = telemetryspec.AssembleBlockAbandon
				pool.assemblyResults.stats = *stats
				pool.assemblyCond.Broadcast()
			} else if err == ledgercore.ErrNoSpace || pool.isAssemblyTimedOut() {
				pool.assemblyResults.ok = true
				pool.assemblyResults.assemblyCompletedOrAbandoned = true
				if err == ledgercore.ErrNoSpace {
					stats.StopReason = telemetryspec.AssembleBlockFull
				} else {
					stats.StopReason = telemetryspec.AssembleBlockTimeout
					// if the block is not full, it means that the above transaction made it to the block, so we want to add it here.
					stats.ProcessingTime.AddTransaction(transactionGroupDuration)
				}

				blockGenerationStarts := time.Now()
				lvb, gerr := pool.pendingBlockEvaluator.GenerateBlock(pool.getVotingAccountsForRound(evalRnd))
				if gerr != nil {
					pool.assemblyResults.err = fmt.Errorf("could not generate block for %d: %v", pool.assemblyResults.roundStartedEvaluating, gerr)
				} else {
					pool.assemblyResults.blk = lvb
				}
				stats.BlockGenerationDuration = uint64(time.Since(blockGenerationStarts))
				pool.assemblyResults.stats = *stats
				pool.assemblyCond.Broadcast()
			} else {
				// add the transaction time only if we didn't ended up finishing the block.
				stats.ProcessingTime.AddTransaction(transactionGroupDuration)
			}
		}
	}
	return err
}

func (pool *TransactionPool) addToPendingBlockEvaluator(txgroup []transactions.SignedTxn, recomputing bool, stats *telemetryspec.AssembleBlockMetrics) error {
	err := pool.addToPendingBlockEvaluatorOnce(txgroup, recomputing, stats)
	if err == ledgercore.ErrNoSpace {
		pool.numPendingWholeBlocks++
		pool.pendingBlockEvaluator.ResetTxnBytes()
		err = pool.addToPendingBlockEvaluatorOnce(txgroup, recomputing, stats)
	}
	return err
}

// recomputeBlockEvaluator constructs a new BlockEvaluator and feeds all
// in-pool transactions to it (removing any transactions that are rejected
// by the BlockEvaluator). Expects that the pool.mu mutex would be already taken.
func (pool *TransactionPool) recomputeBlockEvaluator(committedTxIDs map[transactions.Txid]ledgercore.IncludedTransactions, knownCommitted uint) (stats telemetryspec.ProcessBlockMetrics) {
	pool.pendingBlockEvaluator = nil

	latest := pool.ledger.Latest()
	prev, err := pool.ledger.BlockHdr(latest)
	if err != nil {
		pool.log.Warnf("TransactionPool.recomputeBlockEvaluator: cannot get prev header for %d: %v",
			latest, err)
		return
	}

	// Process upgrade to see if we support the next protocol version
	_, upgradeState, err := bookkeeping.ProcessUpgradeParams(prev)
	if err != nil {
		pool.log.Warnf("TransactionPool.recomputeBlockEvaluator: error processing upgrade params for next round: %v", err)
		return
	}

	// Ensure we know about the next protocol version (MakeBlock will panic
	// if we don't, and we would rather stall locally than panic)
	_, ok := config.Consensus[upgradeState.CurrentProtocol]
	if !ok {
		pool.log.Warnf("TransactionPool.recomputeBlockEvaluator: next protocol version %v is not supported", upgradeState.CurrentProtocol)
		return
	}

	// Grab the transactions to be played through the new block evaluator
	pool.pendingMu.RLock()
	txgroups := pool.pendingTxGroups
	pendingCount := pool.pendingCountNoLock()
	pool.pendingMu.RUnlock()

	pool.assemblyMu.Lock()
	pool.assemblyResults = poolAsmResults{
		roundStartedEvaluating: prev.Round + basics.Round(1),
	}
	pool.assemblyMu.Unlock()

	next := bookkeeping.MakeBlock(prev)
	pool.numPendingWholeBlocks = 0
	hint := pendingCount - int(knownCommitted)
	if hint < 0 || int(knownCommitted) < 0 {
		hint = 0
	}
	pool.pendingBlockEvaluator, err = pool.ledger.StartEvaluator(next.BlockHeader, hint, 0, pool.evalTracer)
	if err != nil {
		// The pendingBlockEvaluator is an interface, and in case of an evaluator error
		// we want to remove the interface itself rather then keeping an interface
		// to a nil.
		pool.pendingBlockEvaluator = nil
		var nonSeqBlockEval ledgercore.ErrNonSequentialBlockEval
		if errors.As(err, &nonSeqBlockEval) {
			if nonSeqBlockEval.EvaluatorRound <= nonSeqBlockEval.LatestRound {
				pool.log.Infof("TransactionPool.recomputeBlockEvaluator: skipped creating block evaluator for round %d since ledger already caught up with that round", nonSeqBlockEval.EvaluatorRound)
				return
			}
		}
		pool.log.Warnf("TransactionPool.recomputeBlockEvaluator: cannot start evaluator: %v", err)
		return
	}

	var asmStats telemetryspec.AssembleBlockMetrics
	asmStats.StartCount = len(txgroups)
	asmStats.StopReason = telemetryspec.AssembleBlockEmpty

	firstTxnGrpTime := time.Now()

	// Feed the transactions in order
	for _, txgroup := range txgroups {
		if len(txgroup) == 0 {
			asmStats.InvalidCount++
			continue
		}
		if _, alreadyCommitted := committedTxIDs[txgroup[0].ID()]; alreadyCommitted {
			asmStats.EarlyCommittedCount++
			continue
		}
		err := pool.add(txgroup, &asmStats)
		if err != nil {
			for _, tx := range txgroup {
				pool.statusCache.put(tx, err.Error())
			}
			// metrics here are duplicated for historic reasons. stats is hardly used and should be removed in favor of asmstats
			switch terr := err.(type) {
			case *ledgercore.TransactionInLedgerError:
				asmStats.CommittedCount++
				stats.RemovedInvalidCount++
			case *bookkeeping.TxnDeadError:
				if int(terr.LastValid-terr.FirstValid) > 20 {
					// cutoff value  here is picked as a somewhat arbitrary cutoff trying to separate longer lived transactions from very short lived ones
					asmStats.ExpiredLongLivedCount++
				}
				asmStats.ExpiredCount++
				stats.ExpiredCount++
			case *ledgercore.LeaseInLedgerError:
				asmStats.LeaseErrorCount++
				stats.RemovedInvalidCount++
				pool.log.Infof("Pending transaction in pool no longer valid: %v", err)
			case *transactions.MinFeeError:
				asmStats.MinFeeErrorCount++
				stats.RemovedInvalidCount++
				pool.log.Infof("Pending transaction in pool no longer valid: %v", err)
			case logic.EvalError:
				asmStats.LogicErrorCount++
				stats.RemovedInvalidCount++
				pool.log.Infof("Pending transaction in pool no longer valid: %v", err)
			default:
				asmStats.InvalidCount++
				stats.RemovedInvalidCount++
				pool.log.Infof("Pending transaction in pool no longer valid: %v", err)
			}
		}
	}

	pool.assemblyMu.Lock()
	if !pool.assemblyDeadline.IsZero() {
		// The deadline was set by node, allocating ProposalAssemblyTime milliseconds for completing proposal
		// assembly. We want to figure out how long have we spent before trying to evaluate the first transaction.
		// ( ideally it's near zero. The goal here is to see if we get to a near time-out situation before processing the
		// first transaction group )
		asmStats.TransactionsLoopStartTime = int64(firstTxnGrpTime.Sub(pool.assemblyDeadline.Add(-pool.proposalAssemblyTime)))
	}

	if evalRnd := pool.pendingBlockEvaluator.Round(); !pool.assemblyResults.ok && pool.assemblyRound <= evalRnd {
		pool.assemblyResults.ok = true
		pool.assemblyResults.assemblyCompletedOrAbandoned = true // this is not strictly needed, since the value would only get inspected by this go-routine, but we'll adjust it along with "ok" for consistency
		blockGenerationStarts := time.Now()
		lvb, err := pool.pendingBlockEvaluator.GenerateBlock(pool.getVotingAccountsForRound(evalRnd))
		if err != nil {
			pool.assemblyResults.err = fmt.Errorf("could not generate block for %d (end): %v", pool.assemblyResults.roundStartedEvaluating, err)
		} else {
			pool.assemblyResults.blk = lvb
		}
		asmStats.BlockGenerationDuration = uint64(time.Since(blockGenerationStarts))
		pool.assemblyResults.stats = asmStats
		pool.assemblyCond.Broadcast()
	}
	pool.assemblyMu.Unlock()

	pool.rememberCommit(true)
	return
}

func (pool *TransactionPool) getStateProofStats(txib *transactions.SignedTxnInBlock, encodedLen int) telemetryspec.StateProofStats {
	stateProofStats := telemetryspec.StateProofStats{
		ProvenWeight:   0,
		SignedWeight:   txib.Txn.StateProofTxnFields.StateProof.SignedWeight,
		NumReveals:     len(txib.Txn.StateProofTxnFields.StateProof.Reveals),
		NumPosToReveal: len(txib.Txn.StateProofTxnFields.StateProof.PositionsToReveal),
		TxnSize:        encodedLen,
	}

	lastSPRound := basics.Round(txib.Txn.StateProofTxnFields.Message.LastAttestedRound)
	verificationCtx, err := pool.ledger.GetStateProofVerificationContext(lastSPRound)
	if err != nil {
		return stateProofStats
	}

	totalWeight := verificationCtx.OnlineTotalWeight.Raw
	stateProofStats.ProvenWeight, _ = basics.Muldiv(totalWeight, uint64(config.Consensus[verificationCtx.Version].StateProofWeightThreshold), 1<<32)
	return stateProofStats
}

// AssembleBlock assembles a block for a given round, trying not to
// take longer than deadline to finish.
func (pool *TransactionPool) AssembleBlock(round basics.Round, deadline time.Time) (assembled *ledgercore.UnfinishedBlock, err error) {
	var stats telemetryspec.AssembleBlockMetrics

	if pool.logAssembleStats {
		start := time.Now()
		defer func() {
			if err != nil {
				return
			}

			// Measure time here because we want to know how close to deadline we are
			dt := time.Since(start)
			stats.Nanoseconds = dt.Nanoseconds()

			payset := assembled.UnfinishedBlock().Payset
			if len(payset) != 0 {
				totalFees := uint64(0)

				for i, txib := range payset {
					fee := txib.Txn.Fee.Raw
					encodedLen := txib.GetEncodedLength()

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
					if txib.Txn.Type == protocol.StateProofTx {
						stats.StateProofStats = pool.getStateProofStats(&payset[i], encodedLen)
					}
				}
				stats.AverageFee = totalFees / uint64(stats.IncludedCount)
			}
			stats.StateProofNextRound = uint64(assembled.UnfinishedBlock().StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
			var details struct {
				Round uint64
			}
			details.Round = uint64(round)
			pool.log.Metrics(telemetryspec.Transaction, stats, details)
		}()
	}

	pool.assemblyMu.Lock()

	// if the transaction pool is more than two rounds behind, we don't want to wait.
	if pool.assemblyResults.roundStartedEvaluating <= round.SubSaturate(2) {
		pool.log.Infof("AssembleBlock: requested round is more than a single round ahead of the transaction pool %d <= %d-2", pool.assemblyResults.roundStartedEvaluating, round)
		stats.StopReason = telemetryspec.AssembleBlockPoolBehind
		pool.assemblyMu.Unlock()
		return pool.assembleEmptyBlock(round)
	}

	defer pool.assemblyMu.Unlock()

	if pool.assemblyResults.roundStartedEvaluating > round {
		// we've already assembled a round in the future. Since we're clearly won't go backward, it means
		// that the agreement is far behind us, so we're going to return here with error code to let
		// the agreement know about it.
		// since the network is already ahead of us, there is no issue here in not generating a block ( since the block would get discarded anyway )
		pool.log.Infof("AssembleBlock: requested round is behind transaction pool round %d < %d", round, pool.assemblyResults.roundStartedEvaluating)
		return nil, ErrStaleBlockAssemblyRequest
	}

	pool.assemblyDeadline = deadline
	pool.assemblyRound = round

	for time.Now().Before(deadline) && (!pool.assemblyResults.ok || pool.assemblyResults.roundStartedEvaluating != round) {
		condvar.TimedWait(&pool.assemblyCond, time.Until(deadline))
	}

	if !pool.assemblyResults.ok {
		// we've passed the deadline, so we're either going to have a partial block, or that we won't make it on time.
		// start preparing an empty block in case we'll miss the extra time (assemblyWaitEps).
		// the assembleEmptyBlock is using the database, so we want to unlock here and take the lock again later on.
		pool.assemblyMu.Unlock()
		emptyBlock, emptyBlockErr := pool.assembleEmptyBlock(round)
		pool.assemblyMu.Lock()

		if pool.assemblyResults.roundStartedEvaluating > round {
			// this case is expected to happen only if the transaction pool was able to construct *two* rounds during the time we were trying to assemble the empty block.
			// while this is extremely unlikely, we need to handle this. the handling it quite straight-forward :
			// since the network is already ahead of us, there is no issue here in not generating a block ( since the block would get discarded anyway )
			pool.log.Infof("AssembleBlock: requested round is behind transaction pool round after timing out %d < %d", round, pool.assemblyResults.roundStartedEvaluating)
			return nil, ErrStaleBlockAssemblyRequest
		}

		deadline = deadline.Add(assemblyWaitEps)
		for time.Now().Before(deadline) && (!pool.assemblyResults.ok || pool.assemblyResults.roundStartedEvaluating != round) {
			condvar.TimedWait(&pool.assemblyCond, time.Until(deadline))
		}

		// check to see if the extra time helped us to get a block.
		if !pool.assemblyResults.ok {
			// it didn't. Lucky us - we already prepared an empty block, so we can return this right now.
			pool.log.Warnf("AssembleBlock: ran out of time for round %d", round)
			stats.StopReason = telemetryspec.AssembleBlockTimeoutEmpty
			if emptyBlockErr != nil {
				emptyBlockErr = fmt.Errorf("AssembleBlock: failed to construct empty block : %w", emptyBlockErr)
			}
			return emptyBlock, emptyBlockErr
		}
	}
	pool.assemblyDeadline = time.Time{}

	if pool.assemblyResults.err != nil {
		return nil, fmt.Errorf("AssemblyBlock: encountered error for round %d: %v", round, pool.assemblyResults.err)
	}
	if pool.assemblyResults.roundStartedEvaluating > round {
		// this scenario should not happen unless the txpool is receiving the new blocks via OnNewBlock
		// with "jumps" between consecutive blocks ( which is why it's a warning )
		// The "normal" use case is evaluated on the top of the function.
		pool.log.Warnf("AssembleBlock: requested round is behind transaction pool round %d < %d", round, pool.assemblyResults.roundStartedEvaluating)
		return nil, ErrStaleBlockAssemblyRequest
	} else if pool.assemblyResults.roundStartedEvaluating == round.SubSaturate(1) {
		pool.log.Warnf("AssembleBlock: assembled block round did not catch up to requested round: %d != %d", pool.assemblyResults.roundStartedEvaluating, round)
		stats.StopReason = telemetryspec.AssembleBlockEvalOld
		return pool.assembleEmptyBlock(round)
	} else if pool.assemblyResults.roundStartedEvaluating < round {
		return nil, fmt.Errorf("AssembleBlock: assembled block round much behind requested round: %d != %d",
			pool.assemblyResults.roundStartedEvaluating, round)
	}

	stats = pool.assemblyResults.stats
	return pool.assemblyResults.blk, nil
}

// assembleEmptyBlock construct a new block for the given round. Internally it's using the ledger database calls, so callers
// need to be aware that it might take a while before it would return.
func (pool *TransactionPool) assembleEmptyBlock(round basics.Round) (assembled *ledgercore.UnfinishedBlock, err error) {
	prevRound := round - 1
	prev, err := pool.ledger.BlockHdr(prevRound)
	if err != nil {
		err = fmt.Errorf("TransactionPool.assembleEmptyBlock: cannot get prev header for %d: %v", prevRound, err)
		return nil, err
	}
	next := bookkeeping.MakeBlock(prev)
	blockEval, err := pool.ledger.StartEvaluator(next.BlockHeader, 0, 0, nil)
	if err != nil {
		var nonSeqBlockEval ledgercore.ErrNonSequentialBlockEval
		if errors.As(err, &nonSeqBlockEval) {
			if nonSeqBlockEval.EvaluatorRound <= nonSeqBlockEval.LatestRound {
				// in the case that the ledger have already moved beyond that round, just let the agreement know that
				// we don't generate a block and it's perfectly fine.
				return nil, ErrStaleBlockAssemblyRequest
			}
		}
		err = fmt.Errorf("TransactionPool.assembleEmptyBlock: cannot start evaluator for %d: %w", round, err)
		return nil, err
	}
	return blockEval.GenerateBlock(pool.getVotingAccountsForRound(round))
}

// AssembleDevModeBlock assemble a new block from the existing transaction pool. The pending evaluator is being
func (pool *TransactionPool) AssembleDevModeBlock() (assembled *ledgercore.UnfinishedBlock, err error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// drop the current block evaluator and start with a new one.
	pool.recomputeBlockEvaluator(nil, 0)

	// The above was already pregenerating the entire block,
	// so there won't be any waiting on this call.
	assembled, err = pool.AssembleBlock(pool.pendingBlockEvaluator.Round(), time.Now().Add(pool.proposalAssemblyTime))
	return
}

// Shutdown stops the transaction pool from accepting new transactions and blocks.
// It takes the pool.mu lock in order to ensure there is no pending remember or block operations in flight
// and sets the shutdown flag to true.
func (pool *TransactionPool) Shutdown() {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.shutdown = true
}
