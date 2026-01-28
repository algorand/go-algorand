// Copyright (C) 2019-2026 Algorand, Inc.
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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/util/metrics"
)

// ErrStaleBlockAssemblyRequest returned by AssembleBlock when requested block number is older than the current transaction pool round
// i.e. typically it means that we're trying to make a proposal for an older round than what the ledger is currently pointing at.
var ErrStaleBlockAssemblyRequest = errors.New("AssembleBlock: requested block assembly specified a round that is older than current transaction pool round")

// ErrPendingQueueReachedMaxCap indicates the current transaction pool has reached its max capacity
var ErrPendingQueueReachedMaxCap = errors.New("TransactionPool.checkPendingQueueSize: transaction pool has reached capacity")

// ErrNoPendingBlockEvaluator indicates there is no pending block evaluator to accept a new tx group
var ErrNoPendingBlockEvaluator = errors.New("TransactionPool.ingest: no pending block evaluator")

// ErrTxPoolFeeError is an error type for txpool fee escalation checks
type ErrTxPoolFeeError struct {
	fee           basics.MicroAlgos
	feeThreshold  uint64
	feePerByte    uint64
	encodedLength int
}

func (e *ErrTxPoolFeeError) Error() string {
	return fmt.Sprintf("fee %d below threshold %d (%d per byte * %d bytes)",
		e.fee, e.feeThreshold, e.feePerByte, e.encodedLength)
}

// TxPoolErrorTag constants for categorizing transaction pool errors.
// These are used by both the txHandler (initial remember) and the
// transaction pool (re-evaluation) to classify errors consistently.
const (
	TxPoolErrTagCap          = "cap"
	TxPoolErrTagPendingEval  = "pending_eval"
	TxPoolErrTagNoSpace      = "no_space"
	TxPoolErrTagFee          = "fee"
	TxPoolErrTagTxnDead      = "txn_dead"
	TxPoolErrTagTxnEarly     = "txn_early"
	TxPoolErrTagTooLarge     = "too_large"
	TxPoolErrTagGroupID      = "groupid"
	TxPoolErrTagTxID         = "txid"
	TxPoolErrTagLease        = "lease"
	TxPoolErrTagTxIDEval     = "txid_eval"
	TxPoolErrTagLeaseEval    = "lease_eval"
	TxPoolErrTagNotWell      = "not_well"    // TxnNotWellFormedError - malformed transaction
	TxPoolErrTagTealErr      = "teal_err"    // TEAL runtime error (logic.EvalError)
	TxPoolErrTagTealReject   = "teal_reject" // TEAL returned false ("rejected by ApprovalProgram")
	TxPoolErrTagMinBalance   = "min_balance" // Account balance below minimum
	TxPoolErrTagOverspend    = "overspend"   // Insufficient Algo funds
	TxPoolErrTagAssetBalance = "asset_bal"   // Insufficient asset balance
	TxPoolErrTagEvalGeneric  = "eval"        // Other evaluation errors not matching known patterns
)

// TxPoolErrTags is the list of all error tags for use with TagCounter.
var TxPoolErrTags = []string{
	TxPoolErrTagCap, TxPoolErrTagPendingEval, TxPoolErrTagNoSpace, TxPoolErrTagFee,
	TxPoolErrTagTxnDead, TxPoolErrTagTxnEarly, TxPoolErrTagTooLarge, TxPoolErrTagGroupID,
	TxPoolErrTagTxID, TxPoolErrTagLease, TxPoolErrTagTxIDEval, TxPoolErrTagLeaseEval,
	TxPoolErrTagNotWell, TxPoolErrTagTealErr, TxPoolErrTagTealReject,
	TxPoolErrTagMinBalance, TxPoolErrTagOverspend, TxPoolErrTagAssetBalance, TxPoolErrTagEvalGeneric,
}

// txPoolReevalCounter tracks transaction groups that failed during block assembly
// re-evaluation. These are transactions that were accepted into the pool but
// failed when re-evaluated against the latest confirmed block.
var txPoolReevalCounter = metrics.NewTagCounter(
	"algod_tx_pool_reeval_{TAG}",
	"Number of transaction groups removed from pool during re-evaluation due to {TAG}",
	TxPoolErrTags...,
)

// txPoolReevalSuccess tracks transaction groups successfully re-evaluated
// after a new block commits.
var txPoolReevalSuccess = metrics.MakeCounter(metrics.MetricName{
	Name:        "algod_tx_pool_reeval_success",
	Description: "Number of transaction groups successfully re-evaluated after new block",
})

// txPoolReevalCommitted tracks transaction groups removed during re-evaluation
// because they were already committed in the latest block.
var txPoolReevalCommitted = metrics.MakeCounter(metrics.MetricName{
	Name:        "algod_tx_pool_reeval_committed",
	Description: "Number of transaction groups removed because already committed in latest block",
})

// ClassifyTxPoolError examines an error from BlockEvaluator.TransactionGroup
// and returns the appropriate tag for metrics. Both errors.Is (for sentinel
// errors) and errors.As (for typed errors) traverse wrapped error chains.
func ClassifyTxPoolError(err error) string {
	if err == nil {
		return ""
	}

	// Sentinel errors (specific values)
	if errors.Is(err, ErrPendingQueueReachedMaxCap) {
		return TxPoolErrTagCap
	}
	if errors.Is(err, ErrNoPendingBlockEvaluator) {
		return TxPoolErrTagPendingEval
	}
	if errors.Is(err, ledgercore.ErrNoSpace) {
		return TxPoolErrTagNoSpace
	}

	// Typed errors
	var feeErr *ErrTxPoolFeeError
	if errors.As(err, &feeErr) {
		return TxPoolErrTagFee
	}

	var minFeeErr *transactions.MinFeeError
	if errors.As(err, &minFeeErr) {
		return TxPoolErrTagFee
	}

	var deadErr *bookkeeping.TxnDeadError
	if errors.As(err, &deadErr) {
		if deadErr.Early {
			return TxPoolErrTagTxnEarly
		}
		return TxPoolErrTagTxnDead
	}

	var txInLedgerErr *ledgercore.TransactionInLedgerError
	if errors.As(err, &txInLedgerErr) {
		if txInLedgerErr.InBlockEvaluator {
			return TxPoolErrTagTxIDEval
		}
		return TxPoolErrTagTxID
	}

	var leaseErr *ledgercore.LeaseInLedgerError
	if errors.As(err, &leaseErr) {
		if leaseErr.InBlockEvaluator {
			return TxPoolErrTagLeaseEval
		}
		return TxPoolErrTagLease
	}

	var groupErr *ledgercore.TxGroupMalformedError
	if errors.As(err, &groupErr) {
		if groupErr.Reason == ledgercore.TxGroupMalformedErrorReasonExceedMaxSize {
			return TxPoolErrTagTooLarge
		}
		return TxPoolErrTagGroupID
	}

	var notWellErr *ledgercore.TxnNotWellFormedError
	if errors.As(err, &notWellErr) {
		return TxPoolErrTagNotWell
	}

	var overspendErr *ledgercore.OverspendError
	if errors.As(err, &overspendErr) {
		return TxPoolErrTagOverspend
	}

	var minBalErr *ledgercore.MinBalanceError
	if errors.As(err, &minBalErr) {
		return TxPoolErrTagMinBalance
	}

	var assetBalErr *ledgercore.AssetBalanceError
	if errors.As(err, &assetBalErr) {
		return TxPoolErrTagAssetBalance
	}

	var approvalErr *ledgercore.ApprovalProgramRejectedError
	if errors.As(err, &approvalErr) {
		return TxPoolErrTagTealReject
	}

	var evalErr logic.EvalError
	if errors.As(err, &evalErr) {
		return TxPoolErrTagTealErr
	}

	return TxPoolErrTagEvalGeneric
}
