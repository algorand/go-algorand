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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/util/metrics"
)

func TestClassifyTxPoolErrorGeneralCoverage(t *testing.T) {
	// Table mirrors the distinct branches inside ClassifyTxPoolError/classifyUnwrappedError.
	tcases := []struct {
		name string
		err  error
		tag  string
		wrap bool
	}{
		{name: "cap", err: ErrPendingQueueReachedMaxCap, tag: TxPoolErrTagCap},
		{name: "cap_wrapped", err: ErrPendingQueueReachedMaxCap, tag: TxPoolErrTagCap, wrap: true},
		{name: "pending_eval", err: ErrNoPendingBlockEvaluator, tag: TxPoolErrTagPendingEval},
		{name: "pending_eval_wrapped", err: ErrNoPendingBlockEvaluator, tag: TxPoolErrTagPendingEval, wrap: true},
		{name: "no_space", err: ledgercore.ErrNoSpace, tag: TxPoolErrTagNoSpace},
		{name: "no_space_wrapped", err: ledgercore.ErrNoSpace, tag: TxPoolErrTagNoSpace, wrap: true},
		{name: "fee_escalation", err: &ErrTxPoolFeeError{}, tag: TxPoolErrTagFee},
		{name: "fee_escalation_wrapped", err: &ErrTxPoolFeeError{}, tag: TxPoolErrTagFee, wrap: true},
		{name: "fee_min_fee", err: func() error { e := transactions.MinFeeError("min"); return &e }(), tag: TxPoolErrTagFee},
		{name: "fee_min_fee_wrapped", err: func() error { e := transactions.MinFeeError("min"); return &e }(), tag: TxPoolErrTagFee, wrap: true},
		{name: "txn_dead", err: &bookkeeping.TxnDeadError{}, tag: TxPoolErrTagTxnDead},
		{name: "txn_dead_wrapped", err: &bookkeeping.TxnDeadError{}, tag: TxPoolErrTagTxnDead, wrap: true},
		{name: "txn_early", err: &bookkeeping.TxnDeadError{Early: true}, tag: TxPoolErrTagTxnEarly},
		{name: "txn_early_wrapped", err: &bookkeeping.TxnDeadError{Early: true}, tag: TxPoolErrTagTxnEarly, wrap: true},
		{name: "txid_ledger", err: &ledgercore.TransactionInLedgerError{InBlockEvaluator: false}, tag: TxPoolErrTagTxID},
		{name: "txid_ledger_wrapped", err: &ledgercore.TransactionInLedgerError{InBlockEvaluator: false}, tag: TxPoolErrTagTxID, wrap: true},
		{name: "txid_eval", err: &ledgercore.TransactionInLedgerError{InBlockEvaluator: true}, tag: TxPoolErrTagTxIDEval},
		{name: "txid_eval_wrapped", err: &ledgercore.TransactionInLedgerError{InBlockEvaluator: true}, tag: TxPoolErrTagTxIDEval, wrap: true},
		{name: "lease_ledger", err: ledgercore.MakeLeaseInLedgerError(transactions.Txid{}, ledgercore.Txlease{Lease: [32]byte{1}}, false), tag: TxPoolErrTagLease},
		{name: "lease_ledger_wrapped", err: ledgercore.MakeLeaseInLedgerError(transactions.Txid{}, ledgercore.Txlease{Lease: [32]byte{1}}, false), tag: TxPoolErrTagLease, wrap: true},
		{name: "lease_eval", err: ledgercore.MakeLeaseInLedgerError(transactions.Txid{}, ledgercore.Txlease{Lease: [32]byte{2}}, true), tag: TxPoolErrTagLeaseEval},
		{name: "lease_eval_wrapped", err: ledgercore.MakeLeaseInLedgerError(transactions.Txid{}, ledgercore.Txlease{Lease: [32]byte{2}}, true), tag: TxPoolErrTagLeaseEval, wrap: true},
		{name: "group_too_large", err: &ledgercore.TxGroupMalformedError{Reason: ledgercore.TxGroupMalformedErrorReasonExceedMaxSize}, tag: TxPoolErrTagTooLarge},
		{name: "group_too_large_wrapped", err: &ledgercore.TxGroupMalformedError{Reason: ledgercore.TxGroupMalformedErrorReasonExceedMaxSize}, tag: TxPoolErrTagTooLarge, wrap: true},
		{name: "group_other", err: &ledgercore.TxGroupMalformedError{Reason: ledgercore.TxGroupMalformedErrorReasonGeneric}, tag: TxPoolErrTagGroupID},
		{name: "group_other_wrapped", err: &ledgercore.TxGroupMalformedError{Reason: ledgercore.TxGroupMalformedErrorReasonGeneric}, tag: TxPoolErrTagGroupID, wrap: true},
		{name: "logic_eval", err: logic.EvalError{Err: errors.New("logic")}, tag: TxPoolErrTagEvalGeneric},
		{name: "logic_eval_wrapped", err: logic.EvalError{Err: errors.New("logic")}, tag: TxPoolErrTagEvalGeneric, wrap: true},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.err
			if tc.wrap {
				err = fmt.Errorf("wrap: %w", err)
			}
			require.Equal(t, tc.tag, ClassifyTxPoolError(err))
		})
	}
}

func TestTxPoolReevalCounterCoversReevalTags(t *testing.T) {
	// Re-eval counter should only record tags from TxPoolReevalErrTags even when classification sees various errors.
	reevalCases := []struct {
		name string
		err  error
		tag  string
	}{
		{name: "fee", err: &ErrTxPoolFeeError{}, tag: TxPoolErrTagFee},
		{name: "txn_dead", err: &bookkeeping.TxnDeadError{}, tag: TxPoolErrTagTxnDead},
		{name: "too_large", err: &ledgercore.TxGroupMalformedError{Reason: ledgercore.TxGroupMalformedErrorReasonExceedMaxSize}, tag: TxPoolErrTagTooLarge},
		{name: "groupid", err: &ledgercore.TxGroupMalformedError{Reason: ledgercore.TxGroupMalformedErrorReasonInconsistentGroupID}, tag: TxPoolErrTagGroupID},
		{name: "txid", err: &ledgercore.TransactionInLedgerError{Txid: transactions.Txid{}, InBlockEvaluator: false}, tag: TxPoolErrTagTxID},
		{name: "txid_eval", err: &ledgercore.TransactionInLedgerError{Txid: transactions.Txid{}, InBlockEvaluator: true}, tag: TxPoolErrTagTxIDEval},
		{name: "lease", err: ledgercore.MakeLeaseInLedgerError(transactions.Txid{}, ledgercore.Txlease{Sender: basics.Address{}, Lease: [32]byte{3}}, false), tag: TxPoolErrTagLease},
		{name: "lease_eval", err: ledgercore.MakeLeaseInLedgerError(transactions.Txid{}, ledgercore.Txlease{Sender: basics.Address{}, Lease: [32]byte{4}}, true), tag: TxPoolErrTagLeaseEval},
		{name: "no_space", err: ledgercore.ErrNoSpace, tag: TxPoolErrTagNoSpace},
		{name: "eval", err: logic.EvalError{Err: errors.New("logic")}, tag: TxPoolErrTagEvalGeneric},
	}

	orig := txPoolReevalCounter
	txPoolReevalCounter = metrics.NewTagCounter(
		"algod_tx_pool_reeval_{TAG}",
		"Number of transaction groups removed from pool during re-evaluation due to {TAG}",
		TxPoolReevalErrTags...,
	)
	t.Cleanup(func() { txPoolReevalCounter = orig })

	for _, tc := range reevalCases {
		t.Run(tc.name, func(t *testing.T) {
			tag := ClassifyTxPoolError(tc.err)
			require.Equal(t, tc.tag, tag)
			require.Contains(t, TxPoolReevalErrTags, tag)
			txPoolReevalCounter.Add(tag, 1)
		})
	}

	metricsMap := map[string]float64{}
	txPoolReevalCounter.AddMetric(metricsMap)
	for _, tc := range reevalCases {
		require.Equal(t, float64(1), metricsMap["algod_tx_pool_reeval_"+tc.tag])
	}
}
