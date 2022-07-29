// Copyright (C) 2019-2022 Algorand, Inc.
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

package ledger

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/internal"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// DebuggerLedgerForEval is a ledger interface for the debugger.
type DebuggerLedgerForEval interface {
	internal.LedgerForEvaluator
	Latest() basics.Round
}

// EvalForDebugger processes a transaction group for the debugger.
func EvalForDebugger(l DebuggerLedgerForEval, stxns []transactions.SignedTxn) (ledgercore.StateDelta, []transactions.SignedTxnInBlock, error) {
	prevBlockHdr, err := l.BlockHdr(l.Latest())
	if err != nil {
		return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{}, err
	}
	nextBlock := bookkeeping.MakeBlock(prevBlockHdr)
	nextBlockProto := config.Consensus[nextBlock.BlockHeader.CurrentProtocol]

	eval, err := internal.StartEvaluator(
		l, nextBlock.BlockHeader,
		internal.EvaluatorOptions{
			PaysetHint:  len(stxns),
			ProtoParams: &nextBlockProto,
			Generate:    true,
			Validate:    true,
		})
	if err != nil {
		return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
			fmt.Errorf("EvalForDebugger() err: %w", err)
	}

	group := make([]transactions.SignedTxnWithAD, len(stxns))
	for i, stxn := range stxns {
		group[i] = transactions.SignedTxnWithAD{
			SignedTxn: stxn,
		}
	}

	return eval.ProcessTransactionGroupForDebugger(group)
}
