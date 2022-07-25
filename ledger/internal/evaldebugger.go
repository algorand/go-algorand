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

package internal

import (
	"fmt"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// ProcessTransactionGroupForDebugger ..
func (eval *BlockEvaluator) ProcessTransactionGroupForDebugger(group []transactions.SignedTxnWithAD) (ledgercore.StateDelta, []transactions.SignedTxnInBlock, error) {
	err := eval.TransactionGroup(group)
	if err != nil {
		return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
			fmt.Errorf("ProcessTransactionGroupForDebugger() err: %w", err)
	}

	// Finally, process any pending end-of-block state changes.
	err = eval.endOfBlock()
	if err != nil {
		return ledgercore.StateDelta{}, []transactions.SignedTxnInBlock{},
			fmt.Errorf("ProcessTransactionGroupForDebugger() err: %w", err)
	}

	return eval.state.deltas(), eval.block.Payset, nil
}
