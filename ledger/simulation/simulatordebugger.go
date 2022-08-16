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

package simulation

import (
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

// ==============================
// > Simulator Debugger
// ==============================

type debuggerHook struct {
	result        *SimulationResult
	cursor        TxnPath
	innerTxnIndex int
}

func makeDebuggerHook(txgroup []transactions.SignedTxn) debuggerHook {
	result := MakeSimulationResult([][]transactions.SignedTxn{txgroup})
	return debuggerHook{result: &result, cursor: make(TxnPath, 0)}
}

func (dh *debuggerHook) BeforeTxn(ep *logic.EvalParams, groupIndex int) error {
	// Add this transaction to the cursor
	dh.cursor = append(dh.cursor, uint64(groupIndex))
	return nil
}

func (dh *debuggerHook) AfterTxn(ep *logic.EvalParams, groupIndex int) error {
	// Remove this transaction from the cursor
	dh.cursor = dh.cursor[:len(dh.cursor)-1]

	// Reset the inner txn index
	dh.innerTxnIndex = 0

	// Set result ApplyData for this transaction
	dh.result.TxnGroups[0].Txns[groupIndex].Txn.ApplyData = ep.TxnGroup[groupIndex].ApplyData
	return nil
}

func (dh *debuggerHook) BeforeInnerTxn(ep *logic.EvalParams) error {
	// Add this inner transaction to the cursor
	dh.cursor = append(dh.cursor, uint64(dh.innerTxnIndex))

	// Increment the inner txn index
	dh.innerTxnIndex++

	return nil
}

func (dh *debuggerHook) AfterInnerTxn(ep *logic.EvalParams) error {
	// Remove this inner transaction from the cursor
	dh.cursor = dh.cursor[:len(dh.cursor)-1]
	return nil
}
