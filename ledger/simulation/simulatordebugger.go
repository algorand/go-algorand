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

type cursorDebuggerHook struct {
	cursor TxnPath
	serial bool
	index  uint64
}

func (ph *cursorDebuggerHook) BeforeTxn(ep *logic.EvalParams, groupIndex int) error {
	if !ph.serial {
		ph.index = 0
	}
	ph.cursor = append(ph.cursor, ph.index)
	ph.serial = false
	return nil
}

func (ph *cursorDebuggerHook) AfterTxn(ep *logic.EvalParams, groupIndex int) error {
	// pop the last index
	lastIndex := len(ph.cursor) - 1
	lastItem := ph.cursor[lastIndex]
	ph.cursor = ph.cursor[:lastIndex]

	if ph.serial {
		ph.index = lastItem
	}
	ph.index++
	ph.serial = true
	return nil
}

// ==============================
// > Simulator Debugger
// ==============================

type debuggerHook struct {
	cursorDebuggerHook

	result *SimulationResult
}

func makeDebuggerHook(txgroup []transactions.SignedTxn) debuggerHook {
	result := MakeSimulationResult([][]transactions.SignedTxn{txgroup})
	return debuggerHook{result: &result}
}

func (dh *debuggerHook) AfterTxn(ep *logic.EvalParams, groupIndex int) error {
	// Update ApplyData if not an inner transaction
	if len(dh.cursor) == 1 {
		dh.result.TxnGroups[0].Txns[groupIndex].Txn.ApplyData = ep.TxnGroup[groupIndex].ApplyData
	}
	return dh.cursorDebuggerHook.AfterTxn(ep, groupIndex)
}

func (dh *debuggerHook) AfterTealOp(state *logic.DebugState) error {
	// When an error occurs, store the ApplyData for the transaction before it's lost
	if state.Error != "" {
		// The cursor won't have been updated yet, so a length of 2 means
		// we're in a first-level inner transaction and are about to leave it
		if len(dh.cursor) == 2 {
			dh.result.TxnGroups[0].Txns[state.GroupIndex].Txn.ApplyData.EvalDelta = state.EvalDelta
		}
	}
	return nil
}
