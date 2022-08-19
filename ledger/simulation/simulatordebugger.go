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
	"fmt"

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

	result            *SimulationResult
	evalDeltaSnapshot transactions.EvalDelta
}

func makeDebuggerHook(txgroup []transactions.SignedTxn) debuggerHook {
	result := MakeSimulationResult([][]transactions.SignedTxn{txgroup})
	return debuggerHook{result: &result}
}

func (dh *debuggerHook) getApplyDataAtPath(path TxnPath) (*transactions.ApplyData, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("simulator debugger error: path is empty")
	}

	applyDataCursor := &dh.result.TxnGroups[0].Txns[dh.cursor[0]].Txn.ApplyData

	for _, index := range dh.cursor[1:] {
		innerTxns := (*applyDataCursor).EvalDelta.InnerTxns
		if index >= uint64(len(innerTxns)) {
			return nil, fmt.Errorf("simulator debugger error: index %d out of range", index)
		}
		applyDataCursor = &innerTxns[index].ApplyData
	}

	return applyDataCursor, nil
}

func (dh *debuggerHook) populateInnerTransactions(txgroup []transactions.SignedTxnWithAD) error {
	applyDataOfCallingTxn, err := dh.getApplyDataAtPath(dh.cursor) // this works because the cursor has not been updated yet by `BeforeTxn`
	if err != nil {
		return err
	}
	applyDataOfCallingTxn.EvalDelta.InnerTxns = append(applyDataOfCallingTxn.EvalDelta.InnerTxns, txgroup...)
	return nil
}

// Copy the inner transaction group to the ApplyData.EvalDelta.InnerTxns of the calling transaction
func (dh *debuggerHook) BeforeInnerTxnGroup(ep *logic.EvalParams) error {
	return dh.populateInnerTransactions(ep.TxnGroup)
}

func (dh *debuggerHook) saveApplyData(applyData transactions.ApplyData) error {
	applyDataOfCurrentTxn, err := dh.getApplyDataAtPath(dh.cursor)
	if err != nil {
		return err
	}

	*applyDataOfCurrentTxn = applyData
	return nil
}

func (dh *debuggerHook) AfterTxn(ep *logic.EvalParams, groupIndex int) error {
	// Update ApplyData if not an inner transaction
	err := dh.saveApplyData(ep.TxnGroup[groupIndex].ApplyData)
	if err != nil {
		return err
	}

	return dh.cursorDebuggerHook.AfterTxn(ep, groupIndex)
}

func (dh *debuggerHook) saveEvalDelta(evalDelta transactions.EvalDelta) error {
	applyDataOfCurrentTxn, err := dh.getApplyDataAtPath(dh.cursor)
	if err != nil {
		return err
	}

	applyDataOfCurrentTxn.EvalDelta = evalDelta
	return nil
}

func (dh *debuggerHook) BeforeTealOp(state *logic.DebugState) error {
	return dh.saveEvalDelta(state.EvalDelta)
}
