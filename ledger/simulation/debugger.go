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
	"math"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

type cursorDebuggerHook struct {
	logic.NullDebuggerHook

	cursor         TxnPath
	nextInnerIndex uint64
	groupIndex     int
}

func (cdbg *cursorDebuggerHook) BeforeTxn(ep *logic.EvalParams, groupIndex int) error {
	top := len(cdbg.cursor) - 1
	if top < 0 {
		cdbg.cursor = TxnPath{0}
	} else {
		cdbg.cursor[top]++
	}
	cdbg.groupIndex = groupIndex
	return nil
}

func (cdbg *cursorDebuggerHook) AfterTxn(ep *logic.EvalParams, groupIndex int) error {
	cdbg.nextInnerIndex = 0
	return nil
}

// Copy the inner transaction group to the ApplyData.EvalDelta.InnerTxns of the calling transaction
func (cdbg *cursorDebuggerHook) BeforeInnerTxnGroup(ep *logic.EvalParams) error {
	innerIndexStart := uint64(math.MaxUint64) // will overflow to 0 when incremented
	if cdbg.nextInnerIndex != 0 {
		innerIndexStart = cdbg.nextInnerIndex - 1
		cdbg.nextInnerIndex = 0
	}
	cdbg.cursor = append(cdbg.cursor, innerIndexStart)
	return nil
}

func (cdbg *cursorDebuggerHook) AfterInnerTxnGroup(ep *logic.EvalParams) error {
	top := len(cdbg.cursor) - 1
	cdbg.nextInnerIndex = cdbg.cursor[top] + 1
	cdbg.cursor = cdbg.cursor[:top]
	cdbg.groupIndex = ep.GetCaller().GroupIndex()
	return nil
}

func (cdbg *cursorDebuggerHook) relativeGroupIndex() int {
	return cdbg.groupIndex
}

func (cdbg *cursorDebuggerHook) absolutePath() TxnPath {
	path := make(TxnPath, len(cdbg.cursor))
	copy(path, cdbg.cursor)
	return path
}

// ==============================
// > Simulator Debugger
// ==============================

type debuggerHook struct {
	cursorDebuggerHook

	isAppRunning      bool
	result            *Result
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

	applyDataCursor := &dh.result.TxnGroups[0].Txns[path[0]].Txn.ApplyData

	for _, index := range path[1:] {
		innerTxns := applyDataCursor.EvalDelta.InnerTxns
		if index >= uint64(len(innerTxns)) {
			return nil, fmt.Errorf("simulator debugger error: index %d out of range with length %d. Full path: %v", index, len(innerTxns), path)
		}
		applyDataCursor = &innerTxns[index].ApplyData
	}

	return applyDataCursor, nil
}

// Copy the inner transaction group to the ApplyData.EvalDelta.InnerTxns of the calling transaction
func (dh *debuggerHook) populateInnerTransactions(txgroup []transactions.SignedTxnWithAD) error {
	applyDataOfCallingTxn, err := dh.getApplyDataAtPath(dh.cursor) // this works because the cursor has not been updated yet by `BeforeTxn`
	if err != nil {
		return err
	}
	applyDataOfCallingTxn.EvalDelta.InnerTxns = append(applyDataOfCallingTxn.EvalDelta.InnerTxns, txgroup...)
	return nil
}

func (dh *debuggerHook) BeforeInnerTxnGroup(ep *logic.EvalParams) error {
	err := dh.populateInnerTransactions(ep.TxnGroup)
	if err != nil {
		return err
	}
	return dh.cursorDebuggerHook.BeforeInnerTxnGroup(ep)
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

func (dh *debuggerHook) BeforeTealOp(cx *logic.EvalContext) error {
	if cx.RunMode() != logic.ModeApp {
		// do nothing for LogicSig ops
		return nil
	}

	groupIndex := dh.relativeGroupIndex()
	return dh.saveEvalDelta(cx.TxnGroup[groupIndex].EvalDelta)
}
