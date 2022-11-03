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
	logic.NullDebuggerHook

	relativeCursor    []int
	previousInnerTxns []int
}

func (cdbg *cursorDebuggerHook) BeforeTxn(ep *logic.EvalParams, groupIndex int) error {
	top := len(cdbg.relativeCursor) - 1
	if top < 0 {
		cdbg.relativeCursor = []int{0}
	} else {
		cdbg.relativeCursor[top]++
	}
	cdbg.previousInnerTxns = append(cdbg.previousInnerTxns, 0)
	return nil
}

func (cdbg *cursorDebuggerHook) AfterTxn(ep *logic.EvalParams, groupIndex int) error {
	cdbg.previousInnerTxns = cdbg.previousInnerTxns[:len(cdbg.previousInnerTxns)-1]
	return nil
}

// Copy the inner transaction group to the ApplyData.EvalDelta.InnerTxns of the calling transaction
func (cdbg *cursorDebuggerHook) BeforeInnerTxnGroup(ep *logic.EvalParams) error {
	cdbg.relativeCursor = append(cdbg.relativeCursor, -1) // will go to 0 in BeforeTxn
	return nil
}

func (cdbg *cursorDebuggerHook) AfterInnerTxnGroup(ep *logic.EvalParams) error {
	top := len(cdbg.relativeCursor) - 1
	cdbg.previousInnerTxns[len(cdbg.previousInnerTxns)-1] += cdbg.relativeCursor[top] + 1
	cdbg.relativeCursor = cdbg.relativeCursor[:top]
	return nil
}

func (cdbg *cursorDebuggerHook) relativeGroupIndex() int {
	top := len(cdbg.relativeCursor) - 1
	return cdbg.relativeCursor[top]
}

func (cdbg *cursorDebuggerHook) absolutePath() TxnPath {
	path := make(TxnPath, len(cdbg.relativeCursor))
	for i, relativeGroupIndex := range cdbg.relativeCursor {
		absoluteIndex := uint64(relativeGroupIndex)
		if i > 0 {
			absoluteIndex += uint64(cdbg.previousInnerTxns[i-1])
		}
		path[i] = absoluteIndex
	}
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
	applyDataOfCallingTxn, err := dh.getApplyDataAtPath(dh.absolutePath()) // this works because the cursor has not been updated yet by `BeforeTxn`
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
	applyDataOfCurrentTxn, err := dh.getApplyDataAtPath(dh.absolutePath())
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
	applyDataOfCurrentTxn, err := dh.getApplyDataAtPath(dh.absolutePath())
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
