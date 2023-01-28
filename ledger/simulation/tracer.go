// Copyright (C) 2019-2023 Algorand, Inc.
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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

type cursorEvalTracer struct {
	logic.NullEvalTracer

	relativeCursor    []int
	previousInnerTxns []int
}

func (tracer *cursorEvalTracer) BeforeTxnGroup(ep *logic.EvalParams) {
	tracer.relativeCursor = append(tracer.relativeCursor, -1) // will go to 0 in BeforeTxn
}

func (tracer *cursorEvalTracer) BeforeTxn(ep *logic.EvalParams, groupIndex int) {
	top := len(tracer.relativeCursor) - 1
	tracer.relativeCursor[top]++
	tracer.previousInnerTxns = append(tracer.previousInnerTxns, 0)
}

func (tracer *cursorEvalTracer) AfterTxn(ep *logic.EvalParams, groupIndex int, ad transactions.ApplyData, evalError error) {
	tracer.previousInnerTxns = tracer.previousInnerTxns[:len(tracer.previousInnerTxns)-1]
}

func (tracer *cursorEvalTracer) AfterTxnGroup(ep *logic.EvalParams, evalError error) {
	top := len(tracer.relativeCursor) - 1
	if len(tracer.previousInnerTxns) != 0 {
		tracer.previousInnerTxns[len(tracer.previousInnerTxns)-1] += tracer.relativeCursor[top] + 1
	}
	tracer.relativeCursor = tracer.relativeCursor[:top]
}

func (tracer *cursorEvalTracer) relativeGroupIndex() int {
	top := len(tracer.relativeCursor) - 1
	return tracer.relativeCursor[top]
}

func (tracer *cursorEvalTracer) absolutePath() TxnPath {
	path := make(TxnPath, len(tracer.relativeCursor))
	for i, relativeGroupIndex := range tracer.relativeCursor {
		absoluteIndex := uint64(relativeGroupIndex)
		if i > 0 {
			absoluteIndex += uint64(tracer.previousInnerTxns[i-1])
		}
		path[i] = absoluteIndex
	}
	return path
}

// ==============================
// > Simulator Debugger
// ==============================

type evalTracer struct {
	cursorEvalTracer

	isAppRunning      bool
	result            *Result
	evalDeltaSnapshot transactions.EvalDelta
	failedAt          TxnPath
}

func makeEvalTracer(txgroup []transactions.SignedTxn) *evalTracer {
	result := MakeSimulationResult([][]transactions.SignedTxn{txgroup})
	return &evalTracer{result: &result}
}

func (tracer *evalTracer) handleError(evalError error) {
	if evalError != nil && tracer.failedAt == nil {
		tracer.failedAt = tracer.absolutePath()
	}
}

func (tracer *evalTracer) getApplyDataAtPath(path TxnPath) (*transactions.ApplyData, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("simulator debugger error: path is empty")
	}

	applyDataCursor := &tracer.result.TxnGroups[0].Txns[path[0]].Txn.ApplyData

	for _, index := range path[1:] {
		innerTxns := applyDataCursor.EvalDelta.InnerTxns
		if index >= uint64(len(innerTxns)) {
			return nil, fmt.Errorf("simulator debugger error: index %d out of range with length %d. Full path: %v", index, len(innerTxns), path)
		}
		applyDataCursor = &innerTxns[index].ApplyData
	}

	return applyDataCursor, nil
}

func (tracer *evalTracer) mustGetApplyDataAtPath(path TxnPath) *transactions.ApplyData {
	ad, err := tracer.getApplyDataAtPath(path)
	if err != nil {
		panic(err)
	}
	return ad
}

// Copy the inner transaction group to the ApplyData.EvalDelta.InnerTxns of the calling transaction
func (tracer *evalTracer) populateInnerTransactions(txgroup []transactions.SignedTxnWithAD) {
	applyDataOfCallingTxn := tracer.mustGetApplyDataAtPath(tracer.absolutePath()) // this works because the cursor has not been updated yet by `BeforeTxn`
	applyDataOfCallingTxn.EvalDelta.InnerTxns = append(applyDataOfCallingTxn.EvalDelta.InnerTxns, txgroup...)
}

func (tracer *evalTracer) BeforeTxnGroup(ep *logic.EvalParams) {
	if ep.GetCaller() != nil {
		// If this is an inner txn group, save the txns
		tracer.populateInnerTransactions(ep.TxnGroup)
	}
	tracer.cursorEvalTracer.BeforeTxnGroup(ep)
}

func (tracer *evalTracer) AfterTxnGroup(ep *logic.EvalParams, evalError error) {
	tracer.handleError(evalError)
	tracer.cursorEvalTracer.AfterTxnGroup(ep, evalError)
}

func (tracer *evalTracer) saveApplyData(applyData transactions.ApplyData) {
	applyDataOfCurrentTxn := tracer.mustGetApplyDataAtPath(tracer.absolutePath())
	// Copy everything except the EvalDelta, since that has been kept up-to-date after every op
	evalDelta := applyDataOfCurrentTxn.EvalDelta
	*applyDataOfCurrentTxn = applyData
	applyDataOfCurrentTxn.EvalDelta = evalDelta
}

func (tracer *evalTracer) AfterTxn(ep *logic.EvalParams, groupIndex int, ad transactions.ApplyData, evalError error) {
	tracer.handleError(evalError)
	tracer.saveApplyData(ad)
	tracer.cursorEvalTracer.AfterTxn(ep, groupIndex, ad, evalError)
}

func (tracer *evalTracer) saveEvalDelta(evalDelta transactions.EvalDelta, appIDToSave basics.AppIndex) {
	applyDataOfCurrentTxn := tracer.mustGetApplyDataAtPath(tracer.absolutePath())
	// Copy everything except the inner transactions, since those have been kept up-to-date when we
	// traced those transactions.
	inners := applyDataOfCurrentTxn.EvalDelta.InnerTxns
	applyDataOfCurrentTxn.EvalDelta = evalDelta
	applyDataOfCurrentTxn.EvalDelta.InnerTxns = inners

	// TODO: remove
	if len(inners) != len(evalDelta.InnerTxns) {
		panic("inner lengths differ")
	}
}

func (tracer *evalTracer) BeforeOpcode(cx *logic.EvalContext) {
	if cx.RunMode() != logic.ModeApp {
		// do nothing for LogicSig ops
		return
	}
	groupIndex := tracer.relativeGroupIndex()
	var appIDToSave basics.AppIndex
	if cx.TxnGroup[groupIndex].SignedTxn.Txn.ApplicationID == 0 {
		// app creation
		appIDToSave = cx.AppID()
	}
	tracer.saveEvalDelta(cx.TxnGroup[groupIndex].EvalDelta, appIDToSave)
}

func (tracer *evalTracer) AfterOpcode(cx *logic.EvalContext, evalError error) {
	tracer.handleError(evalError)
	tracer.cursorEvalTracer.AfterOpcode(cx, evalError)
}

func (tracer *evalTracer) AfterProgram(cx *logic.EvalContext, evalError error) {
	tracer.handleError(evalError)
	tracer.cursorEvalTracer.AfterProgram(cx, evalError)
}
