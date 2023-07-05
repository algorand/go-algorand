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
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// cursorEvalTracer is responsible for maintaining a TxnPath that points to the currently executing
// transaction. The absolutePath() function is used to get this path.
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

func (tracer *cursorEvalTracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
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

// evalTracer is responsible for populating a Result during a simulation evaluation. It saves
// EvalDelta & inner transaction changes as they happen, so if an error occurs during evaluation, we
// can return a partially-built ApplyData with as much information as possible at the time of the
// error.
type evalTracer struct {
	cursorEvalTracer

	result   *Result
	failedAt TxnPath

	// execTraceStack keeps track of the call stack:
	// from top level transaction to the current inner txn that contains latest TransactionTrace.
	// NOTE: execTraceStack is used only for PC/Stack/Storage exposure.
	execTraceStack []*TransactionTrace

	// addCount and popCount keep track of the latest opcode change explanation from opcode.
	addCount int
	popCount int

	// stackHeightAfterDeletion is calculated by stack height before opcode - stack element deletion number.
	// NOTE: both stackChangeExplanation and stackHeightAfterDeletion are used only for Stack exposure.
	stackHeightAfterDeletion int
}

func makeEvalTracer(lastRound basics.Round, request Request, developerAPI bool) (*evalTracer, error) {
	result, err := makeSimulationResult(lastRound, request, developerAPI)
	if err != nil {
		return nil, err
	}
	return &evalTracer{result: &result}, nil
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
		tracer.result.TxnGroups[0].AppBudgetAdded += uint64(ep.Proto.MaxAppProgramCost)
	}
	tracer.cursorEvalTracer.BeforeTxnGroup(ep)

	// Currently only supports one (first) txn group
	if ep.PooledApplicationBudget != nil && tracer.result.TxnGroups[0].AppBudgetAdded == 0 {
		tracer.result.TxnGroups[0].AppBudgetAdded = uint64(*ep.PooledApplicationBudget)
	}

	// Override transaction group budget if specified in request, retrieve from tracer.result
	if ep.PooledApplicationBudget != nil {
		tracer.result.TxnGroups[0].AppBudgetAdded += tracer.result.EvalOverrides.ExtraOpcodeBudget
		*ep.PooledApplicationBudget += int(tracer.result.EvalOverrides.ExtraOpcodeBudget)
	}

	// Override runtime related constraints against ep, before entering txn group
	ep.EvalConstants = tracer.result.EvalOverrides.LogicEvalConstants()
}

func (tracer *evalTracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	tracer.handleError(evalError)
	tracer.cursorEvalTracer.AfterTxnGroup(ep, deltas, evalError)
}

func (tracer *evalTracer) saveApplyData(applyData transactions.ApplyData) {
	applyDataOfCurrentTxn := tracer.mustGetApplyDataAtPath(tracer.absolutePath())
	// Copy everything except the EvalDelta, since that has been kept up-to-date after every op
	evalDelta := applyDataOfCurrentTxn.EvalDelta
	*applyDataOfCurrentTxn = applyData
	applyDataOfCurrentTxn.EvalDelta = evalDelta
}

func (tracer *evalTracer) BeforeTxn(ep *logic.EvalParams, groupIndex int) {
	if tracer.result.ReturnTrace() {
		var txnTraceStackElem *TransactionTrace

		// Where should the current transaction trace attach to:
		// - if it is a top level transaction, then attach to TxnResult level
		// - if it is an inner transaction, then refer to the stack for latest exec trace,
		//   and attach to inner array
		if len(tracer.execTraceStack) == 0 {
			// to adapt to logic sig trace here, we separate into 2 cases:
			// - if we already executed `Before/After-Program`,
			//   then there should be a trace containing logic sig.
			//   We should add the transaction type to the pre-existing execution trace.
			// - otherwise, we take the simplest trace with transaction type.
			if tracer.result.TxnGroups[0].Txns[groupIndex].Trace == nil {
				tracer.result.TxnGroups[0].Txns[groupIndex].Trace = &TransactionTrace{}
			}
			txnTraceStackElem = tracer.result.TxnGroups[0].Txns[groupIndex].Trace
		} else {
			// we are reaching inner txns, so we don't have to be concerned about logic sig trace here
			lastExecTrace := tracer.execTraceStack[len(tracer.execTraceStack)-1]
			lastExecTrace.InnerTraces = append(lastExecTrace.InnerTraces, TransactionTrace{})
			txnTraceStackElem = &lastExecTrace.InnerTraces[len(lastExecTrace.InnerTraces)-1]

			innerIndex := len(lastExecTrace.InnerTraces) - 1
			parentOpIndex := len(*lastExecTrace.programTraceRef) - 1

			parentOp := &(*lastExecTrace.programTraceRef)[parentOpIndex]
			parentOp.SpawnedInners = append(parentOp.SpawnedInners, innerIndex)
		}

		currentTxn := ep.TxnGroup[groupIndex]
		if currentTxn.Txn.Type == protocol.ApplicationCallTx {
			switch currentTxn.Txn.ApplicationCallTxnFields.OnCompletion {
			case transactions.ClearStateOC:
				txnTraceStackElem.programTraceRef = &txnTraceStackElem.ClearStateProgramTrace
			default:
				txnTraceStackElem.programTraceRef = &txnTraceStackElem.ApprovalProgramTrace
			}
		}

		// In both case, we need to add to transaction trace to the stack
		tracer.execTraceStack = append(tracer.execTraceStack, txnTraceStackElem)
	}
	tracer.cursorEvalTracer.BeforeTxn(ep, groupIndex)
}

func (tracer *evalTracer) AfterTxn(ep *logic.EvalParams, groupIndex int, ad transactions.ApplyData, evalError error) {
	tracer.handleError(evalError)
	tracer.saveApplyData(ad)
	// if the current transaction + simulation condition would lead to exec trace making
	// we should clean them up from tracer.execTraceStack.
	if tracer.result.ReturnTrace() {
		lastOne := tracer.execTraceStack[len(tracer.execTraceStack)-1]
		lastOne.programTraceRef = nil
		tracer.execTraceStack = tracer.execTraceStack[:len(tracer.execTraceStack)-1]
	}
	tracer.cursorEvalTracer.AfterTxn(ep, groupIndex, ad, evalError)
}

func (tracer *evalTracer) saveEvalDelta(evalDelta transactions.EvalDelta, appIDToSave basics.AppIndex) {
	applyDataOfCurrentTxn := tracer.mustGetApplyDataAtPath(tracer.absolutePath())
	// Copy everything except the inner transactions, since those have been kept up-to-date when we
	// traced those transactions.
	inners := applyDataOfCurrentTxn.EvalDelta.InnerTxns
	applyDataOfCurrentTxn.EvalDelta = evalDelta
	applyDataOfCurrentTxn.EvalDelta.InnerTxns = inners
}

func (tracer *evalTracer) makeOpcodeTraceUnit(cx *logic.EvalContext) OpcodeTraceUnit {
	return OpcodeTraceUnit{PC: uint64(cx.PC())}
}

func (o *OpcodeTraceUnit) computeStackValueDeletions(cx *logic.EvalContext, tracer *evalTracer) {
	tracer.popCount, tracer.addCount = cx.NextStackChange()
	o.StackPopCount = uint64(tracer.popCount)

	stackHeight := len(cx.Stack)
	tracer.stackHeightAfterDeletion = stackHeight - int(o.StackPopCount)
}

func (tracer *evalTracer) BeforeOpcode(cx *logic.EvalContext) {
	groupIndex := cx.GroupIndex()

	if cx.RunMode() == logic.ModeApp {
		// Remember app EvalDelta before executing the opcode. We do this
		// because if this opcode fails, the block evaluator resets the EvalDelta.
		var appIDToSave basics.AppIndex
		if cx.TxnGroup[groupIndex].SignedTxn.Txn.ApplicationID == 0 {
			// App creation
			appIDToSave = cx.AppID()
		}
		tracer.saveEvalDelta(cx.TxnGroup[groupIndex].EvalDelta, appIDToSave)
	}

	if tracer.result.ReturnTrace() {
		var txnTrace *TransactionTrace
		if cx.RunMode() == logic.ModeSig {
			txnTrace = tracer.result.TxnGroups[0].Txns[groupIndex].Trace
		} else {
			txnTrace = tracer.execTraceStack[len(tracer.execTraceStack)-1]
		}
		*txnTrace.programTraceRef = append(*txnTrace.programTraceRef, tracer.makeOpcodeTraceUnit(cx))

		if tracer.result.ReturnStackChange() {
			latestOpcodeTraceUnit := &(*txnTrace.programTraceRef)[len(*txnTrace.programTraceRef)-1]
			latestOpcodeTraceUnit.computeStackValueDeletions(cx, tracer)
		}
	}
}

func (o *OpcodeTraceUnit) appendAddedStackValue(cx *logic.EvalContext, tracer *evalTracer) {
	for i := tracer.stackHeightAfterDeletion; i < len(cx.Stack); i++ {
		tealValue := cx.Stack[i].ToTealValue()
		o.StackAdded = append(o.StackAdded, basics.TealValue{
			Type:  tealValue.Type,
			Uint:  tealValue.Uint,
			Bytes: tealValue.Bytes,
		})
	}
}

func (tracer *evalTracer) AfterOpcode(cx *logic.EvalContext, evalError error) {
	groupIndex := cx.GroupIndex()

	// NOTE: only when we have no evalError on current opcode,
	// we can proceed for recording stack chaange
	if evalError == nil && tracer.result.ReturnStackChange() {
		var txnTrace *TransactionTrace
		if cx.RunMode() == logic.ModeSig {
			txnTrace = tracer.result.TxnGroups[0].Txns[groupIndex].Trace
		} else {
			txnTrace = tracer.execTraceStack[len(tracer.execTraceStack)-1]
		}

		latestOpcodeTraceUnit := &(*txnTrace.programTraceRef)[len(*txnTrace.programTraceRef)-1]
		latestOpcodeTraceUnit.appendAddedStackValue(cx, tracer)
	}

	if cx.RunMode() != logic.ModeApp {
		// do nothing for LogicSig ops
		return
	}
	tracer.handleError(evalError)
}

func (tracer *evalTracer) BeforeProgram(cx *logic.EvalContext) {
	groupIndex := cx.GroupIndex()

	// Before Program, activated for logic sig, happens before txn group execution
	// we should create trace object for this txn result
	if cx.RunMode() != logic.ModeApp {
		if tracer.result.ReturnTrace() {
			tracer.result.TxnGroups[0].Txns[groupIndex].Trace = &TransactionTrace{}
			traceRef := tracer.result.TxnGroups[0].Txns[groupIndex].Trace
			traceRef.programTraceRef = &traceRef.LogicSigTrace
		}
	}
}

func (tracer *evalTracer) AfterProgram(cx *logic.EvalContext, evalError error) {
	groupIndex := cx.GroupIndex()

	if cx.RunMode() != logic.ModeApp {
		// Report cost for LogicSig program and exit
		tracer.result.TxnGroups[0].Txns[groupIndex].LogicSigBudgetConsumed = uint64(cx.Cost())
		if tracer.result.ReturnTrace() {
			tracer.result.TxnGroups[0].Txns[groupIndex].Trace.programTraceRef = nil
		}
		return
	}

	// Report cost of this program.
	// If it is an inner app call, roll up its cost to the top level transaction.
	tracer.result.TxnGroups[0].Txns[tracer.relativeCursor[0]].AppBudgetConsumed += uint64(cx.Cost())

	tracer.handleError(evalError)
}
