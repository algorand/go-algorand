// Copyright (C) 2019-2025 Algorand, Inc.
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

	"github.com/algorand/go-algorand/crypto"
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

func (tracer *cursorEvalTracer) absolutePath() TxnPath {
	path := make(TxnPath, len(tracer.relativeCursor))
	for i, relativeGroupIndex := range tracer.relativeCursor {
		absoluteIndex := relativeGroupIndex
		if i > 0 {
			absoluteIndex += tracer.previousInnerTxns[i-1]
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

	unnamedResourcePolicy *resourcePolicy

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

	// scratchSlots are the scratch slots changed on current opcode (currently either `store` or `stores`).
	// NOTE: this field scratchSlots is used only for scratch change exposure.
	scratchSlots []int

	groups [][]transactions.SignedTxnWithAD
}

func makeEvalTracer(lastRound basics.Round, group []transactions.SignedTxnWithAD, request Request, developerAPI bool) (*evalTracer, error) {
	result, err := makeSimulationResult(lastRound, request, developerAPI)
	if err != nil {
		return nil, err
	}
	return &evalTracer{result: &result, groups: [][]transactions.SignedTxnWithAD{group}}, nil
}

// handleError is responsible for setting the failedAt field properly.
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
		if index >= len(innerTxns) {
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
		tracer.result.TxnGroups[0].AppBudgetAdded += ep.Proto.MaxAppProgramCost
	}
	tracer.cursorEvalTracer.BeforeTxnGroup(ep)

	// Currently only supports one (first) txn group
	if ep.PooledApplicationBudget != nil && tracer.result.TxnGroups[0].AppBudgetAdded == 0 {
		tracer.result.TxnGroups[0].AppBudgetAdded = *ep.PooledApplicationBudget
	}

	// Override transaction group budget if specified in request, retrieve from tracer.result
	if ep.PooledApplicationBudget != nil {
		tracer.result.TxnGroups[0].AppBudgetAdded += tracer.result.EvalOverrides.ExtraOpcodeBudget
		*ep.PooledApplicationBudget += tracer.result.EvalOverrides.ExtraOpcodeBudget
	}

	if ep.GetCaller() == nil {
		// Override runtime related constraints against ep, before entering txn group
		ep.EvalConstants = tracer.result.EvalOverrides.LogicEvalConstants()
		if tracer.result.EvalOverrides.AllowUnnamedResources {
			tracer.unnamedResourcePolicy = newResourcePolicy(ep, &tracer.result.TxnGroups[0])
			ep.EvalConstants.UnnamedResources = tracer.unnamedResourcePolicy
		}
	}
}

func (tracer *evalTracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	tracer.handleError(evalError)
	tracer.cursorEvalTracer.AfterTxnGroup(ep, deltas, evalError)

	if ep.GetCaller() == nil && tracer.unnamedResourcePolicy != nil {
		tracer.unnamedResourcePolicy = nil
	}
}

func (tracer *evalTracer) saveApplyData(applyData transactions.ApplyData, omitEvalDelta bool) {
	applyDataOfCurrentTxn := tracer.mustGetApplyDataAtPath(tracer.absolutePath())
	evalDelta := applyDataOfCurrentTxn.EvalDelta
	*applyDataOfCurrentTxn = applyData
	if omitEvalDelta {
		// If omitEvalDelta is true, restore the EvalDelta from applyDataOfCurrentTxn
		applyDataOfCurrentTxn.EvalDelta = evalDelta
	}
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
	if ep.GetCaller() == nil && tracer.unnamedResourcePolicy != nil {
		tracer.unnamedResourcePolicy.txnRootIndex = groupIndex
	}
	tracer.cursorEvalTracer.BeforeTxn(ep, groupIndex)
}

func (tracer *evalTracer) AfterTxn(ep *logic.EvalParams, groupIndex int, ad transactions.ApplyData, evalError error) {
	tracer.handleError(evalError)
	tracer.saveApplyData(ad, evalError != nil)
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
	return OpcodeTraceUnit{PC: cx.PC()}
}

func (o *OpcodeTraceUnit) computeStackValueDeletions(cx *logic.EvalContext, tracer *evalTracer) {
	tracer.popCount, tracer.addCount = cx.GetOpSpec().StackExplain(cx)
	o.StackPopCount = tracer.popCount

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

		latestOpcodeTraceUnit := &(*txnTrace.programTraceRef)[len(*txnTrace.programTraceRef)-1]
		if tracer.result.ReturnStackChange() {
			latestOpcodeTraceUnit.computeStackValueDeletions(cx, tracer)
		}
		if tracer.result.ReturnScratchChange() {
			tracer.recordChangedScratchSlots(cx)
		}
		if tracer.result.ReturnStateChange() {
			latestOpcodeTraceUnit.appendStateOperations(cx)
			tracer.result.InitialStates.increment(cx)
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

func (o *OpcodeTraceUnit) appendStateOperations(cx *logic.EvalContext) {
	if cx.GetOpSpec().AppStateExplain == nil {
		return
	}
	appState, stateOp, appID, acctAddr, stateKey := cx.GetOpSpec().AppStateExplain(cx)
	// If the operation is not write or delete, return without
	if stateOp == logic.AppStateRead {
		return
	}
	o.StateChanges = append(o.StateChanges, StateOperation{
		AppStateOp: stateOp,
		AppState:   appState,
		AppID:      appID,
		Key:        stateKey,
		Account:    acctAddr,
	})
}

func (tracer *evalTracer) recordChangedScratchSlots(cx *logic.EvalContext) {
	currentOpcodeName := cx.GetOpSpec().Name
	last := len(cx.Stack) - 1
	tracer.scratchSlots = nil

	switch currentOpcodeName {
	case "store":
		slot := cx.GetProgram()[cx.PC()+1]
		tracer.scratchSlots = append(tracer.scratchSlots, int(slot))
	case "stores":
		prev := last - 1
		slot := cx.Stack[prev].Uint

		// If something goes wrong for `stores`, we don't have to error here
		// for in runtime already has evalError
		if slot >= uint64(len(cx.Scratch)) {
			return
		}
		tracer.scratchSlots = append(tracer.scratchSlots, int(slot))
	}
}

func (tracer *evalTracer) recordUpdatedScratchVars(cx *logic.EvalContext) []ScratchChange {
	if len(tracer.scratchSlots) == 0 {
		return nil
	}
	changes := make([]ScratchChange, len(tracer.scratchSlots))
	for i, slot := range tracer.scratchSlots {
		changes[i] = ScratchChange{
			Slot:     slot,
			NewValue: cx.Scratch[slot].ToTealValue(),
		}
	}
	return changes
}

func (o *OpcodeTraceUnit) updateNewStateValues(cx *logic.EvalContext) {
	for i, sc := range o.StateChanges {
		o.StateChanges[i].NewValue = logic.AppStateQuerying(
			cx, sc.AppState, sc.AppStateOp, sc.AppID, sc.Account, sc.Key)
	}
}

func (tracer *evalTracer) AfterOpcode(cx *logic.EvalContext, evalError error) {
	groupIndex := cx.GroupIndex()

	// NOTE: only when we have no evalError on current opcode,
	// we can proceed for recording stack change
	if evalError == nil && tracer.result.ReturnTrace() {
		var txnTrace *TransactionTrace
		if cx.RunMode() == logic.ModeSig {
			txnTrace = tracer.result.TxnGroups[0].Txns[groupIndex].Trace
		} else {
			txnTrace = tracer.execTraceStack[len(tracer.execTraceStack)-1]
		}

		latestOpcodeTraceUnit := &(*txnTrace.programTraceRef)[len(*txnTrace.programTraceRef)-1]
		if tracer.result.ReturnStackChange() {
			latestOpcodeTraceUnit.appendAddedStackValue(cx, tracer)
		}
		if tracer.result.ReturnScratchChange() {
			latestOpcodeTraceUnit.ScratchSlotChanges = tracer.recordUpdatedScratchVars(cx)
		}
		if tracer.result.ReturnStateChange() {
			latestOpcodeTraceUnit.updateNewStateValues(cx)
		}
	}

	if cx.RunMode() == logic.ModeApp {
		if cx.TxnGroup[groupIndex].Txn.ApplicationCallTxnFields.OnCompletion != transactions.ClearStateOC {
			tracer.handleError(evalError)
		}
		if evalError == nil && tracer.unnamedResourcePolicy != nil {
			if err := tracer.unnamedResourcePolicy.tracker.reconcileBoxWriteBudget(cx.BoxDirtyBytes(), cx.Proto.BytesPerBoxReference); err != nil {
				// This should never happen, since we limit the IO budget to tracer.unnamedResourcePolicy.assignment.maxPossibleBoxIOBudget
				// (as shown below), so we should never have to reconcile an unachievable budget.
				panic(err.Error())
			}

			// Update box budget. It will decrease if an additional non-box resource has been accessed.
			cx.SetIOBudget(tracer.unnamedResourcePolicy.tracker.maxPossibleBoxIOBudget(cx.Proto.BytesPerBoxReference))
		}
	}
}

func (tracer *evalTracer) BeforeProgram(cx *logic.EvalContext) {
	groupIndex := cx.GroupIndex()

	switch cx.RunMode() {
	case logic.ModeSig:
		// Before Program, activated for logic sig, happens before txn group execution
		// we should create trace object for this txn result
		if tracer.result.ReturnTrace() {
			tracer.result.TxnGroups[0].Txns[groupIndex].Trace = &TransactionTrace{}
			traceRef := tracer.result.TxnGroups[0].Txns[groupIndex].Trace
			traceRef.programTraceRef = &traceRef.LogicSigTrace
			traceRef.LogicSigHash = crypto.Hash(cx.GetProgram())
		}
	case logic.ModeApp:
		if tracer.result.ReturnTrace() {
			txnTraceStackElem := tracer.execTraceStack[len(tracer.execTraceStack)-1]
			currentTxn := cx.EvalParams.TxnGroup[groupIndex]
			programHash := crypto.Hash(cx.GetProgram())

			switch currentTxn.Txn.ApplicationCallTxnFields.OnCompletion {
			case transactions.ClearStateOC:
				txnTraceStackElem.ClearStateProgramHash = programHash
			default:
				txnTraceStackElem.ApprovalProgramHash = programHash
			}
		}
		if tracer.result.ReturnStateChange() {
			// If we are recording state changes, including initial states,
			// then we should exclude initial states of created app during simulation.
			if cx.TxnGroup[groupIndex].SignedTxn.Txn.ApplicationID == 0 {
				tracer.result.InitialStates.CreatedApp.Add(cx.AppID())
			}
		}

		if tracer.unnamedResourcePolicy != nil {
			globalSharing := false
			for iter := cx; iter != nil; iter = iter.GetCaller() {
				if iter.ProgramVersion() >= 9 {
					// If some caller in the app callstack allows global sharing, global resources can
					// be accessed here. Otherwise the top-level txn must declare all resources locally.
					globalSharing = true
					break
				}
			}
			tracer.unnamedResourcePolicy.globalSharing = globalSharing
			tracer.unnamedResourcePolicy.programVersion = cx.ProgramVersion()
			if tracer.unnamedResourcePolicy.initialBoxSurplusReadBudget == nil {
				s := cx.SurplusReadBudget
				tracer.unnamedResourcePolicy.initialBoxSurplusReadBudget = &s
			}
			cx.SetIOBudget(tracer.unnamedResourcePolicy.tracker.maxPossibleBoxIOBudget(cx.Proto.BytesPerBoxReference))
		}
	}
}

func (tracer *evalTracer) AfterProgram(cx *logic.EvalContext, pass bool, evalError error) {
	groupIndex := cx.GroupIndex()

	if cx.RunMode() == logic.ModeSig {
		// Report cost for LogicSig program and exit
		tracer.result.TxnGroups[0].Txns[groupIndex].LogicSigBudgetConsumed = cx.Cost()
		if tracer.result.ReturnTrace() {
			tracer.result.TxnGroups[0].Txns[groupIndex].Trace.programTraceRef = nil
		}
		return
	}

	// Report cost of this program.
	// If it is an inner app call, roll up its cost to the top level transaction.
	tracer.result.TxnGroups[0].Txns[tracer.relativeCursor[0]].AppBudgetConsumed += cx.Cost()

	if cx.TxnGroup[groupIndex].Txn.ApplicationCallTxnFields.OnCompletion == transactions.ClearStateOC {
		if tracer.result.ReturnTrace() && (!pass || evalError != nil) {
			txnTrace := tracer.execTraceStack[len(tracer.execTraceStack)-1]
			txnTrace.ClearStateRollback = true
			if evalError != nil {
				txnTrace.ClearStateRollbackError = evalError.Error()
			}
		}
	} else {
		tracer.handleError(evalError)
	}

	// Since an app could rekey multiple accounts, we need to go over the
	// rest of the txngroup and make sure all the auth addrs are correct
	if tracer.result.EvalOverrides.FixSigners && len(tracer.relativeCursor) == 1 {
		knownAuthAddrs := make(map[basics.Address]basics.Address)
		// iterate over all txns in the group after this one
		for i := groupIndex + 1; i < len(cx.TxnGroup); i++ {
			stxn := &tracer.groups[0][i]
			sender := stxn.Txn.Sender

			// If we don't already know the auth addr, get it from the ledger
			if _, authAddrKnown := knownAuthAddrs[sender]; !authAddrKnown {
				// Get the auth addr from the ledger
				data, err := cx.Ledger.AccountData(sender)
				if err != nil {
					panic(err)
				}

				knownAuthAddrs[sender] = data.AuthAddr
			}

			// Fix the current auth addr if this txn doesn't have a signature
			if txnHasNoSignature(stxn.SignedTxn) {
				stxn.AuthAddr = knownAuthAddrs[sender]
				if stxn.AuthAddr == sender {
					stxn.AuthAddr = basics.Address{}
				}
			}

			// If this is an appl, we can break since we know AfterProgram will be called afterwards
			if stxn.Txn.Type == protocol.ApplicationCallTx {
				break
			}

			// If this is a rekey, save the auth addr for the sender
			if stxn.Txn.RekeyTo != (basics.Address{}) {
				knownAuthAddrs[sender] = stxn.Txn.RekeyTo
			}
		}
	}
}

func (tracer *evalTracer) DetailedEvalErrors() bool { return true }
