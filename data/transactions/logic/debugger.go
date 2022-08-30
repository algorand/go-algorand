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

package logic

// DebuggerHook functions are called by eval function during TEAL program execution
// if provided. The interface is empty because none of the hooks are required by default.
//
// See `debuggerBeforeTxnHook`, `debuggerBeforeAppEvalHook`, etc. for supported
// interface methods and refer to the lifecycle graph within the DebuggerHook interface definition for
// the sequence in which hooks are called.
//
// NOTE: Debugger hooks are passed by reference to DebugState and EvalParams and are not copies.
// It is therefore the responsibility of the debugger hooks to not modify the state of the structs
// passed to them. Additionally, hooks are responsible for copying the information
// they need from the state and params structs. No guarantees are made that the referenced state
// will not change between hook calls. This decision was made in an effort to reduce the performance
// impact of the debugger hooks.
type DebuggerHook interface {

	// LOGICSIG LIFECYCLE GRAPH
	// ┌─────────────────────────┐
	// │ LogicSig Evaluation     │
	// ├─────────────────────────┤
	// │ > BeforeLogicSigEval    │
	// │                         │
	// │  ┌───────────────────┐  │
	// │  │ Teal Operation    │  │
	// │  ├───────────────────┤  │
	// │  │ > BeforeTealOp    │  │
	// │  │                   │  │
	// │  │ > AfterTealOp     │  │
	// │  └───────────────────┘  │
	// |   ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞   │
	// │                         │
	// │ > AfterLogicSigEval     │
	// └─────────────────────────┘

	// APP LIFECYCLE GRAPH
	// ┌────────────────────────────────────────────────┐
	// │ Transaction Evaluation                         │
	// ├────────────────────────────────────────────────┤
	// │ > BeforeTxn                                    │
	// │                                                │
	// │  ┌──────────────────────────────────────────┐  │
	// │  │ ? App Call                               │  │
	// │  ├──────────────────────────────────────────┤  │
	// │  │ > BeforeAppEval                          │  │
	// │  │                                          │  │
	// │  │  ┌────────────────────────────────────┐  │  │
	// │  │  │ Teal Operation                     │  │  │
	// │  │  ├────────────────────────────────────┤  │  │
	// │  │  │ > BeforeTealOp                     │  │  │
	// │  │  │  ┌──────────────────────────────┐  │  │  │
	// │  │  │  │ ? Inner Transaction Group    │  │  │  │
	// │  │  │  ├──────────────────────────────┤  │  │  │
	// │  │  │  │ > BeforeInnerTxnGroup        │  │  │  │
	// │  │  │  │  ┌────────────────────────┐  │  │  │  │
	// │  │  │  │  │ Transaction Evaluation │  │  │  │  │
	// │  │  │  │  ├────────────────────────┤  │  │  │  │
	// │  │  │  │  │ ...                    │  │  │  │  │
	// │  │  │  │  └────────────────────────┘  │  │  │  │
	// │  │  │  │    ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞    │  │  │  │
	// │  │  │  │                              │  │  │  │
	// │  │  │  │ > AfterInnerTxnGroup         │  │  │  │
	// │  │  │  └──────────────────────────────┘  │  │  │
	// │  │  │ > AfterTealOp                      │  │  │
	// │  │  └────────────────────────────────────┘  │  │
	// │  │    ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞    │  │
	// │  │                                          │  │
	// │  │ > AfterAppEval                           │  │
	// │  └──────────────────────────────────────────┘  │
	// |    ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞    │
	// │                                                │
	// │ > AfterTxn                                     │
	// └────────────────────────────────────────────────┘

	// BeforeTxn is called before a transaction is executed.
	// groupIndex refers to the index of the transaction in the transaction group that was just executed.
	BeforeTxn(ep *EvalParams, groupIndex int) error

	// AfterTxn is called after a transaction has been executed.
	// groupIndex refers to the index of the transaction in the transaction group that was just executed.
	AfterTxn(ep *EvalParams, groupIndex int) error

	// BeforeInnerTxnGroup is called before an inner transaction group is executed.
	// Each inner transaction within the group calls BeforeTxn and subsequent hooks, as described
	// in the lifecycle diagram.
	BeforeInnerTxnGroup(ep *EvalParams) error

	// AfterInnerTxnGroup is called after an inner transaction group has been executed.
	AfterInnerTxnGroup(ep *EvalParams) error
}

type debuggerBeforeAppEvalHook interface {
	// BeforeAppEval is called before the app is evaluated.
	// This hook is similar to BeforeTxn, but includes debug state information instead of eval params.
	BeforeAppEval(state *DebugState) error
}

type debuggerAfterAppEvalHook interface {
	// AfterAppEval is called after the app has been evaluated.
	AfterAppEval(state *DebugState) error
}

type debuggerBeforeLogicSigEvalHook interface {
	// BeforeLogicSigEval is called before the LogicSig is evaluated.
	// This hook is similar to BeforeAppEval, but indicates the start of a LogicSig's evaluation instead.
	BeforeLogicSigEval(state *DebugState) error
}

type debuggerAfterLogicSigEvalHook interface {
	// AfterLogicSigEval is called after the LogicSig is evaluated.
	AfterLogicSigEval(state *DebugState) error
}

type debuggerBeforeTealOpHook interface {
	// BeforeTealOp is called before the op is evaluated
	BeforeTealOp(state *DebugState) error
}

type debuggerAfterTealOpHook interface {
	// AfterTealOp is called after the op has been evaluated
	AfterTealOp(state *DebugState) error
}
