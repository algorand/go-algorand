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

import "fmt"

// DebuggerHook functions are called by eval function during TEAL program execution, if a debugger
// is provided.
//
// There are 4 required debugger hook functions:
//   - BeforeTxn
//   - AfterTxn
//   - BeforeInnerTxnGroup
//   - AfterInnerTxnGroup
//
// And 4 optional ones:
//   - BeforeLogicEval
//   - AfterLogicEval
//   - BeforeTealOp
//   - AfterTealOp
//
// Refer to the lifecycle graph below for the sequence in which hooks are called.
//
// See the interfaces `debuggerBeforeLogicEvalHook`, `debuggerAfterLogicEvalHook`, etc. for the
// optional hook function definitions.
//
// NOTE: Arguments given to Debugger hooks (EvalParams and EvalContext) are passed by reference,
// they are not copies. It is therefore the responsibility of the debugger hooks to NOT modify the
// state of the structs passed to them. Additionally, hooks are responsible for copying the information
// they need from the argument structs. No guarantees are made that the referenced state will not
// change between hook calls. This decision was made in an effort to reduce the performance
// impact of the debugger hooks.
//
//   LOGICSIG LIFECYCLE GRAPH
//   ┌─────────────────────────┐
//   │ LogicSig Evaluation     │
//   ├─────────────────────────┤
//   │ > BeforeLogicEval       │
//   │                         │
//   │  ┌───────────────────┐  │
//   │  │ Teal Operation    │  │
//   │  ├───────────────────┤  │
//   │  │ > BeforeTealOp    │  │
//   │  │                   │  │
//   │  │ > AfterTealOp     │  │
//   │  └───────────────────┘  │
//   |   ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞   │
//   │                         │
//   │ > AfterLogicEval        │
//   └─────────────────────────┘
//
//   APP LIFECYCLE GRAPH
//   ┌────────────────────────────────────────────────┐
//   │ Transaction Evaluation                         │
//   ├────────────────────────────────────────────────┤
//   │ > BeforeTxn                                    │
//   │                                                │
//   │  ┌──────────────────────────────────────────┐  │
//   │  │ ? App Call                               │  │
//   │  ├──────────────────────────────────────────┤  │
//   │  │ > BeforeLogicEval                        │  │
//   │  │                                          │  │
//   │  │  ┌────────────────────────────────────┐  │  │
//   │  │  │ Teal Operation                     │  │  │
//   │  │  ├────────────────────────────────────┤  │  │
//   │  │  │ > BeforeTealOp                     │  │  │
//   │  │  │  ┌──────────────────────────────┐  │  │  │
//   │  │  │  │ ? Inner Transaction Group    │  │  │  │
//   │  │  │  ├──────────────────────────────┤  │  │  │
//   │  │  │  │ > BeforeInnerTxnGroup        │  │  │  │
//   │  │  │  │  ┌────────────────────────┐  │  │  │  │
//   │  │  │  │  │ Transaction Evaluation │  │  │  │  │
//   │  │  │  │  ├────────────────────────┤  │  │  │  │
//   │  │  │  │  │ ...                    │  │  │  │  │
//   │  │  │  │  └────────────────────────┘  │  │  │  │
//   │  │  │  │    ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞    │  │  │  │
//   │  │  │  │                              │  │  │  │
//   │  │  │  │ > AfterInnerTxnGroup         │  │  │  │
//   │  │  │  └──────────────────────────────┘  │  │  │
//   │  │  │ > AfterTealOp                      │  │  │
//   │  │  └────────────────────────────────────┘  │  │
//   │  │    ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞    │  │
//   │  │                                          │  │
//   │  │ > AfterLogicEval                         │  │
//   │  └──────────────────────────────────────────┘  │
//   |    ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞    │
//   │                                                │
//   │ > AfterTxn                                     │
//   └────────────────────────────────────────────────┘
type DebuggerHook interface {
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

type debuggerBeforeLogicEvalHook interface {
	// BeforeLogicEval is called before an app or LogicSig is evaluated.
	BeforeLogicEval(cx *EvalContext) error
}

func callBeforeLogicHookIfItExists(dh DebuggerHook, cx *EvalContext) error {
	if dh == nil {
		return nil
	}
	hook, ok := dh.(debuggerBeforeLogicEvalHook)
	if !ok {
		return nil
	}
	err := hook.BeforeLogicEval(cx)
	if err != nil {
		return fmt.Errorf("error while running debugger BeforeLogicEval hook: %w", err)
	}
	return nil
}

type debuggerAfterLogicEvalHook interface {
	// AfterLogicEval is called after an app or LogicSig is evaluated.
	AfterLogicEval(cx *EvalContext, evalError error) error
}

func callAfterLogicHookIfItExists(dh DebuggerHook, cx *EvalContext, evalError error) error {
	if dh == nil {
		return nil
	}
	hook, ok := dh.(debuggerAfterLogicEvalHook)
	if !ok {
		return nil
	}
	err := hook.AfterLogicEval(cx, evalError)
	if err != nil {
		return fmt.Errorf("error while running debugger AfterLogicEval hook: %w", err)
	}
	return nil
}

type debuggerBeforeTealOpHook interface {
	// BeforeTealOp is called before the op is evaluated
	BeforeTealOp(cx *EvalContext) error
}

func callBeforeTealOpHookIfItExists(dh DebuggerHook, cx *EvalContext) error {
	if dh == nil {
		return nil
	}
	hook, ok := dh.(debuggerBeforeTealOpHook)
	if !ok {
		return nil
	}
	err := hook.BeforeTealOp(cx)
	if err != nil {
		return fmt.Errorf("error while running debugger BeforeTealOp hook: %w", err)
	}
	return nil
}

type debuggerAfterTealOpHook interface {
	// AfterTealOp is called after the op has been evaluated
	AfterTealOp(cx *EvalContext, evalError error) error
}

func callAfterTealOpHookIfItExists(dh DebuggerHook, cx *EvalContext, evalError error) error {
	if dh == nil {
		return nil
	}
	hook, ok := dh.(debuggerAfterTealOpHook)
	if !ok {
		return nil
	}
	err := hook.AfterTealOp(cx, evalError)
	if err != nil {
		return fmt.Errorf("error while running debugger AfterTealOp hook: %w", err)
	}
	return nil
}
