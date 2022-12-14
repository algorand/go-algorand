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

import "github.com/algorand/go-algorand/data/transactions"

// EvalTracer functions are called by eval function during AVM program execution, if a tracer
// is provided.
//
// Refer to the lifecycle graph below for the sequence in which hooks are called.
//
// NOTE: Arguments given to Tracer hooks (EvalParams and EvalContext) are passed by reference,
// they are not copies. It is therefore the responsibility of the tracer implementation to NOT
// modify the state of the structs passed to them. Additionally, hooks are responsible for copying
// the information they need from the argument structs. No guarantees are made that the referenced
// state will not change between hook calls. This decision was made in an effort to reduce the
// performance impact of tracers.
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
type EvalTracer interface {
	// BeforeTxn is called before a transaction is executed.
	// groupIndex refers to the index of the transaction in the transaction group that was just executed.
	BeforeTxn(ep *EvalParams, groupIndex int)

	// AfterTxn is called after a transaction has been executed.
	// groupIndex refers to the index of the transaction in the transaction group that was just executed.
	AfterTxn(ep *EvalParams, groupIndex int, ad transactions.ApplyData)

	// BeforeLogicEval is called before an app or LogicSig is evaluated.
	BeforeLogicEval(cx *EvalContext)

	// AfterLogicEval is called after an app or LogicSig is evaluated.
	AfterLogicEval(cx *EvalContext, evalError error)

	// BeforeTealOp is called before the op is evaluated
	BeforeTealOp(cx *EvalContext)

	// AfterTealOp is called after the op has been evaluated
	AfterTealOp(cx *EvalContext, evalError error)

	// BeforeInnerTxnGroup is called before an inner transaction group is executed.
	// Each inner transaction within the group calls BeforeTxn and subsequent hooks, as described
	// in the lifecycle diagram.
	BeforeInnerTxnGroup(ep *EvalParams)

	// AfterInnerTxnGroup is called after an inner transaction group has been executed.
	AfterInnerTxnGroup(ep *EvalParams)
}

// NullEvalTracer implements EvalTracer, but all of its hook methods do nothing
type NullEvalTracer struct{}

// BeforeTxn does nothing
func (n NullEvalTracer) BeforeTxn(ep *EvalParams, groupIndex int) {}

// AfterTxn does nothing
func (n NullEvalTracer) AfterTxn(ep *EvalParams, groupIndex int, ad transactions.ApplyData) {}

// BeforeLogicEval does nothing
func (n NullEvalTracer) BeforeLogicEval(cx *EvalContext) {}

// AfterLogicEval does nothing
func (n NullEvalTracer) AfterLogicEval(cx *EvalContext, evalError error) {}

// BeforeTealOp does nothing
func (n NullEvalTracer) BeforeTealOp(cx *EvalContext) {}

// AfterTealOp does nothing
func (n NullEvalTracer) AfterTealOp(cx *EvalContext, evalError error) {}

// BeforeInnerTxnGroup does nothing
func (n NullEvalTracer) BeforeInnerTxnGroup(ep *EvalParams) {}

// AfterInnerTxnGroup does nothing
func (n NullEvalTracer) AfterInnerTxnGroup(ep *EvalParams) {}
