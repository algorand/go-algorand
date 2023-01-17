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
//   │ > BeforeProgram         │
//   │                         │
//   │  ┌───────────────────┐  │
//   │  │ Teal Operation    │  │
//   │  ├───────────────────┤  │
//   │  │ > BeforeOpcode    │  │
//   │  │                   │  │
//   │  │ > AfterOpcode     │  │
//   │  └───────────────────┘  │
//   |   ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞   │
//   │                         │
//   │ > AfterProgram          │
//   └─────────────────────────┘
//
//   APP LIFECYCLE GRAPH
//   ┌──────────────────────────────────────────────────────┐
//   │ Transaction Evaluation                               │
//   ├──────────────────────────────────────────────────────┤
//   │ > BeforeTxnGroup                                     │
//   │                                                      │
//   │  ┌────────────────────────────────────────────────┐  │
//   │  │ > BeforeTxn                                    │  │
//   │  │                                                │  │
//   │  │  ┌──────────────────────────────────────────┐  │  │
//   │  │  │ ? App Call                               │  │  │
//   │  │  ├──────────────────────────────────────────┤  │  │
//   │  │  │ > BeforeProgram                          │  │  │
//   │  │  │                                          │  │  │
//   │  │  │  ┌────────────────────────────────────┐  │  │  │
//   │  │  │  │ Teal Operation                     │  │  │  │
//   │  │  │  ├────────────────────────────────────┤  │  │  │
//   │  │  │  │ > BeforeOpcode                     │  │  │  │
//   │  │  │  │  ┌──────────────────────────────┐  │  │  │  │
//   │  │  │  │  │ ? Inner Transaction Group    │  │  │  │  │
//   │  │  │  │  ├──────────────────────────────┤  │  │  │  │
//   │  │  │  │  │ > BeforeTxnGroup             │  │  │  │  │
//   │  │  │  │  │  ┌────────────────────────┐  │  │  │  │  │
//   │  │  │  │  │  │ Transaction Evaluation │  │  │  │  │  │
//   │  │  │  │  │  ├────────────────────────┤  │  │  │  │  │
//   │  │  │  │  │  │ ...                    │  │  │  │  │  │
//   │  │  │  │  │  └────────────────────────┘  │  │  │  │  │
//   │  │  │  │  │    ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞    │  │  │  │  │
//   │  │  │  │  │                              │  │  │  │  │
//   │  │  │  │  │ > AfterTxnGroup              │  │  │  │  │
//   │  │  │  │  └──────────────────────────────┘  │  │  │  │
//   │  │  │  │ > AfterOpcode                      │  │  │  │
//   │  │  │  └────────────────────────────────────┘  │  │  │
//   │  │  │    ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞    │  │  │
//   │  │  │                                          │  │  │
//   │  │  │ > AfterProgram                           │  │  │
//   │  │  └──────────────────────────────────────────┘  │  │
//   |  |    ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞    │  |
//   │  │                                                │  │
//   │  │ > AfterTxn                                     │  │
//   │  └────────────────────────────────────────────────┘  │
//   |    ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞  ⁞    |
//   │                                                      │
//   │ > AfterTxnGroup                                      │
//   └──────────────────────────────────────────────────────┘
type EvalTracer interface {
	// BeforeTxnGroup is called before a transaction group is executed. This includes both top-level
	// and inner transaction groups. The argument ep is the EvalParams object for the group; if the
	// group is an inner group, this is the EvalParams object for the inner group.
	//
	// Each transaction within the group calls BeforeTxn and subsequent hooks, as described in the
	// lifecycle diagram.
	BeforeTxnGroup(ep *EvalParams)

	// AfterTxnGroup is called after a transaction group has been executed. This includes both
	// top-level and inner transaction groups. The argument ep is the EvalParams object for the
	// group; if the group is an inner group, this is the EvalParams object for the inner group.
	AfterTxnGroup(ep *EvalParams)

	// BeforeTxn is called before a transaction is executed.
	//
	// groupIndex refers to the index of the transaction in the transaction group that will be executed.
	BeforeTxn(ep *EvalParams, groupIndex int)

	// AfterTxn is called after a transaction has been executed.
	//
	// groupIndex refers to the index of the transaction in the transaction group that was just executed.
	// ad is the ApplyData result of the transaction; prefer using this instead of
	// ep.TxnGroup[groupIndex].ApplyData, since it may not be populated at this point.
	AfterTxn(ep *EvalParams, groupIndex int, ad transactions.ApplyData)

	// BeforeProgram is called before an app or LogicSig program is evaluated.
	BeforeProgram(cx *EvalContext)

	// AfterProgram is called after an app or LogicSig program is evaluated.
	AfterProgram(cx *EvalContext, evalError error)

	// BeforeOpcode is called before the op is evaluated
	BeforeOpcode(cx *EvalContext)

	// AfterOpcode is called after the op has been evaluated
	AfterOpcode(cx *EvalContext, evalError error)
}

// NullEvalTracer implements EvalTracer, but all of its hook methods do nothing
type NullEvalTracer struct{}

// BeforeTxnGroup does nothing
func (n NullEvalTracer) BeforeTxnGroup(ep *EvalParams) {}

// AfterTxnGroup does nothing
func (n NullEvalTracer) AfterTxnGroup(ep *EvalParams) {}

// BeforeTxn does nothing
func (n NullEvalTracer) BeforeTxn(ep *EvalParams, groupIndex int) {}

// AfterTxn does nothing
func (n NullEvalTracer) AfterTxn(ep *EvalParams, groupIndex int, ad transactions.ApplyData) {}

// BeforeProgram does nothing
func (n NullEvalTracer) BeforeProgram(cx *EvalContext) {}

// AfterProgram does nothing
func (n NullEvalTracer) AfterProgram(cx *EvalContext, evalError error) {}

// BeforeOpcode does nothing
func (n NullEvalTracer) BeforeOpcode(cx *EvalContext) {}

// AfterOpcode does nothing
func (n NullEvalTracer) AfterOpcode(cx *EvalContext, evalError error) {}
