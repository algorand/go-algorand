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

package mockdebugger

import (
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// EventType represents a type of logic.DebuggerHook event
type EventType string

const (
	// BeforeLogicEvalEvent represents the logic.DebuggerHook.BeforeLogicEval event
	BeforeLogicEvalEvent EventType = "BeforeLogicEval"
	// AfterLogicEvalEvent represents the logic.DebuggerHook.AfterLogicEval event
	AfterLogicEvalEvent EventType = "AfterLogicEval"
	// BeforeTxnEvent represents the logic.DebuggerHook.BeforeTxn event
	BeforeTxnEvent EventType = "BeforeTxn"
	// AfterTxnEvent represents the logic.DebuggerHook.AfterTxn event
	AfterTxnEvent EventType = "AfterTxn"
	// BeforeTealOpEvent represents the logic.DebuggerHook.BeforeTealOp event
	BeforeTealOpEvent EventType = "BeforeTealOp"
	// AfterTealOpEvent represents the logic.DebuggerHook.AfterTealOp event
	AfterTealOpEvent EventType = "AfterTealOp"
	// BeforeInnerTxnGroupEvent represents the logic.DebuggerHook.BeforeInnerTxnGroup event
	BeforeInnerTxnGroupEvent EventType = "BeforeInnerTxnGroup"
	// AfterInnerTxnGroupEvent represents the logic.DebuggerHook.AfterInnerTxnGroup event
	AfterInnerTxnGroupEvent EventType = "AfterInnerTxnGroup"
)

// Event represents a logic.DebuggerHook event
type Event struct {
	Type EventType

	// only for BeforeLogicEval and AfterLogicEval
	LogicEvalMode logic.RunMode

	// only for BeforeTxn and AfterTxn
	TxnType protocol.TxType

	// only for AfterTxn
	TxnApplyData transactions.ApplyData

	// only for BeforeInnerTxnGroup and AfterInnerTxnGroup
	InnerGroupSize int
}

// BeforeLogicEval creates a new Event with the type BeforeLogicEvalEvent
func BeforeLogicEval(mode logic.RunMode) Event {
	return Event{Type: BeforeLogicEvalEvent, LogicEvalMode: mode}
}

// AfterLogicEval creates a new Event with the type AfterLogicEvalEvent
func AfterLogicEval(mode logic.RunMode) Event {
	return Event{Type: AfterLogicEvalEvent, LogicEvalMode: mode}
}

// BeforeTxn creates a new Event with the type BeforeTxnEvent
func BeforeTxn(txnType protocol.TxType) Event {
	return Event{Type: BeforeTxnEvent, TxnType: txnType}
}

// AfterTxn creates a new Event with the type AfterTxnEvent
func AfterTxn(txnType protocol.TxType, ad transactions.ApplyData) Event {
	return Event{Type: AfterTxnEvent, TxnType: txnType, TxnApplyData: ad}
}

// BeforeTealOp creates a new Event with the type BeforeTealOpEvent
func BeforeTealOp() Event {
	return Event{Type: BeforeTealOpEvent}
}

// AfterTealOp creates a new Event with the type AfterTealOpEvent
func AfterTealOp() Event {
	return Event{Type: AfterTealOpEvent}
}

// BeforeInnerTxnGroup creates a new Event with the type BeforeInnerTxnGroupEvent
func BeforeInnerTxnGroup(groupSize int) Event {
	return Event{Type: BeforeInnerTxnGroupEvent, InnerGroupSize: groupSize}
}

// AfterInnerTxnGroup creates a new Event with the type AfterInnerTxnGroupEvent
func AfterInnerTxnGroup(groupSize int) Event {
	return Event{Type: AfterInnerTxnGroupEvent, InnerGroupSize: groupSize}
}

// Debugger is a mock debugger that implements logic.DebuggerHook
type Debugger struct {
	Events []Event
}

// BeforeLogicEval mocks the logic.Debugger.BeforeLogicEval method
func (d *Debugger) BeforeLogicEval(cx *logic.EvalContext) error {
	d.Events = append(d.Events, BeforeLogicEval(cx.RunMode()))
	return nil
}

// AfterLogicEval mocks the logic.Debugger.AfterLogicEval method
func (d *Debugger) AfterLogicEval(cx *logic.EvalContext, evalError error) error {
	d.Events = append(d.Events, AfterLogicEval(cx.RunMode()))
	return nil
}

// BeforeTxn mocks the logic.Debugger.BeforeTxn method
func (d *Debugger) BeforeTxn(ep *logic.EvalParams, groupIndex int) error {
	d.Events = append(d.Events, BeforeTxn(ep.TxnGroup[groupIndex].Txn.Type))
	return nil
}

// AfterTxn mocks the logic.Debugger.AfterTxn method
func (d *Debugger) AfterTxn(ep *logic.EvalParams, groupIndex int, ad transactions.ApplyData) error {
	d.Events = append(d.Events, AfterTxn(ep.TxnGroup[groupIndex].Txn.Type, ad))
	return nil
}

// BeforeTealOp mocks the logic.Debugger.BeforeTealOp method
func (d *Debugger) BeforeTealOp(cx *logic.EvalContext) error {
	d.Events = append(d.Events, BeforeTealOp())
	return nil
}

// AfterTealOp mocks the logic.Debugger.AfterTealOp method
func (d *Debugger) AfterTealOp(cx *logic.EvalContext, evalError error) error {
	d.Events = append(d.Events, AfterTealOp())
	return nil
}

// BeforeInnerTxnGroup mocks the logic.Debugger.BeforeInnerTxnGroup method
func (d *Debugger) BeforeInnerTxnGroup(ep *logic.EvalParams) error {
	d.Events = append(d.Events, BeforeInnerTxnGroup(len(ep.TxnGroup)))
	return nil
}

// AfterInnerTxnGroup mocks the logic.Debugger.AfterInnerTxnGroup method
func (d *Debugger) AfterInnerTxnGroup(ep *logic.EvalParams) error {
	d.Events = append(d.Events, AfterInnerTxnGroup(len(ep.TxnGroup)))
	return nil
}
