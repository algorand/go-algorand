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

package mocktracer

import (
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// EventType represents a type of logic.EvalTracer event
type EventType string

const (
	// BeforeLogicEvalEvent represents the logic.EvalTracer.BeforeLogicEval event
	BeforeLogicEvalEvent EventType = "BeforeLogicEval"
	// AfterLogicEvalEvent represents the logic.EvalTracer.AfterLogicEval event
	AfterLogicEvalEvent EventType = "AfterLogicEval"
	// BeforeTxnEvent represents the logic.EvalTracer.BeforeTxn event
	BeforeTxnEvent EventType = "BeforeTxn"
	// AfterTxnEvent represents the logic.EvalTracer.AfterTxn event
	AfterTxnEvent EventType = "AfterTxn"
	// BeforeTealOpEvent represents the logic.EvalTracer.BeforeTealOp event
	BeforeTealOpEvent EventType = "BeforeTealOp"
	// AfterTealOpEvent represents the logic.EvalTracer.AfterTealOp event
	AfterTealOpEvent EventType = "AfterTealOp"
	// BeforeInnerTxnGroupEvent represents the logic.EvalTracer.BeforeInnerTxnGroup event
	BeforeInnerTxnGroupEvent EventType = "BeforeInnerTxnGroup"
	// AfterInnerTxnGroupEvent represents the logic.EvalTracer.AfterInnerTxnGroup event
	AfterInnerTxnGroupEvent EventType = "AfterInnerTxnGroup"
)

// Event represents a logic.EvalTracer event
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

// Tracer is a mock tracer that implements logic.EvalTracer
type Tracer struct {
	Events []Event
}

// BeforeLogicEval mocks the logic.EvalTracer.BeforeLogicEval method
func (d *Tracer) BeforeLogicEval(cx *logic.EvalContext) {
	d.Events = append(d.Events, BeforeLogicEval(cx.RunMode()))
}

// AfterLogicEval mocks the logic.EvalTracer.AfterLogicEval method
func (d *Tracer) AfterLogicEval(cx *logic.EvalContext, evalError error) {
	d.Events = append(d.Events, AfterLogicEval(cx.RunMode()))
}

// BeforeTxn mocks the logic.EvalTracer.BeforeTxn method
func (d *Tracer) BeforeTxn(ep *logic.EvalParams, groupIndex int) {
	d.Events = append(d.Events, BeforeTxn(ep.TxnGroup[groupIndex].Txn.Type))
}

// AfterTxn mocks the logic.EvalTracer.AfterTxn method
func (d *Tracer) AfterTxn(ep *logic.EvalParams, groupIndex int, ad transactions.ApplyData) {
	d.Events = append(d.Events, AfterTxn(ep.TxnGroup[groupIndex].Txn.Type, ad))
}

// BeforeTealOp mocks the logic.EvalTracer.BeforeTealOp method
func (d *Tracer) BeforeTealOp(cx *logic.EvalContext) {
	d.Events = append(d.Events, BeforeTealOp())
}

// AfterTealOp mocks the logic.EvalTracer.AfterTealOp method
func (d *Tracer) AfterTealOp(cx *logic.EvalContext, evalError error) {
	d.Events = append(d.Events, AfterTealOp())
}

// BeforeInnerTxnGroup mocks the logic.EvalTracer.BeforeInnerTxnGroup method
func (d *Tracer) BeforeInnerTxnGroup(ep *logic.EvalParams) {
	d.Events = append(d.Events, BeforeInnerTxnGroup(len(ep.TxnGroup)))
}

// AfterInnerTxnGroup mocks the logic.EvalTracer.AfterInnerTxnGroup method
func (d *Tracer) AfterInnerTxnGroup(ep *logic.EvalParams) {
	d.Events = append(d.Events, AfterInnerTxnGroup(len(ep.TxnGroup)))
}
