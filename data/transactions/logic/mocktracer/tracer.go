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
	// BeforeProgramEvent represents the logic.EvalTracer.BeforeProgram event
	BeforeProgramEvent EventType = "BeforeProgram"
	// AfterProgramEvent represents the logic.EvalTracer.AfterProgram event
	AfterProgramEvent EventType = "AfterProgram"
	// BeforeTxnEvent represents the logic.EvalTracer.BeforeTxn event
	BeforeTxnEvent EventType = "BeforeTxn"
	// AfterTxnEvent represents the logic.EvalTracer.AfterTxn event
	AfterTxnEvent EventType = "AfterTxn"
	// BeforeOpcodeEvent represents the logic.EvalTracer.BeforeOpcode event
	BeforeOpcodeEvent EventType = "BeforeOpcode"
	// AfterOpcodeEvent represents the logic.EvalTracer.AfterOpcode event
	AfterOpcodeEvent EventType = "AfterOpcode"
	// BeforeInnerTxnGroupEvent represents the logic.EvalTracer.BeforeInnerTxnGroup event
	BeforeInnerTxnGroupEvent EventType = "BeforeInnerTxnGroup"
	// AfterInnerTxnGroupEvent represents the logic.EvalTracer.AfterInnerTxnGroup event
	AfterInnerTxnGroupEvent EventType = "AfterInnerTxnGroup"
)

// Event represents a logic.EvalTracer event
type Event struct {
	Type EventType

	// only for BeforeProgram and AfterProgram
	LogicEvalMode logic.RunMode

	// only for BeforeTxn and AfterTxn
	TxnType protocol.TxType

	// only for AfterTxn
	TxnApplyData transactions.ApplyData

	// only for BeforeInnerTxnGroup and AfterInnerTxnGroup
	InnerGroupSize int
}

// BeforeProgram creates a new Event with the type BeforeProgramEvent
func BeforeProgram(mode logic.RunMode) Event {
	return Event{Type: BeforeProgramEvent, LogicEvalMode: mode}
}

// AfterProgram creates a new Event with the type AfterProgramEvent
func AfterProgram(mode logic.RunMode) Event {
	return Event{Type: AfterProgramEvent, LogicEvalMode: mode}
}

// BeforeTxn creates a new Event with the type BeforeTxnEvent
func BeforeTxn(txnType protocol.TxType) Event {
	return Event{Type: BeforeTxnEvent, TxnType: txnType}
}

// AfterTxn creates a new Event with the type AfterTxnEvent
func AfterTxn(txnType protocol.TxType, ad transactions.ApplyData) Event {
	return Event{Type: AfterTxnEvent, TxnType: txnType, TxnApplyData: ad}
}

// BeforeOpcode creates a new Event with the type BeforeOpcodeEvent
func BeforeOpcode() Event {
	return Event{Type: BeforeOpcodeEvent}
}

// AfterOpcode creates a new Event with the type AfterOpcodeEvent
func AfterOpcode() Event {
	return Event{Type: AfterOpcodeEvent}
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

// BeforeProgram mocks the logic.EvalTracer.BeforeProgram method
func (d *Tracer) BeforeProgram(cx *logic.EvalContext) {
	d.Events = append(d.Events, BeforeProgram(cx.RunMode()))
}

// AfterProgram mocks the logic.EvalTracer.AfterProgram method
func (d *Tracer) AfterProgram(cx *logic.EvalContext, evalError error) {
	d.Events = append(d.Events, AfterProgram(cx.RunMode()))
}

// BeforeTxn mocks the logic.EvalTracer.BeforeTxn method
func (d *Tracer) BeforeTxn(ep *logic.EvalParams, groupIndex int) {
	d.Events = append(d.Events, BeforeTxn(ep.TxnGroup[groupIndex].Txn.Type))
}

// AfterTxn mocks the logic.EvalTracer.AfterTxn method
func (d *Tracer) AfterTxn(ep *logic.EvalParams, groupIndex int, ad transactions.ApplyData) {
	d.Events = append(d.Events, AfterTxn(ep.TxnGroup[groupIndex].Txn.Type, ad))
}

// BeforeOpcode mocks the logic.EvalTracer.BeforeOpcode method
func (d *Tracer) BeforeOpcode(cx *logic.EvalContext) {
	d.Events = append(d.Events, BeforeOpcode())
}

// AfterOpcode mocks the logic.EvalTracer.AfterOpcode method
func (d *Tracer) AfterOpcode(cx *logic.EvalContext, evalError error) {
	d.Events = append(d.Events, AfterOpcode())
}

// BeforeInnerTxnGroup mocks the logic.EvalTracer.BeforeInnerTxnGroup method
func (d *Tracer) BeforeInnerTxnGroup(ep *logic.EvalParams) {
	d.Events = append(d.Events, BeforeInnerTxnGroup(len(ep.TxnGroup)))
}

// AfterInnerTxnGroup mocks the logic.EvalTracer.AfterInnerTxnGroup method
func (d *Tracer) AfterInnerTxnGroup(ep *logic.EvalParams) {
	d.Events = append(d.Events, AfterInnerTxnGroup(len(ep.TxnGroup)))
}
