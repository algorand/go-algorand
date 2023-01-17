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

package mocktracer

import (
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// EventType represents a type of logic.EvalTracer event
type EventType string

const (
	// BeforeTxnGroupEvent represents the logic.EvalTracer.BeforeTxnGroup event
	BeforeTxnGroupEvent EventType = "BeforeTxnGroup"
	// AfterTxnGroupEvent represents the logic.EvalTracer.AfterTxnGroup event
	AfterTxnGroupEvent EventType = "AfterTxnGroup"
	// BeforeTxnEvent represents the logic.EvalTracer.BeforeTxn event
	BeforeTxnEvent EventType = "BeforeTxn"
	// AfterTxnEvent represents the logic.EvalTracer.AfterTxn event
	AfterTxnEvent EventType = "AfterTxn"
	// BeforeProgramEvent represents the logic.EvalTracer.BeforeProgram event
	BeforeProgramEvent EventType = "BeforeProgram"
	// AfterProgramEvent represents the logic.EvalTracer.AfterProgram event
	AfterProgramEvent EventType = "AfterProgram"
	// BeforeOpcodeEvent represents the logic.EvalTracer.BeforeOpcode event
	BeforeOpcodeEvent EventType = "BeforeOpcode"
	// AfterOpcodeEvent represents the logic.EvalTracer.AfterOpcode event
	AfterOpcodeEvent EventType = "AfterOpcode"
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

	// only for BeforeTxnGroup and AfterTxnGroup
	GroupSize int
}

// BeforeTxnGroup creates a new Event with the type BeforeTxnGroupEvent
func BeforeTxnGroup(groupSize int) Event {
	return Event{Type: BeforeTxnGroupEvent, GroupSize: groupSize}
}

// AfterTxnGroup creates a new Event with the type AfterTxnGroupEvent
func AfterTxnGroup(groupSize int) Event {
	return Event{Type: AfterTxnGroupEvent, GroupSize: groupSize}
}

// BeforeProgram creates a new Event with the type BeforeProgramEvent
func BeforeProgram(mode logic.RunMode) Event {
	return Event{Type: BeforeProgramEvent, LogicEvalMode: mode}
}

// BeforeTxn creates a new Event with the type BeforeTxnEvent
func BeforeTxn(txnType protocol.TxType) Event {
	return Event{Type: BeforeTxnEvent, TxnType: txnType}
}

// AfterTxn creates a new Event with the type AfterTxnEvent
func AfterTxn(txnType protocol.TxType, ad transactions.ApplyData) Event {
	return Event{Type: AfterTxnEvent, TxnType: txnType, TxnApplyData: ad}
}

// AfterProgram creates a new Event with the type AfterProgramEvent
func AfterProgram(mode logic.RunMode) Event {
	return Event{Type: AfterProgramEvent, LogicEvalMode: mode}
}

// BeforeOpcode creates a new Event with the type BeforeOpcodeEvent
func BeforeOpcode() Event {
	return Event{Type: BeforeOpcodeEvent}
}

// AfterOpcode creates a new Event with the type AfterOpcodeEvent
func AfterOpcode() Event {
	return Event{Type: AfterOpcodeEvent}
}

// Tracer is a mock tracer that implements logic.EvalTracer
type Tracer struct {
	Events []Event
}

// BeforeTxnGroup mocks the logic.EvalTracer.BeforeTxnGroup method
func (d *Tracer) BeforeTxnGroup(ep *logic.EvalParams) {
	d.Events = append(d.Events, BeforeTxnGroup(len(ep.TxnGroup)))
}

// AfterTxnGroup mocks the logic.EvalTracer.AfterTxnGroup method
func (d *Tracer) AfterTxnGroup(ep *logic.EvalParams) {
	d.Events = append(d.Events, AfterTxnGroup(len(ep.TxnGroup)))
}

// BeforeTxn mocks the logic.EvalTracer.BeforeTxn method
func (d *Tracer) BeforeTxn(ep *logic.EvalParams, groupIndex int) {
	d.Events = append(d.Events, BeforeTxn(ep.TxnGroup[groupIndex].Txn.Type))
}

// AfterTxn mocks the logic.EvalTracer.AfterTxn method
func (d *Tracer) AfterTxn(ep *logic.EvalParams, groupIndex int, ad transactions.ApplyData) {
	d.Events = append(d.Events, AfterTxn(ep.TxnGroup[groupIndex].Txn.Type, ad))
}

// BeforeProgram mocks the logic.EvalTracer.BeforeProgram method
func (d *Tracer) BeforeProgram(cx *logic.EvalContext) {
	d.Events = append(d.Events, BeforeProgram(cx.RunMode()))
}

// AfterProgram mocks the logic.EvalTracer.AfterProgram method
func (d *Tracer) AfterProgram(cx *logic.EvalContext, evalError error) {
	d.Events = append(d.Events, AfterProgram(cx.RunMode()))
}

// BeforeOpcode mocks the logic.EvalTracer.BeforeOpcode method
func (d *Tracer) BeforeOpcode(cx *logic.EvalContext) {
	d.Events = append(d.Events, BeforeOpcode())
}

// AfterOpcode mocks the logic.EvalTracer.AfterOpcode method
func (d *Tracer) AfterOpcode(cx *logic.EvalContext, evalError error) {
	d.Events = append(d.Events, AfterOpcode())
}
