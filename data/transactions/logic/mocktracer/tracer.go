// Copyright (C) 2019-2024 Algorand, Inc.
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
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EventType represents a type of logic.EvalTracer event
type EventType string

const (
	// BeforeBlockEvent represents the logic.EvalTracer.BeforeBlock event
	BeforeBlockEvent EventType = "BeforeBlock"
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
	// AfterBlockEvent represents the logic.EvalTracer.AfterBlock event
	AfterBlockEvent EventType = "AfterBlock"
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

	// only for AfterTxnGroup and AfterTxn
	Deltas *ledgercore.StateDelta

	// only for BeforeTxnGroup and AfterTxnGroup
	GroupSize int

	// only for AfterProgram
	Pass bool

	// only for AfterOpcode, AfterProgram, AfterTxn, and AfterTxnGroup
	HasError bool

	// only for BeforeBlock, AfterBlock
	Round basics.Round
}

// BeforeBlock creates a new Event with the type BeforeBlockEvent for a particular round
func BeforeBlock(round basics.Round) Event {
	return Event{Type: BeforeBlockEvent, Round: round}
}

// BeforeTxnGroup creates a new Event with the type BeforeTxnGroupEvent
func BeforeTxnGroup(groupSize int) Event {
	return Event{Type: BeforeTxnGroupEvent, GroupSize: groupSize}
}

// AfterTxnGroup creates a new Event with the type AfterTxnGroupEvent
func AfterTxnGroup(groupSize int, deltas *ledgercore.StateDelta, hasError bool) Event {
	return Event{Type: AfterTxnGroupEvent, GroupSize: groupSize, Deltas: copyDeltas(deltas), HasError: hasError}
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
func AfterTxn(txnType protocol.TxType, ad transactions.ApplyData, hasError bool) Event {
	return Event{Type: AfterTxnEvent, TxnType: txnType, TxnApplyData: ad, HasError: hasError}
}

// ProgramResult represents the result of a program execution
type ProgramResult int

const (
	// ProgramResultPass represents a program that passed
	ProgramResultPass ProgramResult = iota
	// ProgramResultReject represents a program that rejected
	ProgramResultReject
	// ProgramResultError represents a program that errored
	ProgramResultError
)

// AfterProgram creates a new Event with the type AfterProgramEvent
func AfterProgram(mode logic.RunMode, result ProgramResult) Event {
	return Event{Type: AfterProgramEvent, LogicEvalMode: mode, Pass: result == ProgramResultPass, HasError: result == ProgramResultError}
}

// BeforeOpcode creates a new Event with the type BeforeOpcodeEvent
func BeforeOpcode() Event {
	return Event{Type: BeforeOpcodeEvent}
}

// AfterOpcode creates a new Event with the type AfterOpcodeEvent
func AfterOpcode(hasError bool) Event {
	return Event{Type: AfterOpcodeEvent, HasError: hasError}
}

// AfterBlock creates a new Event with the type AfterBlockEvent
func AfterBlock(round basics.Round) Event {
	return Event{Type: AfterBlockEvent, Round: round}
}

// OpcodeEvents returns a slice of events that represent calling `count` opcodes
func OpcodeEvents(count int, endsWithError bool) []Event {
	events := make([]Event, 0, count*2)
	for i := 0; i < count; i++ {
		hasError := false
		if endsWithError && i+1 == count {
			hasError = true
		}
		events = append(events, BeforeOpcode(), AfterOpcode(hasError))
	}
	return events
}

// FlattenEvents flattens a slice of slices into a single slice of Events
func FlattenEvents(rows [][]Event) []Event {
	var out []Event
	for _, row := range rows {
		out = append(out, row...)
	}
	return out
}

// Tracer is a mock tracer that implements logic.EvalTracer
type Tracer struct {
	Events []Event
}

// BeforeBlock mocks the logic.EvalTracer.BeforeBlock method
func (d *Tracer) BeforeBlock(hdr *bookkeeping.BlockHeader) {
	d.Events = append(d.Events, BeforeBlock(hdr.Round))
}

// BeforeTxnGroup mocks the logic.EvalTracer.BeforeTxnGroup method
func (d *Tracer) BeforeTxnGroup(ep *logic.EvalParams) {
	d.Events = append(d.Events, BeforeTxnGroup(len(ep.TxnGroup)))
}

// AfterTxnGroup mocks the logic.EvalTracer.AfterTxnGroup method
func (d *Tracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	d.Events = append(d.Events, AfterTxnGroup(len(ep.TxnGroup), deltas, evalError != nil))
}

// BeforeTxn mocks the logic.EvalTracer.BeforeTxn method
func (d *Tracer) BeforeTxn(ep *logic.EvalParams, groupIndex int) {
	d.Events = append(d.Events, BeforeTxn(ep.TxnGroup[groupIndex].Txn.Type))
}

// AfterTxn mocks the logic.EvalTracer.AfterTxn method
func (d *Tracer) AfterTxn(ep *logic.EvalParams, groupIndex int, ad transactions.ApplyData, evalError error) {
	d.Events = append(d.Events, AfterTxn(ep.TxnGroup[groupIndex].Txn.Type, ad, evalError != nil))
}

// BeforeProgram mocks the logic.EvalTracer.BeforeProgram method
func (d *Tracer) BeforeProgram(cx *logic.EvalContext) {
	d.Events = append(d.Events, BeforeProgram(cx.RunMode()))
}

// AfterProgram mocks the logic.EvalTracer.AfterProgram method
func (d *Tracer) AfterProgram(cx *logic.EvalContext, pass bool, evalError error) {
	var result ProgramResult
	if pass {
		result = ProgramResultPass
	} else if evalError != nil {
		result = ProgramResultError
	} else {
		result = ProgramResultReject

	}
	d.Events = append(d.Events, AfterProgram(cx.RunMode(), result))
}

// BeforeOpcode mocks the logic.EvalTracer.BeforeOpcode method
func (d *Tracer) BeforeOpcode(cx *logic.EvalContext) {
	d.Events = append(d.Events, BeforeOpcode())
}

// AfterOpcode mocks the logic.EvalTracer.AfterOpcode method
func (d *Tracer) AfterOpcode(cx *logic.EvalContext, evalError error) {
	d.Events = append(d.Events, AfterOpcode(evalError != nil))
}

// AfterBlock mocks the logic.EvalTracer.BeforeBlock method
func (d *Tracer) AfterBlock(hdr *bookkeeping.BlockHeader) {
	d.Events = append(d.Events, AfterBlock(hdr.Round))
}

// DetailedEvalErrors returns true, enabling detailed errors in tests.
func (d *Tracer) DetailedEvalErrors() bool { return true }

// copyDeltas makes a deep copy of the given ledgercore.StateDelta pointer, if it's not nil.
// This is inefficient, but it should only be used for testing.
func copyDeltas(deltas *ledgercore.StateDelta) *ledgercore.StateDelta {
	if deltas == nil {
		return nil
	}
	encoded := protocol.EncodeReflect(deltas)
	var clone ledgercore.StateDelta
	err := protocol.DecodeReflect(encoded, &clone)
	if err != nil {
		panic(err)
	}
	return &clone
}

// AssertEventsEqual asserts that two slices of Events are equal, taking into account complex
// equality of StateDeltas. The arguments will be modified in-place to normalize any StateDeltas.
func AssertEventsEqual(t *testing.T, expected, actual []Event) {
	t.Helper()

	// Dehydrate deltas for better comparison
	for i := range expected {
		if expected[i].Deltas != nil {
			expected[i].Deltas.Dehydrate()
		}
	}
	for i := range actual {
		if actual[i].Deltas != nil {
			actual[i].Deltas.Dehydrate()
		}
	}

	// These extra checks are not necessary for correctness, but they provide more targeted information on failure
	if assert.Equal(t, len(expected), len(actual)) {
		for i := range expected {
			assert.Equal(t, expected[i].Deltas, actual[i].Deltas, "StateDelta disagreement: i=%d, expected event type: %v, actual event type: %v", i, expected[i].Type, actual[i].Type)
		}
	}

	require.Equal(t, expected, actual)
}
