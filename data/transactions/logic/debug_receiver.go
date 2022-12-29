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

//go:build debugteal

package logic

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/data/basics"
)

// TealValue Represents a TEAL value.
type TealValue struct {
	// Bytes \[tb\] bytes value.
	Bytes string `json:"bytes"`

	// Type \[tt\] value type. Value `1` refers to **bytes**, value `2` refers to **uint**
	Type uint64 `json:"type"`

	// Uint \[ui\] uint value.
	Uint uint64 `json:"uint"`
}

func (tv TealValue) String() string {
	if tv.Type == 1 {
		//return "0x" + hex.EncodeToString([]byte(tv.Bytes))
		return tv.Bytes
	} else {
		return strconv.FormatUint(tv.Uint, 10)
	}
}

type HistoryStep struct {
	// Error Evaluation error if any
	Error *string `json:"error,omitempty"`

	// Line Line number
	Line uint64 `json:"line"`

	// Pc Program counter
	Pc      uint64       `json:"pc"`
	Scratch *[]TealValue `json:"scratch,omitempty"`
	Stack   []TealValue  `json:"stack"`
}

func (hs *HistoryStep) StackString() string {
	var sb strings.Builder
	for i, v := range hs.Stack {
		if i != 0 {
			sb.WriteRune(' ')
		}
		sb.WriteString(v.String())
	}
	return sb.String()
}

type SimpleDebugReceiver struct {
	Disassembly   string
	History       []HistoryStep
	scratchActive []bool
}

func (ddr *SimpleDebugReceiver) updateScratch() {
	maxActive := -1
	lasti := len(ddr.History) - 1

	if ddr.History[lasti].Scratch == nil {
		return
	}

	if ddr.scratchActive == nil {
		ddr.scratchActive = make([]bool, 256)
	}

	for i, sv := range *ddr.History[lasti].Scratch {
		ddr.scratchActive[i] = false
		if sv.Type != uint64(basics.TealUintType) || sv.Uint != 0 {
			ddr.scratchActive[i] = true
			maxActive = i
		}
	}

	if maxActive == -1 {
		ddr.History[lasti].Scratch = nil
		return
	}

	*ddr.History[lasti].Scratch = (*ddr.History[lasti].Scratch)[:maxActive+1]
	for i := range *ddr.History[lasti].Scratch {
		if !ddr.scratchActive[i] {
			(*ddr.History[lasti].Scratch)[i].Type = 0
		}
	}
}

func (ddr *SimpleDebugReceiver) stateToState(state *DebugState) HistoryStep {
	st := HistoryStep{
		Line: uint64(state.Line),
		Pc:   uint64(state.PC),
	}
	st.Stack = make([]TealValue, len(state.Stack))
	for i, v := range state.Stack {
		st.Stack[i] = TealValue{
			Uint:  v.Uint,
			Bytes: v.Bytes,
			Type:  uint64(v.Type),
		}
	}
	if len(state.Error) > 0 {
		st.Error = new(string)
		*st.Error = state.Error
	}

	scratch := make([]TealValue, len(state.Scratch))
	for i, v := range state.Scratch {
		scratch[i] = TealValue{
			Uint:  v.Uint,
			Bytes: v.Bytes,
			Type:  uint64(v.Type),
		}
	}
	st.Scratch = &scratch
	return st
}

// Register is fired on program creation (DebuggerHook interface)
func (ddr *SimpleDebugReceiver) Register(state *DebugState) error {
	ddr.Disassembly = state.Disassembly
	return nil
}

func (ddr *SimpleDebugReceiver) Lines() []string {
	return strings.Split(ddr.Disassembly, "\n")
}

// Update is fired on every step (DebuggerHook interface)
func (ddr *SimpleDebugReceiver) Update(state *DebugState) error {
	st := ddr.stateToState(state)
	ddr.History = append(ddr.History, st)
	ddr.updateScratch()
	return nil
}

// Complete is called when the program exits (DebuggerHook interface)
func (ddr *SimpleDebugReceiver) Complete(state *DebugState) error {
	return ddr.Update(state)
}

func (ddr *SimpleDebugReceiver) String() string {
	var out strings.Builder
	lines := ddr.Lines()
	for _, h := range ddr.History {
		fmt.Fprintf(&out, "%4d (%04x): %s [%s]\n", h.Line, h.Pc, lines[h.Line-1], h.StackString())
	}
	return out.String()
}

func debugTealDebuggerFactoryImpl() DebuggerHook {
	return new(SimpleDebugReceiver)
}

func init() {
	// set factory function var in debugger.go
	debugTealDebuggerFactory = debugTealDebuggerFactoryImpl
}
