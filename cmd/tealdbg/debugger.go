// Copyright (C) 2019-2020 Algorand, Inc.
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

package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

// Notification is sent to the client over their websocket connection
// on each new TEAL execution/update/complation
type Notification struct {
	Event      string           `codec:"event"`
	DebugState logic.DebugState `codec:"state"`
}

// DebugAdapter represents debugger frontend (i.e. CDT, webpage, VSCode, etc)
type DebugAdapter interface {
	SessionStarted(sid string, debugger Control, ch chan Notification)
	SessionEnded(sid string)
	WaitForCompletion()
}

// Control interface for execution control
type Control interface {
	Step()
	Resume()
	SetBreakpoint(line int) error
	RemoveBreakpoint(line int) error
	SetBreakpointsActive(active bool)

	GetSourceMap() ([]byte, error)
	GetSource() (string, []byte)
	GetStates(changes *logic.AppStateChange) appState
}

// Debugger is TEAL event-driven debugger
type Debugger struct {
	mus      deadlock.Mutex
	sessions map[string]*session
	programs map[string]*programMeta

	mud deadlock.Mutex
	das []DebugAdapter
}

// MakeDebugger creates Debugger instance
func MakeDebugger() *Debugger {
	d := new(Debugger)
	d.sessions = make(map[string]*session)
	d.programs = make(map[string]*programMeta)
	return d
}

type programMeta struct {
	name         string
	program      []byte
	source       string
	offsetToLine map[int]int
	states       appState
}

// breakpointLine is a source line number with a couple special values:
// -1 do not break
//  0 break at next instruction
//  N break at line N
type breakpointLine int

const (
	noBreak   breakpointLine = -1
	stepBreak breakpointLine = 0
)

type debugConfig struct {
	BreakAtLine breakpointLine `json:"breakatline"`
}

type session struct {
	mu deadlock.Mutex
	// Reply to registration/update when bool received on acknowledgement
	// channel, allowing program execution to continue
	acknowledged chan bool

	// debugConfigs holds information about this debugging session,
	// currently just when we want to break
	debugConfig debugConfig

	// notifications from eval
	notifications chan Notification

	// program that is being debugged
	disassembly string
	lines       []string

	programName  string
	program      []byte
	source       string
	offsetToLine map[int]int // pc to source line
	pcOffset     map[int]int // disassembly line to pc

	breakpoints []breakpoint
	line        atomicInt

	states appState
}

type breakpoint struct {
	set    bool
	active bool
}

func (bs *breakpoint) NonEmpty() bool {
	return bs.set
}

func makeSession(disassembly string, line int) (s *session) {
	s = new(session)

	// Allocate a default debugConfig (don't break)
	s.debugConfig = debugConfig{
		BreakAtLine: noBreak,
	}

	// Allocate an acknowledgement and notifications channels
	s.acknowledged = make(chan bool)
	s.notifications = make(chan Notification)

	s.disassembly = disassembly
	s.lines = strings.Split(disassembly, "\n")
	s.breakpoints = make([]breakpoint, len(s.lines))
	s.line.Store(line)
	return
}

func (s *session) resume() {
	select {
	case s.acknowledged <- true:
		fmt.Println("Queued")
	default:
		fmt.Println("Not Queued")
	}
}

func (s *session) Step() {
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.debugConfig = debugConfig{BreakAtLine: stepBreak}
	}()

	s.resume()
}

func (s *session) Resume() {
	currentLine := s.line.Load()

	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.debugConfig = debugConfig{BreakAtLine: noBreak} // reset possible break after Step
		// find any active breakpoints and set next break
		if currentLine < len(s.breakpoints) {
			for line, state := range s.breakpoints[currentLine+1:] {
				if state.set && state.active {
					s.setBreakpoint(line + currentLine + 1)
					break
				}
			}
		}
	}()

	s.resume()
}

// setBreakpoint must be called with lock taken
func (s *session) setBreakpoint(line int) error {
	if line >= len(s.breakpoints) {
		return fmt.Errorf("invalid bp line %d", line)
	}
	s.breakpoints[line] = breakpoint{set: true, active: true}
	s.debugConfig = debugConfig{BreakAtLine: breakpointLine(line)}
	return nil
}

func (s *session) SetBreakpoint(line int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setBreakpoint(line)
}

func (s *session) RemoveBreakpoint(line int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if line < 0 || line >= len(s.breakpoints) {
		return fmt.Errorf("invalid bp line %d", line)
	}
	if s.breakpoints[line].NonEmpty() {
		s.debugConfig = debugConfig{BreakAtLine: noBreak}
		s.breakpoints[line] = breakpoint{}
	}
	return nil
}

func (s *session) SetBreakpointsActive(active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 0; i < len(s.breakpoints); i++ {
		if s.breakpoints[i].NonEmpty() {
			s.breakpoints[i].active = active
		}
	}
	if !active {
		s.debugConfig = debugConfig{BreakAtLine: noBreak}
	}
}

// GetSourceMap creates source map from source, disassembly and mappings
func (s *session) GetSourceMap() ([]byte, error) {
	if len(s.source) == 0 {
		return nil, nil
	}

	type sourceMap struct {
		Version    int      `json:"version"`
		File       string   `json:"file"`
		SourceRoot string   `json:"sourceRoot"`
		Sources    []string `json:"sources"`
		Mappings   string   `json:"mappings"`
	}
	lines := make([]string, len(s.lines))
	const targetCol int = 0
	const sourceIdx int = 0
	sourceLine := 0
	const sourceCol int = 0
	prevSourceLine := 0

	// the very first entry is needed by CDT
	lines[0] = MakeSourceMapLine(targetCol, sourceIdx, 0, sourceCol)
	for targetLine := 1; targetLine < len(s.lines); targetLine++ {
		if pc, ok := s.pcOffset[targetLine]; ok && pc != 0 {
			sourceLine, ok = s.offsetToLine[pc]
			if !ok {
				lines[targetLine] = ""
			} else {
				lines[targetLine] = MakeSourceMapLine(targetCol, sourceIdx, sourceLine-prevSourceLine, sourceCol)
				prevSourceLine = sourceLine
			}
		} else {
			delta := 0
			// the very last empty line, increment by number src number by 1
			if targetLine == len(s.lines)-1 {
				delta = 1
			}
			lines[targetLine] = MakeSourceMapLine(targetCol, sourceIdx, delta, sourceCol)
		}
	}

	sm := sourceMap{
		Version:    3,
		File:       s.programName + ".dis",
		SourceRoot: "",
		Sources:    []string{"source"}, // this is a pseudo source file name, served by debugger
		Mappings:   strings.Join(lines, ";"),
	}
	data, err := json.Marshal(&sm)
	return data, err
}

func (s *session) GetSource() (string, []byte) {
	if len(s.source) == 0 {
		return "", nil
	}
	return s.programName, []byte(s.source)
}

func (s *session) GetStates(changes *logic.AppStateChange) appState {
	if changes == nil {
		return s.states
	}

	newStates := s.states.clone()
	appIdx := newStates.appIdx

	applyDelta := func(sd basics.StateDelta, tkv basics.TealKeyValue) {
		for key, delta := range sd {
			switch delta.Action {
			case basics.SetUintAction:
				tkv[key] = basics.TealValue{Type: basics.TealUintType, Uint: delta.Uint}
			case basics.SetBytesAction:
				tkv[key] = basics.TealValue{
					Type: basics.TealBytesType, Bytes: delta.Bytes,
				}
			case basics.DeleteAction:
				delete(tkv, key)
			}
		}
	}

	if len(changes.GlobalStateChanges) > 0 {
		tkv := newStates.global[appIdx]
		if tkv == nil {
			tkv = make(basics.TealKeyValue)
		}
		applyDelta(changes.GlobalStateChanges, tkv)
		newStates.global[appIdx] = tkv
	}

	for addr, delta := range changes.LocalStateChanges {
		local := newStates.locals[addr]
		if local == nil {
			local = make(map[basics.AppIndex]basics.TealKeyValue)
		}
		tkv := local[appIdx]
		if tkv == nil {
			tkv = make(basics.TealKeyValue)
		}
		applyDelta(delta, tkv)
		local[appIdx] = tkv
		newStates.locals[addr] = local
	}

	return newStates
}

func (d *Debugger) getSession(sid string) (s *session, err error) {
	d.mus.Lock()
	defer d.mus.Unlock()
	s, ok := d.sessions[sid]
	if !ok {
		err = fmt.Errorf("session %s not found", sid)
	}
	return
}

func (d *Debugger) createSession(sid string, disassembly string, line int, pcOffset map[int]int) (s *session) {
	d.mus.Lock()
	defer d.mus.Unlock()

	s = makeSession(disassembly, line)
	d.sessions[sid] = s
	meta, ok := d.programs[sid]
	if ok {
		s.programName = meta.name
		s.program = meta.program
		s.source = meta.source
		s.offsetToLine = meta.offsetToLine
		s.pcOffset = pcOffset
		s.states = meta.states
	}
	return
}

func (d *Debugger) removeSession(sid string) (s *session) {
	d.mus.Lock()
	defer d.mus.Unlock()

	delete(d.sessions, sid)
	return
}

// AddAdapter adds a new debugger adapter
func (d *Debugger) AddAdapter(da DebugAdapter) {
	d.mud.Lock()
	defer d.mud.Unlock()
	d.das = append(d.das, da)
}

// SaveProgram stores program, source and offsetToLine for later use
func (d *Debugger) SaveProgram(
	name string, program []byte, source string, offsetToLine map[int]int,
	states appState,
) {
	hash := logic.GetProgramID(program)
	d.mus.Lock()
	defer d.mus.Unlock()
	d.programs[hash] = &programMeta{
		name,
		program,
		source,
		offsetToLine,
		states,
	}
}

// Register setups new session and notifies frontends if any
func (d *Debugger) Register(state *logic.DebugState) error {
	sid := state.ExecID
	pcOffset := make(map[int]int, len(state.PCOffset))
	for _, pco := range state.PCOffset {
		pcOffset[state.PCToLine(pco.PC)] = pco.PC
	}
	s := d.createSession(sid, state.Disassembly, state.Line, pcOffset)

	// Store the state for this execution
	d.mud.Lock()
	for _, da := range d.das {
		da.SessionStarted(sid, s, s.notifications)
	}
	d.mud.Unlock()

	// TODO: Race or deadlock possible here:
	// 1. registered sent, context switched
	// 2. Non-blocking Resume() called in onRegistered handler on not ready acknowledged channel
	// 3. context switched back and blocked on <-s.acknowledged below
	//
	// How to fix:
	// make Resume() synchronous but special handling needed for already completed programs

	// Inform the user to configure execution
	s.notifications <- Notification{"registered", *state}

	// Wait for acknowledgement
	<-s.acknowledged

	return nil
}

// Update process state update notifications: pauses or continues as needed
func (d *Debugger) Update(state *logic.DebugState) error {
	sid := state.ExecID
	s, err := d.getSession(sid)
	if err != nil {
		return err
	}
	s.line.Store(state.Line)

	go func() {
		// Check if we are triggered and acknowledge asynchronously
		cfg := s.debugConfig
		if cfg.BreakAtLine != noBreak {
			if cfg.BreakAtLine == stepBreak || breakpointLine(state.Line) == cfg.BreakAtLine {
				// Breakpoint hit! Inform the user
				s.notifications <- Notification{"updated", *state}
			} else {
				// Continue if we haven't hit the next breakpoint
				s.acknowledged <- true
			}
		} else {
			// User won't send acknowledgment, so we will
			s.acknowledged <- true
		}
	}()

	// Let TEAL continue when acknowledged
	<-s.acknowledged

	return nil
}

// Complete terminates session and notifies frontends if any
func (d *Debugger) Complete(state *logic.DebugState) error {
	sid := state.ExecID
	s, err := d.getSession(sid)
	if err != nil {
		return err
	}

	// Inform the user
	s.notifications <- Notification{"completed", *state}

	// Clean up exec-specific state
	d.removeSession(sid)

	d.mud.Lock()
	for _, da := range d.das {
		da.SessionEnded(sid)
	}
	d.mud.Unlock()

	return nil
}
