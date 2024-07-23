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

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/logging"
)

// Notification is sent to the client over their websocket connection
// on each new TEAL execution/update/completion
type Notification struct {
	Event      string           `codec:"event"`
	DebugState logic.DebugState `codec:"state"`
}

// DebugAdapter represents debugger frontend (i.e. CDT, webpage, VSCode, etc)
type DebugAdapter interface {
	// SessionStarted is called by the debugging core on the beginning of execution.
	// Control interface must be used to manage execution (step, break, resume, etc).
	// Notification channel must be used for receiving events from the debugger.
	SessionStarted(sid string, debugger Control, ch chan Notification)
	// SessionStarted is called by the debugging core on the competition of execution.
	SessionEnded(sid string)
	// WaitForCompletion must returns only when all session were completed and block otherwise.
	WaitForCompletion()
	// URL returns the most frontend URL for the most recent session
	// or an empty string if there are no sessions yet.
	URL() string
}

// Control interface for execution control
type Control interface {
	Step()
	StepOver()
	StepOut()
	Resume()
	SetBreakpoint(line int) error
	RemoveBreakpoint(line int) error
	SetBreakpointsActive(active bool)

	GetSourceMap() ([]byte, error)
	GetSource() (string, []byte)
	GetStates(s *logic.DebugState) AppState
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
	name           string
	program        []byte
	source         string
	offsetToSource map[int]logic.SourceLocation
	states         AppState
}

// debugConfig contains information about control execution and breakpoints.
type debugConfig struct {
	NoBreak     bool `json:"nobreak"`
	StepBreak   bool `json:"stepbreak"`
	StepOutOver bool `json:"stepover"`

	ActiveBreak map[int]struct{} `json:"activebreak"`
	CallDepth   int              `json:"calldepth"`
}

func makeDebugConfig() debugConfig {
	dc := debugConfig{}
	dc.ActiveBreak = make(map[int]struct{})
	return dc
}

func (dc *debugConfig) setNoBreak() {
	dc.NoBreak = true
}

func (dc *debugConfig) setStepBreak() {
	dc.StepBreak = true
}

func (dc *debugConfig) setStepOutOver(callDepth int) {
	dc.StepOutOver = true
	dc.CallDepth = callDepth
}

// setActiveBreak does not check if the line is a valid value, so it should
// be called inside the setBreakpoint() in session.
func (dc *debugConfig) setActiveBreak(line int) {
	dc.ActiveBreak[line] = struct{}{}
}

// isBreak checks if Update() should break at this line and callDepth.
func (dc *debugConfig) isBreak(line int, callDepth int) bool {
	if dc.StepBreak {
		return true
	}

	_, ok := dc.ActiveBreak[line]
	if !dc.StepOutOver || dc.CallDepth == callDepth {
		// If we are in stepOver or stepOut, then make sure we check
		// callstack depth before breaking at this line.
		return ok
	}
	return false
}

type session struct {
	mu deadlock.Mutex
	// Reply to registration/update when bool received on acknowledgement
	// channel, allowing program execution to continue
	acknowledged chan bool

	// debugConfigs holds information about this debugging session,
	// such as the breakpoints, initial call stack depth, and whether we want
	// to step over/out/in.
	debugConfig debugConfig

	// notifications from eval
	notifications chan Notification

	// program that is being debugged
	disassembly string
	lines       []string

	programName    string
	program        []byte
	source         string
	offsetToSource map[int]logic.SourceLocation // pc to source line/col
	pcOffset       map[int]int                  // disassembly line to pc

	breakpoints []breakpoint
	line        atomicInt

	callStack []logic.CallFrame

	states AppState
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
	s.debugConfig = makeDebugConfig()
	s.debugConfig.setNoBreak()

	// Allocate an acknowledgement and notifications channels
	s.acknowledged = make(chan bool)
	s.notifications = make(chan Notification)

	s.disassembly = disassembly
	s.lines = strings.Split(disassembly, "\n")
	s.breakpoints = make([]breakpoint, len(s.lines))
	s.line.Store(line)
	s.callStack = []logic.CallFrame{}
	return
}

func (s *session) resume() {
	// There is a chance for race in automated environments like tests and scripted executions:
	// acknowledged channel is not listening but attempted to write here.
	// See a comment in Registered function.
	// This loop adds delays to mitigate possible race:
	// if the channel is not ready then yield and give another go-routine a chance.
	for i := 0; i < 50; i++ {
		select {
		case s.acknowledged <- true:
			return
		default:
			time.Sleep(1 * time.Millisecond)
		}
	}
}

func (s *session) Step() {
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.debugConfig = makeDebugConfig()
		s.debugConfig.setStepBreak()
	}()

	s.resume()
}

func (s *session) StepOver() {
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		// Get the first TEAL opcode in the line
		currentOp := strings.Fields(s.lines[s.line.Load()])[0]
		s.debugConfig = makeDebugConfig()

		// Step over a function call (callsub op).
		if currentOp == "callsub" && s.line.Load() < len(s.breakpoints) {
			// Set a flag to check if we are in StepOver mode and to
			// save our initial call depth so we can pass over breakpoints that
			// are not on the correct call depth.
			s.debugConfig.setStepOutOver(len(s.callStack))
			err := s.setBreakpoint(s.line.Load() + 1)
			if err != nil {
				s.debugConfig.setStepBreak()
			}
		} else {
			s.debugConfig.setStepBreak()
		}
	}()
	s.resume()
}

func (s *session) StepOut() {
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.debugConfig = makeDebugConfig()
		if len(s.callStack) == 0 {
			s.debugConfig.setNoBreak()
		} else {
			callFrame := s.callStack[len(s.callStack)-1]
			s.debugConfig.setStepOutOver(len(s.callStack) - 1)
			err := s.setBreakpoint(callFrame.FrameLine + 1)
			if err != nil {
				s.debugConfig.setStepBreak()
			}
		}
	}()

	s.resume()
}

func (s *session) Resume() {
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.debugConfig = makeDebugConfig()
		// find any active breakpoints and set break
		for line, state := range s.breakpoints {
			if state.set && state.active {
				err := s.setBreakpoint(line)
				if err != nil {
					s.debugConfig.setStepBreak()
				}
			}
		}
	}()

	s.resume()
}

// setBreakpoint must be called with lock taken
// Used for setting a breakpoint in step execution and adding bp to the session.
func (s *session) setBreakpoint(line int) error {
	if line >= len(s.breakpoints) {
		return fmt.Errorf("invalid bp line %d", line)
	}
	s.breakpoints[line] = breakpoint{set: true, active: true}
	s.debugConfig.setActiveBreak(line)
	return nil
}

func (s *session) SetBreakpoint(line int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Reset all existing flags and breakpoints and set a new bp.
	s.debugConfig = makeDebugConfig()
	return s.setBreakpoint(line)
}

func (s *session) setCallStack(callStack []logic.CallFrame) {
	s.mu.Lock()
	s.callStack = callStack
	s.mu.Unlock()
}

func (s *session) RemoveBreakpoint(line int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if line < 0 || line >= len(s.breakpoints) {
		return fmt.Errorf("invalid bp line %d", line)
	}
	if s.breakpoints[line].NonEmpty() {
		s.debugConfig = makeDebugConfig()
		s.debugConfig.setNoBreak()
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
		s.debugConfig = makeDebugConfig()
		s.debugConfig.setNoBreak()
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
	prevLoc := logic.SourceLocation{Line: 0, Column: 0}

	// the very first entry is needed by CDT
	lines[0] = logic.MakeSourceMapLine(targetCol, sourceIdx, 0, 0)
	for targetLine := 1; targetLine < len(s.lines); targetLine++ {
		if pc, ok := s.pcOffset[targetLine]; ok && pc != 0 {
			source, ok := s.offsetToSource[pc]
			if !ok {
				lines[targetLine] = ""
			} else {
				lines[targetLine] = logic.MakeSourceMapLine(targetCol, sourceIdx, source.Line-prevLoc.Line, source.Column-prevLoc.Column)
				prevLoc = source
			}
		} else {
			ldelta, cdelta := 0, 0
			// the very last empty line, increment by number src number by 1
			if targetLine == len(s.lines)-1 {
				ldelta = 1
				cdelta = -prevLoc.Column
			}
			lines[targetLine] = logic.MakeSourceMapLine(targetCol, sourceIdx, ldelta, cdelta)
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

func (s *session) GetStates(st *logic.DebugState) AppState {
	if st == nil {
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

	changes := st.EvalDelta
	if len(changes.GlobalDelta) > 0 {
		tkv := newStates.global[appIdx]
		if tkv == nil {
			tkv = make(basics.TealKeyValue)
		}
		applyDelta(changes.GlobalDelta, tkv)
		newStates.global[appIdx] = tkv
	}

	txn := st.TxnGroup[st.GroupIndex].Txn
	accounts := append([]basics.Address{txn.Sender}, txn.Accounts...)
	for idx, delta := range changes.LocalDeltas {
		addr := accounts[idx]
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

	if len(changes.Logs) > 0 {
		newStates.logs = changes.Logs
	}

	if len(changes.InnerTxns) > 0 {
		newStates.innerTxns = changes.InnerTxns
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
		s.offsetToSource = meta.offsetToSource
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
	name string, program []byte, source string, offsetToSource map[int]logic.SourceLocation,
	states AppState,
) {
	hash := logic.GetProgramID(program)
	d.mus.Lock()
	defer d.mus.Unlock()
	d.programs[hash] = &programMeta{
		name,
		program,
		source,
		offsetToSource,
		states,
	}
}

// Register setups new session and notifies frontends if any
func (d *Debugger) Register(state *logic.DebugState) {
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
}

// Update process state update notifications: pauses or continues as needed
func (d *Debugger) Update(state *logic.DebugState) {
	err := d.update(state)
	if err != nil {
		logging.Base().Errorf("error in Update hook: %s", err.Error())
	}
}

func (d *Debugger) update(state *logic.DebugState) error {
	sid := state.ExecID
	s, err := d.getSession(sid)
	if err != nil {
		return err
	}
	s.line.Store(state.Line)
	cfg := s.debugConfig

	// copy state to prevent a data race in this the go-routine and upcoming updates to the state
	go func(localState logic.DebugState) {
		// Check if we are triggered and acknowledge asynchronously
		if !cfg.NoBreak {
			if cfg.isBreak(localState.Line, len(localState.CallStack)) {
				// Copy callstack information
				s.setCallStack(state.CallStack)
				// Breakpoint hit! Inform the user
				s.notifications <- Notification{"updated", localState}
			} else {
				// Continue if we haven't hit the next breakpoint
				s.acknowledged <- true
			}
		} else {
			// User won't send acknowledgment, so we will
			s.acknowledged <- true
		}
	}(*state)

	// Let TEAL continue when acknowledged
	<-s.acknowledged

	return nil
}

// Complete terminates session and notifies frontends if any
func (d *Debugger) Complete(state *logic.DebugState) {
	err := d.complete(state)
	if err != nil {
		logging.Base().Errorf("error in Complete hook: %s", err.Error())
	}
}

func (d *Debugger) complete(state *logic.DebugState) error {
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
