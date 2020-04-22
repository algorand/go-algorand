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
	"fmt"
	"strings"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/transactions/logic"
)

// Notification is sent to the client over their websocket connection
// on each new TEAL execution/update/complation
type Notification struct {
	Event      string           `json:"event"`
	DebugState logic.DebugState `json:"state"`
}

// DebugAdapter represents debugger frontend (i.e. CDT, webpage, VSCode, etc)
type DebugAdapter interface {
	Setup(ctx interface{}) error
	SessionStarted(sid string, debugger Control, ch chan Notification)
	SessionEnded(sid string)
}

// Control interface for execution control
type Control interface {
	Step()
	Resume()
	SetBreakpoint(line int) error
	RemoveBreakpoint(line int) error
	SetBreakpointsActive(active bool)
}

// Debugger is TEAL event-driven debugger
type Debugger struct {
	mus      deadlock.Mutex
	sessions map[string]*session

	mud deadlock.Mutex
	das []DebugAdapter
}

// MakeDebugger creates Debugger instance
func MakeDebugger() *Debugger {
	d := new(Debugger)
	d.sessions = make(map[string]*session)
	return d
}

type debugConfig struct {
	// If -1, don't break
	BreakAtLine int `json:"breakatline"`
}

type session struct {
	mu deadlock.Mutex
	// Reply to registration/update when bool received on acknolwedgement
	// channel, allowing program execution to continue
	acknowledged chan bool

	// debugConfigs holds information about this debugging session,
	// currently just when we want to break
	debugConfig debugConfig

	// notifications from eval
	notifications chan Notification

	// program that is being debugged
	program string
	lines   []string

	breakpoints []breakpoint
	line        atomicInt
}

type breakpoint struct {
	set    bool
	active bool
}

func (bs *breakpoint) NonEmpty() bool {
	return bs.set
}

func makeSession(program string, line int) (s *session) {
	s = new(session)

	// Allocate a default debugConfig (don't break)
	s.debugConfig = debugConfig{
		BreakAtLine: -1,
	}

	// Allocate an acknowledgement and notifications channels
	s.acknowledged = make(chan bool)
	s.notifications = make(chan Notification)

	s.program = program
	s.lines = strings.Split(program, "\n")
	s.breakpoints = make([]breakpoint, len(s.lines))
	s.line.Store(line)
	return
}

func (s *session) resume() {
	select {
	case s.acknowledged <- true:
	default:
	}
}

func (s *session) Step() {
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.debugConfig = debugConfig{BreakAtLine: 0}
	}()

	s.resume()
}

func (s *session) Resume() {
	currentLine := s.line.Load()

	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.debugConfig = debugConfig{BreakAtLine: -1} // reset possible break after Step
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
	s.debugConfig = debugConfig{BreakAtLine: line}
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
		s.debugConfig = debugConfig{BreakAtLine: -1}
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
		s.debugConfig = debugConfig{BreakAtLine: -1}
	}
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

func (d *Debugger) createSession(sid string, program string, line int) (s *session) {
	d.mus.Lock()
	defer d.mus.Unlock()

	s = makeSession(program, line)
	d.sessions[sid] = s
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

// Register setups new session and notifies frontends if any
func (d *Debugger) Register(state *logic.DebugState) error {
	sid := state.ExecID
	s := d.createSession(sid, state.Disassembly, state.Line)

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

// Update process state update nofifications: pauses or continues as needed
func (d *Debugger) Update(state *logic.DebugState) error {
	sid := state.ExecID
	s, err := d.getSession(sid)
	if err != nil {
		return err
	}
	s.line.Store(state.Line)

	go func() {
		// Check if we are triggered and acknolwedge asynchronously
		cfg := s.debugConfig
		if cfg.BreakAtLine != -1 {
			if cfg.BreakAtLine == 0 || state.Line == cfg.BreakAtLine {
				// Breakpoint hit! Inform the user
				s.notifications <- Notification{"updated", *state}
			} else {
				// Continue if we haven't hit the next breakpoint
				s.acknowledged <- true
			}
		} else {
			// User won't send acknowledement, so we will
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
