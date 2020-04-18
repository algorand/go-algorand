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
	"sync"

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
	Resume()
	SetBreakpoint(pc int)
	SetBreakpointAtLine(line int)
	RemoveBreakpoint(pc int)
	RemoveBreakpointAtLine(line int)
}

// Debugger is TEAL event-driven debugger
type Debugger struct {
	mu       sync.Mutex
	sessions map[string]*session
	das      []DebugAdapter
}

// MakeDebugger creates Debugger instance
func MakeDebugger() *Debugger {
	d := new(Debugger)
	d.sessions = make(map[string]*session)
	return d
}

type debugConfig struct {
	// If -1, don't break
	BreakOnPC int `json:"breakonpc"`
}

type session struct {
	mu sync.Mutex
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
	offsets []logic.PCOffset
}

func makeSession(program string, offsets []logic.PCOffset) (s *session) {
	s = new(session)

	// Allocate a default debugConfig (don't break)
	s.debugConfig = debugConfig{
		BreakOnPC: -1,
	}

	// Allocate an acknowledgement and notifications channels
	s.acknowledged = make(chan bool)
	s.notifications = make(chan Notification)

	s.program = program
	s.offsets = offsets
	s.lines = strings.Split(program, "\n")
	return
}

func (s *session) Resume() {
	select {
	case s.acknowledged <- true:
	default:
	}
}

func (s *session) SetBreakpoint(pc int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.debugConfig = debugConfig{BreakOnPC: pc}
}

func (s *session) SetBreakpointAtLine(line int) {
	pc := s.lineToPC(line)
	s.SetBreakpoint(pc)
}

func (s *session) RemoveBreakpoint(pc int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.debugConfig = debugConfig{BreakOnPC: -1}
}

func (s *session) RemoveBreakpointAtLine(line int) {
	pc := s.lineToPC(line)
	s.RemoveBreakpoint(pc)
}

func (s *session) lineToPC(line int) int {
	if len(s.offsets) == 0 || line < 1 {
		return 0
	}

	offset := len(strings.Join(s.lines[:line], "\n"))

	for i := 0; i < len(s.offsets); i++ {
		if s.offsets[i].Offset >= offset {
			return s.offsets[i].PC
		}
	}
	return 0
}

func (d *Debugger) getSession(sid string) (s *session, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions[sid]
	if !ok {
		err = fmt.Errorf("session %s not found", sid)
	}
	return
}

func (d *Debugger) createSession(sid string, program string, offsets []logic.PCOffset) (s *session) {
	d.mu.Lock()
	defer d.mu.Unlock()

	s = makeSession(program, offsets)
	d.sessions[sid] = s
	return
}

func (d *Debugger) removeSession(sid string) (s *session) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.sessions, sid)
	return
}

// AddAdapter adds a new debugger adapter
func (d *Debugger) AddAdapter(da DebugAdapter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.das = append(d.das, da)
}

// Register setups new session and notifies frontends if any
func (d *Debugger) Register(state *logic.DebugState) error {
	sid := state.ExecID
	s := d.createSession(sid, state.Disassembly, state.PCOffset)

	// Store the state for this execution
	d.mu.Lock()
	for _, da := range d.das {
		da.SessionStarted(sid, s, s.notifications)
	}
	d.mu.Unlock()

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

	go func() {
		// Check if we are triggered and acknolwedge asynchronously
		cfg := s.debugConfig
		if cfg.BreakOnPC != -1 {
			if cfg.BreakOnPC == 0 || state.PC == cfg.BreakOnPC {
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

	d.mu.Lock()
	for _, da := range d.das {
		da.SessionEnded(sid)
	}
	d.mu.Unlock()

	return nil
}
