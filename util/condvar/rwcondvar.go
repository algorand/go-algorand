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

package condvar

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"
)

// RWCond implements a condition variable, a rendezvous point for goroutines waiting for or announcing the occurrence of an event.
// This implementation is similar to the underlying sync.Cond, but extend it to support RW locks.
type RWCond struct {
	readCond  *sync.Cond
	writeCond *sync.Cond
}

// NewRWCond returns a new RWCond
func NewRWCond(l *deadlock.RWMutex) *RWCond {
	return &RWCond{
		writeCond: sync.NewCond(l),
		readCond:  sync.NewCond(l.RLocker()),
	}
}

// Broadcast wakes all goroutines waiting on c.
// It is allowed but not required for the caller to hold c.L during the call.
func (c *RWCond) Broadcast() {
	c.writeCond.Broadcast()
	c.readCond.Broadcast()
}

// RBroadcast wakes all goroutines waiting on c with the RWait function.
// It is allowed but not required for the caller to hold c.L during the call.
func (c *RWCond) RBroadcast() {
	c.readCond.Broadcast()
}

// Signal wakes up to one goroutine waiting on c for reading AND up to one goroutine waiting on c for writing.
// It is allowed but not required for the caller to hold c.L during the call.
func (c *RWCond) Signal() {
	c.readCond.Signal()
	c.writeCond.Signal()
}

// Wait atomically unlocks the write lock and suspends execution of the calling goroutine.
// After later resuming execution, Wait locks the write lock before returning.
// Unlike in other systems, Wait cannot return unless awoken by Broadcast or Signal.
func (c *RWCond) Wait() {
	c.writeCond.Wait()
}

// RWait atomically unlocks the read lock and suspends execution of the calling goroutine.
// After later resuming execution, RWait locks the read lock before returning.
// Unlike in other systems, RWait cannot return unless awoken by Broadcast, RBroadcast or Signal.
func (c *RWCond) RWait() {
	c.readCond.Wait()
}

// TimedWait atomically unlocks the write lock and suspends execution of the calling goroutine.
// After later resuming execution, Wait locks the write lock before returning.
// Unlike in other systems, Wait cannot return unless awoken by Broadcast or Signal.
func (c *RWCond) TimedWait(timeout time.Duration) bool {
	return timedWait(c.writeCond, timeout)
}

// RTimedWait atomically unlocks the write lock and suspends execution of the calling goroutine.
// After later resuming execution, Wait locks the write lock before returning.
// Unlike in other systems, Wait cannot return unless awoken by Broadcast or Signal.
func (c *RWCond) RTimedWait(timeout time.Duration) bool {
	return timedWait(c.readCond, timeout)
}

// timedWait waits for sync.Cond c to be signaled, with a timeout.
// If the condition is not signaled before timeout, timedWait forces
// a Broadcast() on c until this function returns.  This assumes a
// (common) use of sync.Cond where stray signals are allowed, so
// the extra Broadcast() introduced by this function isn't a problem.
// The function returns true if a timeout has occured or false otherwise.
// note that stray broadcasts could cause this function to return false
// while the underlying condition has not been met, and therefore the
// caller must verify the condition in either case.
// ( if the caller ensures that there are no other broadcasts involved,
// then the returned bool can be safely used to determine if the function
// had timed out or not )
func timedWait(cond *sync.Cond, timeout time.Duration) bool {
	var timedOut int32
	exiting := make(chan struct{}, 1)
	waitRoutineClosed := make(chan struct{}, 1)

	go func() {
		defer close(waitRoutineClosed)
		select {
		case <-time.After(timeout):
			atomic.StoreInt32(&timedOut, 1)
		case <-exiting:
			return
		}

		for {
			cond.Broadcast()

			// It is unlikely but possible that the parent
			// thread hasn't gotten around to calling c.Wait()
			// yet, so the c.Broadcast() did not wake it up.
			// Sleep for few milliseconds and try again
			select {
			case <-time.After(time.Millisecond):
			case <-exiting:
				return
			}
		}

	}()

	cond.Wait()
	close(exiting)
	<-waitRoutineClosed
	return atomic.LoadInt32(&timedOut) == 1
}
