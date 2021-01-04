// Copyright (C) 2019-2021 Algorand, Inc.
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

package execpool

import (
	"context"
	"runtime"
	"sync"
)

// The list of all valid priority values. When adding new ones, add them before numPrios.
// (i.e. there should be no gaps, and the first priority needs to be zero)
const (
	LowPriority Priority = iota
	HighPriority

	numPrios
)

// ExecutionPool interface exposes the core functionality of the execution pool.
type ExecutionPool interface {
	Enqueue(enqueueCtx context.Context, t ExecFunc, arg interface{}, i Priority, out chan interface{}) error
	GetOwner() interface{}
	Shutdown()
	GetParallelism() int
}

// A pool is a fixed set of worker goroutines which perform tasks in parallel.
type pool struct {
	inputs  []chan enqueuedTask
	wg      sync.WaitGroup
	owner   interface{}
	numCPUs int
}

// A ExecFunc is a unit of work to be executed by a Pool goroutine.
//
// Note that a ExecFunc will occupy a Pool goroutine, so do not schedule tasks
// that spend an excessive amount of time waiting.
type ExecFunc func(interface{}) interface{}

// A Priority specifies a hint to the Pool to execute a Task at some priority.
//
// Tasks with higher Priority values will tend to finish more quickly.
//
// If there are tasks with different priorities, a worker will pick the
// highest-priority task to execute next.
type Priority uint8

type enqueuedTask struct {
	execFunc ExecFunc
	arg      interface{}
	out      chan interface{}
}

// MakePool creates a pool.
func MakePool(owner interface{}) ExecutionPool {
	p := &pool{
		inputs:  make([]chan enqueuedTask, numPrios),
		numCPUs: runtime.NumCPU(),
		owner:   owner,
	}

	// initialize input channels.
	for i := 0; i < len(p.inputs); i++ {
		p.inputs[i] = make(chan enqueuedTask)
	}

	p.wg.Add(p.numCPUs)
	for i := 0; i < p.numCPUs; i++ {
		go p.worker()
	}

	return p
}

// GetParallelism returns the parallelism degree
func (p *pool) GetParallelism() int {
	return p.numCPUs
}

// GetOwner return the owner interface that was passed-in during pool creation.
//
// The idea is that a pool can be either passed-in or created locally. Before shutting down the
// pool, the caller should check if it was passed-in or not. Instead of having a separate flag for
// that purpose, the pool have an "owner" parameters that allows the caller to determine if it need
// to be shut down or not.
func (p *pool) GetOwner() interface{} {
	return p.owner
}

// Enqueue will enqueue a task for verification at a given priority.
//
// Enqueue blocks until the task is enqueued correctly, or until the passed-in
// context is cancelled.
///
// Enqueue returns nil if task was enqueued successfully or the result of the
// expired context error.
func (p *pool) Enqueue(enqueueCtx context.Context, t ExecFunc, arg interface{}, i Priority, out chan interface{}) error {
	select {
	case p.inputs[i] <- enqueuedTask{
		execFunc: t,
		arg:      arg,
		out:      out,
	}:
		return nil
	case <-enqueueCtx.Done():
		return enqueueCtx.Err()
	}
}

// Shutdown will tell the pool's goroutines to terminate, returning when
// resources have been freed.
//
// It must be called at most once.
func (p *pool) Shutdown() {
	for _, ch := range p.inputs {
		close(ch)
	}
	p.wg.Wait()
}

// worker function blocks until a new task is pending on any of the channels and execute the above task.
// the implementation below would give higher priority for channels that are on higher priority slot.
func (p *pool) worker() {
	var t enqueuedTask
	var ok bool
	lowPrio := p.inputs[LowPriority]
	highPrio := p.inputs[HighPriority]
	defer p.wg.Done()
	for {

		select {
		case t, ok = <-highPrio:
		default:
			select {
			case t, ok = <-highPrio:
			case t, ok = <-lowPrio:
			}
		}

		if !ok {
			return
		}
		res := t.execFunc(t.arg)

		if t.out != nil {
			t.out <- res
		}
	}
}
