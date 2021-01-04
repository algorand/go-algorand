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
	"sync"
)

// A backlog for an execution pool. The typical usage of this is to
// create non-blocking queue which would get executed once the execution pool is ready to accept new
// tasks.
type backlog struct {
	pool      ExecutionPool
	wg        sync.WaitGroup
	buffer    chan backlogItemTask
	ctx       context.Context
	ctxCancel context.CancelFunc
	owner     interface{}
	priority  Priority
}

type backlogItemTask struct {
	enqueuedTask
	priority Priority
}

// BacklogPool supports all the ExecutionPool functions plus few more that tests the pending tasks.
type BacklogPool interface {
	ExecutionPool
	EnqueueBacklog(enqueueCtx context.Context, t ExecFunc, arg interface{}, out chan interface{}) error
}

// MakeBacklog creates a backlog
func MakeBacklog(execPool ExecutionPool, backlogSize int, priority Priority, owner interface{}) BacklogPool {
	if backlogSize < 0 {
		return nil
	}
	bl := &backlog{
		pool:     execPool,
		owner:    owner,
		priority: priority,
	}
	bl.ctx, bl.ctxCancel = context.WithCancel(context.Background())
	if bl.pool == nil {
		// create one internally.
		bl.pool = MakePool(bl)
	}
	if backlogSize == 0 {
		// use the number of cpus in the system.
		backlogSize = bl.pool.GetParallelism()
	}
	bl.buffer = make(chan backlogItemTask, backlogSize)

	bl.wg.Add(1)
	go bl.worker()
	return bl
}

func (b *backlog) GetParallelism() int {
	return b.pool.GetParallelism()
}

// Enqueue enqueues a single task into the backlog
func (b *backlog) Enqueue(enqueueCtx context.Context, t ExecFunc, arg interface{}, priority Priority, out chan interface{}) error {
	select {
	case b.buffer <- backlogItemTask{
		enqueuedTask: enqueuedTask{
			execFunc: t,
			arg:      arg,
			out:      out,
		},
		priority: priority,
	}:
		return nil
	case <-enqueueCtx.Done():
		return enqueueCtx.Err()
	case <-b.ctx.Done():
		return b.ctx.Err()
	}
}

// Enqueue enqueues a single task into the backlog
func (b *backlog) EnqueueBacklog(enqueueCtx context.Context, t ExecFunc, arg interface{}, out chan interface{}) error {
	select {
	case b.buffer <- backlogItemTask{
		enqueuedTask: enqueuedTask{
			execFunc: t,
			arg:      arg,
			out:      out,
		},
		priority: b.priority,
	}:
		return nil
	case <-enqueueCtx.Done():
		return enqueueCtx.Err()
	case <-b.ctx.Done():
		return b.ctx.Err()
	}
}

// Shutdown shuts down the backlog.
func (b *backlog) Shutdown() {
	b.ctxCancel()
	// NOTE: Do not close(b.buffer) because there's no good way to ensure Enqueue*() won't write to it and panic. Just let it be garbage collected.
	b.wg.Wait()
	if b.pool.GetOwner() == b {
		b.pool.Shutdown()
	}
}

func (b *backlog) worker() {
	var t backlogItemTask
	var ok bool
	defer b.wg.Done()

	for {

		select {
		case t, ok = <-b.buffer:
		case <-b.ctx.Done():
			return
		}

		if !ok {
			return
		}

		if b.pool.Enqueue(b.ctx, t.execFunc, t.arg, t.priority, t.out) != nil {
			break
		}
	}
}

func (b *backlog) GetOwner() interface{} {
	return b.owner
}
