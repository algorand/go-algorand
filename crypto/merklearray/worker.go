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

package merklearray

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// workerState describes a group of goroutines processing a sequential list
// of maxidx elements starting from 0.
type workerState struct {
	// maxidx is the total number of elements to process, and nextidx
	// is the next element that a worker should process.
	maxidx  uint64
	nextidx uint64

	// nworkers is the number of workers that can be started.
	// This field gets decremented once workers are launched,
	// and represents the number of remaining workers that can
	// be launched.
	nworkers int

	// starting is a channel that paces the creation of workers.
	// In particular, a new worker can be started only when the
	// previous worker starts running code.  The first thing that
	// a worker does is to send a message on this channel, to allow
	// for more workers to start.  This ensures reasonable performance
	// even when the number of elements to process is small (and where
	// otherwise the cost of launching workers might dominate).
	starting chan struct{}

	// wg tracks outstanding workers, to determine when all workers
	// have finished their processing.
	wg sync.WaitGroup
}

func newWorkerState(max uint64) *workerState {
	var ws workerState
	ws.nworkers = runtime.NumCPU()
	ws.maxidx = max

	ws.starting = make(chan struct{}, 1)
	ws.starting <- struct{}{}

	return &ws
}

// next returns the next position to process, and bumps the counter
// by delta.  This implicitly means that the worker that calls next
// is promising to process delta elements at the returned position.
func (ws *workerState) next(delta uint64) uint64 {
	return atomic.AddUint64(&ws.nextidx, delta) - delta
}

// wait waits for all of the workers to finish.
func (ws *workerState) wait() {
	ws.wg.Wait()
}

// nextWorker() is used by the top-level caller to decide when it
// should launch the next worker.
func (ws *workerState) nextWorker() bool {
	if ws.nworkers <= 0 {
		return false
	}

	_ = <-ws.starting

	curidx := atomic.LoadUint64(&ws.nextidx)
	if curidx >= ws.maxidx {
		return false
	}

	ws.nworkers--
	ws.wg.Add(1)
	return true
}

// When a worker thread starts running, it can call started() to
// allow the next worker thread to be spawned.
func (ws *workerState) started() {
	ws.starting <- struct{}{}
}
