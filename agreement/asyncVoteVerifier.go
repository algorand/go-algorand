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

package agreement

import (
	"context"
	"errors"
	"sync"

	"github.com/algorand/go-algorand/util/execpool"
)

type asyncVerifyVoteRequest struct {
	ctx     context.Context
	l       LedgerReader
	uv      *unauthenticatedVote
	uev     *unauthenticatedEquivocationVote
	index   int
	message message

	// a channel that holds the response
	out chan<- asyncVerifyVoteResponse
}

type asyncVerifyVoteResponse struct {
	v         vote
	ev        equivocationVote
	index     int
	message   message
	err       error
	cancelled bool

	// a pointer to the request
	req *asyncVerifyVoteRequest
}

// AsyncVoteVerifier uses workers to verify agreement protocol votes and writes the results on an output channel specified by the user.
type AsyncVoteVerifier struct {
	done            chan struct{}
	wg              sync.WaitGroup
	workerWaitCh    chan struct{}
	backlogExecPool execpool.BacklogPool
	execpoolOut     chan interface{}
	ctx             context.Context
	ctxCancel       context.CancelFunc
}

// MakeAsyncVoteVerifier creates an AsyncVoteVerifier with workers as the number of CPUs
func MakeAsyncVoteVerifier(verificationPool execpool.BacklogPool) *AsyncVoteVerifier {
	verifier := &AsyncVoteVerifier{
		done: make(chan struct{}),
	}
	if verificationPool == nil {
		// The MakeBacklog would internall allocate an execution pool if none was provided.
		verificationPool = execpool.MakeBacklog(nil, 0, execpool.HighPriority, verifier)
	}
	verifier.backlogExecPool = verificationPool
	// The backlog execution pool is going to have 2*GetParallelism() items in the input channel.
	// Since we want our output channel to be sufficitly large, we're going to allocate the size of the
	// input channel, plus all the content of the currently-executing tasks. That would prevent the
	// pool from getting stuck by client enqueuing messages, as long as these clients keep pulling from the
	// output queue at the same rate.
	verifier.execpoolOut = make(chan interface{}, 3*verificationPool.GetParallelism())

	verifier.ctx, verifier.ctxCancel = context.WithCancel(context.Background())

	verifier.workerWaitCh = make(chan struct{})
	go verifier.worker()
	return verifier
}

func (avv *AsyncVoteVerifier) worker() {
	defer close(avv.workerWaitCh)
	for res := range avv.execpoolOut {
		asyncResponse := res.(*asyncVerifyVoteResponse)
		if asyncResponse != nil {
			asyncResponse.req.out <- *asyncResponse
		}
		avv.wg.Done()
	}
}

func (avv *AsyncVoteVerifier) executeVoteVerification(task interface{}) interface{} {
	req := task.(asyncVerifyVoteRequest)

	select {
	case <-req.ctx.Done():
		// request cancelled, return an error response on the channel
		return &asyncVerifyVoteResponse{err: req.ctx.Err(), cancelled: true, req: &req}
	default:
		// request was not cancelled, so we verify it here and return the result on the channel
		v, err := req.uv.verify(req.l)
		req.message.Vote = v

		var e *LedgerDroppedRoundError
		cancelled := errors.As(err, &e)

		return &asyncVerifyVoteResponse{v: v, index: req.index, message: req.message, err: err, cancelled: cancelled, req: &req}
	}
}

func (avv *AsyncVoteVerifier) executeEqVoteVerification(task interface{}) interface{} {
	req := task.(asyncVerifyVoteRequest)

	select {
	case <-req.ctx.Done():
		// request cancelled, return an error response on the channel
		return &asyncVerifyVoteResponse{err: req.ctx.Err(), cancelled: true, req: &req}
	default:
		// request was not cancelled, so we verify it here and return the result on the channel
		ev, err := req.uev.verify(req.l)

		var e *LedgerDroppedRoundError
		cancelled := errors.As(err, &e)

		return &asyncVerifyVoteResponse{ev: ev, index: req.index, message: req.message, err: err, cancelled: cancelled, req: &req}
	}
}

func (avv *AsyncVoteVerifier) verifyVote(verctx context.Context, l LedgerReader, uv unauthenticatedVote, index int, message message, out chan<- asyncVerifyVoteResponse) {
	select {
	case <-avv.ctx.Done(): // if we're quitting, don't enqueue the request
	// case <-verctx.Done(): DO NOT DO THIS! otherwise we will lose the vote (and forget to clean up)!
	// instead, enqueue so the worker will set the error value and return the cancelled vote properly.
	default:
		// if we're done while waiting for room in the requests channel, don't queue the request
		req := asyncVerifyVoteRequest{ctx: verctx, l: l, uv: &uv, index: index, message: message, out: out}
		avv.wg.Add(1)
		if avv.backlogExecPool.EnqueueBacklog(avv.ctx, avv.executeVoteVerification, req, avv.execpoolOut) != nil {
			// we want to call "wg.Done()" here to "fix" the accounting of the number of pending tasks.
			// if we got a non-nil, it means that our context has expired, which means that we won't see this task
			// getting to the verification function.
			avv.wg.Done()
		}
	}
}

func (avv *AsyncVoteVerifier) verifyEqVote(verctx context.Context, l LedgerReader, uev unauthenticatedEquivocationVote, index int, message message, out chan<- asyncVerifyVoteResponse) {
	select {
	case <-avv.ctx.Done(): // if we're quitting, don't enqueue the request
	// case <-verctx.Done(): DO NOT DO THIS! otherwise we will lose the vote (and forget to clean up)!
	// instead, enqueue so the worker will set the error value and return the cancelled vote properly.
	default:
		// if we're done while waiting for room in the requests channel, don't queue the request
		req := asyncVerifyVoteRequest{ctx: verctx, l: l, uev: &uev, index: index, message: message, out: out}
		avv.wg.Add(1)
		if avv.backlogExecPool.EnqueueBacklog(avv.ctx, avv.executeEqVoteVerification, req, avv.execpoolOut) != nil {
			// we want to call "wg.Done()" here to "fix" the accounting of the number of pending tasks.
			// if we got a non-nil, it means that our context has expired, which means that we won't see this task
			// getting to the verification function.
			avv.wg.Done()
		}
	}
}

// Quit tells the AsyncVoteVerifier to shutdown and waits until all workers terminate.
func (avv *AsyncVoteVerifier) Quit() {
	// indicate we're done and wait for all workers to finish
	avv.ctxCancel()

	// wait until all the tasks we've given the pool are done.
	avv.wg.Wait()
	if avv.backlogExecPool.GetOwner() == avv {
		avv.backlogExecPool.Shutdown()
	}

	// since no more tasks are coming, we can safely close the output pool channel.
	close(avv.execpoolOut)
	// wait until the worker function exists.
	<-avv.workerWaitCh
}

// Parallelism gives the maximum parallelism of the vote verifier.
func (avv *AsyncVoteVerifier) Parallelism() int {
	return avv.backlogExecPool.GetParallelism()
}
