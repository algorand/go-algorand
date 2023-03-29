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

package agreement

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/util/execpool"
)

type asyncVerifyVoteRequest struct {
	ctx     context.Context
	l       LedgerReader
	uv      *unauthenticatedVote
	uev     *unauthenticatedEquivocationVote
	index   uint64
	message message

	// a channel that holds the response
	out chan<- asyncVerifyVoteResponse
}

type asyncVerifyVoteResponse struct {
	v         vote
	ev        equivocationVote
	index     uint64
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
	batchVerifier   *execpool.StreamToBatch
	batchInputChan  chan execpool.InputJob
}

// MakeStartAsyncVoteVerifier creates an AsyncVoteVerifier with workers as the number of CPUs
func MakeStartAsyncVoteVerifier(verificationPool execpool.BacklogPool) *AsyncVoteVerifier {
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

	verifier.batchInputChan = make(chan execpool.InputJob)

	verifier.batchVerifier = execpool.MakeStreamToBatch(
		verifier.batchInputChan,
		verificationPool,
		&voteBatchProcessor{outChan: verifier.execpoolOut})
	go verifier.worker()
	verifier.batchVerifier.Start(verifier.ctx)
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

func (avv *AsyncVoteVerifier) verifyVote(verctx context.Context, l LedgerReader, uv unauthenticatedVote, index uint64, message message, out chan<- asyncVerifyVoteResponse) {
	select {
	case <-avv.ctx.Done(): // if we're quitting, don't enqueue the request
	// case <-verctx.Done(): DO NOT DO THIS! otherwise we will lose the vote (and forget to clean up)!
	// instead, enqueue so the worker will set the error value and return the cancelled vote properly.
	default:
		// if we're done while waiting for room in the requests channel, don't queue the request
		req := asyncVerifyVoteRequest{ctx: verctx, l: l, uv: &uv, index: index, message: message, out: out}
		avv.wg.Add(1)
		avv.batchInputChan <- &req
	}
}

func (avv *AsyncVoteVerifier) verifyEqVote(verctx context.Context, l LedgerReader, uev unauthenticatedEquivocationVote, index uint64, message message, out chan<- asyncVerifyVoteResponse) {
	select {
	case <-avv.ctx.Done(): // if we're quitting, don't enqueue the request
	// case <-verctx.Done(): DO NOT DO THIS! otherwise we will lose the vote (and forget to clean up)!
	// instead, enqueue so the worker will set the error value and return the cancelled vote properly.
	default:
		// if we're done while waiting for room in the requests channel, don't queue the request
		req := asyncVerifyVoteRequest{ctx: verctx, l: l, uev: &uev, index: index, message: message, out: out}
		avv.wg.Add(1)
		avv.batchInputChan <- &req
	}
}

// Quit tells the AsyncVoteVerifier to shutdown and waits until all workers terminate.
func (avv *AsyncVoteVerifier) Quit() {
	// indicate we're done and wait for all workers to finish
	avv.ctxCancel()

	// wait until the batchVerifier stops and reports cancled error on remaining unverified sigs (excepts the ones in exec pool)
	avv.batchVerifier.WaitForStop()

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

func (uv *asyncVerifyVoteRequest) GetNumberOfBatchableItems() (count uint64, err error) {
	if uv.uev != nil {
		return uint64(2), nil
	}
	return uint64(1), nil
}

type voteBatchProcessor struct {
	outChan chan<- interface{}
}

type voteEqVote struct {
	v  *vote
	ev *equivocationVote
}

type verificationTasksResults struct {
	tasks       []*crypto.SigVerificationTask
	taskIndexes []int
	failed      []bool
	vEqV        []voteEqVote
}

func makeVerificationTasksResults(initialSize int) verificationTasksResults {
	vtr := verificationTasksResults{}
	vtr.tasks = make([]*crypto.SigVerificationTask, 0, initialSize)
	vtr.taskIndexes = make([]int, 0, initialSize)
	vtr.failed = make([]bool, 0, initialSize)
	vtr.vEqV = make([]voteEqVote, 0, initialSize)
	return vtr
}

func (vtr *verificationTasksResults) addEqVoteTasks(tasks []*crypto.SigVerificationTask, ev equivocationVote) {
	prev := len(vtr.tasks)
	vtr.tasks = append(vtr.tasks, tasks...)

	vtr.taskIndexes = append(vtr.taskIndexes, prev+len(tasks))
	vtr.vEqV = append(vtr.vEqV, voteEqVote{ev: &ev})
}

func (vtr *verificationTasksResults) addVoteTask(task *crypto.SigVerificationTask, v vote) {
	prev := len(vtr.tasks)
	vtr.tasks = append(vtr.tasks, task)
	vtr.taskIndexes = append(vtr.taskIndexes, prev+1)
	vtr.vEqV = append(vtr.vEqV, voteEqVote{v: &v})
}

func (vtr *verificationTasksResults) addResults(failed []bool) {
	vtr.failed = failed
}

func (vtr *verificationTasksResults) getItemResult(req *asyncVerifyVoteRequest, itemIndex int) (*vote, *equivocationVote, error) {
	i0 := 0
	if itemIndex > 0 {
		i0 = vtr.taskIndexes[itemIndex-1]
	}
	i1 := vtr.taskIndexes[itemIndex]
	isEV := i1-i0 == 2

	if isEV {
		pairIndexes := []int{i0, i0 + 1}
		for i := range []int{0, 1} {
			if !vtr.failed[pairIndexes[i]] {
				continue
			}
			rv := vtr.tasks[pairIndexes[i]].Message.(rawVote)
			voteID := vtr.tasks[pairIndexes[i]].V
			uv := unauthenticatedVote{
				R:    rv,
				Cred: req.uev.Cred,
				Sig:  req.uev.Sigs[i],
			}
			return nil, vtr.vEqV[itemIndex].ev, fmt.Errorf("unauthenticatedEquivocationVote.verify: failed to verify pair %d: %w", i,
				fmt.Errorf("unauthenticatedVote.verify: could not verify FS signature on vote by %v given %v: %+v", rv.Sender, voteID, uv))
		}
		return nil, vtr.vEqV[itemIndex].ev, nil
	}
	if vtr.failed[i0] {
		rv := vtr.tasks[i0].Message.(rawVote)
		voteID := vtr.tasks[i0].V
		return vtr.vEqV[itemIndex].v, nil, fmt.Errorf("unauthenticatedVote.verify: could not verify FS signature on vote by %v given %v: %+v", rv.Sender, voteID, req.uv)
	}
	return vtr.vEqV[itemIndex].v, nil, nil
}

func (vbp *voteBatchProcessor) ProcessBatch(jobs []execpool.InputJob) {
	verificationTasks := makeVerificationTasksResults(len(jobs))
	checkedRequests := make([]*asyncVerifyVoteRequest, 0, len(jobs))
	for i := range jobs {
		req := jobs[i].(*asyncVerifyVoteRequest)
		select {
		case <-req.ctx.Done():
			// request cancelled, return an error response on the channel
			vbp.Cleanup(jobs, req.ctx.Err())
		default:
			// if this is an eq vote
			if req.uev != nil {
				vts, ev, err := req.uev.getEquivocVerificationTasks(req.l)
				if err != nil {
					var e *LedgerDroppedRoundError
					cancelled := errors.As(err, &e)
					vbp.outChan <- &asyncVerifyVoteResponse{index: req.index, message: req.message, err: err, cancelled: cancelled, req: req}
				} else {
					checkedRequests = append(checkedRequests, req)
					verificationTasks.addEqVoteTasks(vts, ev)
				}
			}
			// if this is a vote
			if req.uv != nil {
				vt, v, err := req.uv.getVerificationTask(req.l)
				if err != nil {
					var e *LedgerDroppedRoundError
					cancelled := errors.As(err, &e)
					vbp.outChan <- &asyncVerifyVoteResponse{index: req.index, message: req.message, err: err, cancelled: cancelled, req: req}
				} else {
					checkedRequests = append(checkedRequests, req)
					verificationTasks.addVoteTask(vt, v)
				}
			}
		}
	}
	failed := crypto.BatchVerifyOneTimeSignatures(verificationTasks.tasks)
	verificationTasks.addResults(failed)
	for i := range checkedRequests {
		req := checkedRequests[i]
		v, ev, err := verificationTasks.getItemResult(req, i)
		var e *LedgerDroppedRoundError
		cancelled := errors.As(err, &e)
		if v != nil {
			req.message.Vote = *v
			vbp.outChan <- &asyncVerifyVoteResponse{v: *v, index: req.index, message: req.message, err: err, cancelled: cancelled, req: req}
		}
		if ev != nil {
			vbp.outChan <- &asyncVerifyVoteResponse{ev: *ev, index: req.index, message: req.message, err: err, cancelled: cancelled, req: req}
		}
	}
}

func (vbp *voteBatchProcessor) GetErredUnprocessed(ue execpool.InputJob, err error) {
	vbp.Cleanup([]execpool.InputJob{ue}, err)
}
func (vbp *voteBatchProcessor) Cleanup(ue []execpool.InputJob, err error) {
	for i := range ue {
		req := ue[i].(*asyncVerifyVoteRequest)
		vbp.outChan <- &asyncVerifyVoteResponse{index: req.index, err: err, cancelled: true, req: req}
	}
}
