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
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/util/execpool"
)

type voteBatchProcessor struct {
	outChan chan<- interface{}
}

// ProcessBatch implements stream.BatchProcessor interface
func (vbp *voteBatchProcessor) ProcessBatch(jobs []execpool.InputJob) {
	verificationTasks := makeVerificationTasksAndResults(len(jobs))
	// taskedJobs are the jobs that passed the initial checks and a signiture verification task if created for them
	taskedJobs := make([]*asyncVerifyVoteRequest, 0, len(jobs))
	for i := range jobs {
		req := jobs[i].(*asyncVerifyVoteRequest)
		select {
		case <-req.ctx.Done():
			// request of the job is cancelled, return an error response on the channel
			vbp.GetErredUnprocessed(jobs[i], req.ctx.Err())
		default:
		}
		// if this is an eq vote
		if req.uev != nil {
			vts, m, err := req.uev.getEquivocVerificationTasks(req.l)
			if err != nil {
				var e *LedgerDroppedRoundError
				cancelled := errors.As(err, &e)
				vbp.outChan <- &asyncVerifyVoteResponse{index: req.index, message: req.message, err: err, cancelled: cancelled, req: req}
				continue
			}
			taskedJobs = append(taskedJobs, req)
			verificationTasks.addEqVoteJob(vts, m, req.uev)
			continue
		}
		// if this is a vote
		if req.uv != nil {
			m, err := membership(req.l, req.uv.R.Sender, req.uv.R.Round, req.uv.R.Period, req.uv.R.Step)
			if err != nil {
				err2 := fmt.Errorf("voteBatchProcessor.ProcessBatch: could not get membership parameters: %w", err)
				var e *LedgerDroppedRoundError
				cancelled := errors.As(err, &e)
				vbp.outChan <- &asyncVerifyVoteResponse{index: req.index, message: req.message, err: err2, cancelled: cancelled, req: req}
				continue
			}
			vt, err := req.uv.getVerificationTask(req.l, &m)
			if err != nil {
				var e *LedgerDroppedRoundError
				cancelled := errors.As(err, &e)
				vbp.outChan <- &asyncVerifyVoteResponse{index: req.index, message: req.message, err: err, cancelled: cancelled, req: req}
				continue
			}
			taskedJobs = append(taskedJobs, req)
			verificationTasks.addVoteJob(vt, &m, req.uv)
		}
	}
	// Signiture verification of the batch
	verificationTasks.failed = crypto.BatchVerifyOneTimeSignatures(verificationTasks.tasks)
	for i := range taskedJobs {
		req := taskedJobs[i]
		// check if the signature passed, authenticate cred and return the vote/equivocationVote
		v, ev, err := verificationTasks.getJobResult(req, i)
		var e *LedgerDroppedRoundError
		cancelled := errors.As(err, &e)
		if v != nil {
			req.message.Vote = *v
			vbp.outChan <- &asyncVerifyVoteResponse{v: *v, index: req.index, message: req.message, err: err, cancelled: cancelled, req: req}
		} else if ev != nil {
			vbp.outChan <- &asyncVerifyVoteResponse{ev: *ev, index: req.index, message: req.message, err: err, cancelled: cancelled, req: req}
		} else {
			vbp.outChan <- &asyncVerifyVoteResponse{index: req.index, message: req.message, err: err, cancelled: cancelled, req: req}
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

type unauthVMem struct {
	uv  *unauthenticatedVote
	uev *unauthenticatedEquivocationVote
	m   *committee.Membership
}

// verificationTasksAndResults holds information of a single batch, composed of multiple jobs
// each job corresponds to either a vote or an equivocationVote
// each vote job has 1 SigVerificationTask, each equivocationVote has 2 SigVerificationTask
type verificationTasksAndResults struct {
	// failed is the verification results of tasks, so they will have the same length
	// each vote job has 1 entry in tasks, each equivocationVote has 2 entries
	// taskIndexes maps the jobs to the tasks (one entry for each job)
	//     taskIndexes[k] is the position of the job k+1 in tasks (0 is the first job)
	//     if taskIndexes[k+1]-taskIndexes[k] == 1, job k+1 is a vote,
	//     if taskIndexes[k+1]-taskIndexes[k] == 2, job k+1 is an equivocationVote with 2 tasks
	// unauthV is the data associated with each job, it has the same length as taskIndexes
	tasks       []*crypto.SigVerificationTask
	failed      []bool
	taskIndexes []int
	unauthV     []unauthVMem
}

func makeVerificationTasksAndResults(initialSize int) verificationTasksAndResults {
	vtr := verificationTasksAndResults{}
	vtr.tasks = make([]*crypto.SigVerificationTask, 0, initialSize)
	vtr.taskIndexes = make([]int, 0, initialSize)
	vtr.failed = make([]bool, 0, initialSize)
	vtr.unauthV = make([]unauthVMem, 0, initialSize)
	return vtr
}

// addEqVoteJob adds 2 tasks for a single equivocation vote job
func (vtr *verificationTasksAndResults) addEqVoteJob(tasks []*crypto.SigVerificationTask, m *committee.Membership, uv *unauthenticatedEquivocationVote) {
	prev := len(vtr.tasks)
	vtr.tasks = append(vtr.tasks, tasks...)
	vtr.taskIndexes = append(vtr.taskIndexes, prev+len(tasks))
	vtr.unauthV = append(vtr.unauthV, unauthVMem{uev: uv, m: m})
}

// addVoteJob adds 1 task for a single vote job
func (vtr *verificationTasksAndResults) addVoteJob(task *crypto.SigVerificationTask, m *committee.Membership, uv *unauthenticatedVote) {
	prev := len(vtr.tasks)
	vtr.tasks = append(vtr.tasks, task)
	vtr.taskIndexes = append(vtr.taskIndexes, prev+1)
	vtr.unauthV = append(vtr.unauthV, unauthVMem{uv: uv, m: m})
}

// getJobResult returns the authenticated vote (or equivocation vote) for the j-th job (request)
func (vtr *verificationTasksAndResults) getJobResult(req *asyncVerifyVoteRequest, j int) (*vote, *equivocationVote, error) {
	i0 := 0 // i0 is the index of the first task in tasks for j (i0 is always 0 for j=0)
	if j > 0 {
		i0 = vtr.taskIndexes[j-1]
	}
	// if isEV (is equivocationVote, then there are 2 tasks, and i0 is the index of the first)
	isEV := vtr.taskIndexes[j]-i0 == 2

	// is eq vote, there are 2 results in failed that need to be checked
	if isEV {
		// pairIndexes are the indexes in tasks for the 2 tasks corresponding to the equivocationVote job
		pairIndexes := []int{i0, i0 + 1}
		for p, i := range pairIndexes {
			if !vtr.failed[i] {
				continue
			}
			rv := vtr.tasks[i].Message.(rawVote)
			voteID := vtr.tasks[i].V
			return nil, nil, fmt.Errorf("verificationTasksAndResults.getJobResult: failed to verify pair %d: %w", p,
				fmt.Errorf("could not verify FS signature on vote by %v given %v: %+v", rv.Sender, voteID, vtr.unauthV[j].uev))
		}
		// here, the signatures of both votes are verified. Now authenticate the cred
		ev, err := vtr.unauthV[j].uev.authenticateCredAndGetEqVote(req.l, vtr.unauthV[j].m)
		return nil, ev, err
	}

	// is Vote, there is only 1 result in failed to be checked
	if vtr.failed[i0] {
		rv := vtr.tasks[i0].Message.(rawVote)
		voteID := vtr.tasks[i0].V
		return nil, nil, fmt.Errorf("verificationTasksAndResults.getJobResult: could not verify FS signature on vote by %v given %v: %+v", rv.Sender, voteID, req.uv)
	}
	// Validate the cred
	v, err := vtr.unauthV[j].uv.authenticateCredAndGetVote(req.l, vtr.unauthV[j].m)
	return v, nil, err
}
