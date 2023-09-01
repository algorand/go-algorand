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

package execpool

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/algorand/go-algorand/logging"
)

// ErrShuttingDownError is the error returned when a job is not processed because the service is shutting down
var ErrShuttingDownError = errors.New("not processed, execpool service is shutting down")

// waitForNextJobDuration is the time to wait before sending the batch to the exec pool
// If the incoming rate is low, an input job in the batch may wait no less than
// waitForNextJobDuration before it is sent for processing.
// This can introduce a latency to the propagation in the network (e.g. sigs in txn or vote),
// since every relay will go through this wait time before broadcasting the result.
// However, when the incoming rate is high, the batch will fill up quickly and will send
// for processing before waitForNextJobDuration.
const waitForNextJobDuration = 2 * time.Millisecond

const txnPerWorksetThreshold = 32

// batchSizeBlockLimit is the limit when the batch exceeds, will be added to the exec pool, even if the pool is saturated
// and the stream  will be blocked until the exec pool accepts the batch
const batchSizeBlockLimit = 1024

// InputJob is the interface the incoming jobs need to implement
type InputJob interface {
	GetNumberOfBatchableItems() (count uint64, err error)
}

// BatchProcessor is the interface of the functions needed to prepare a batch from the stream,
// process and return the results
type BatchProcessor interface {
	// ProcessBatch processes a batch packed from the stream in the execpool
	ProcessBatch(jobs []InputJob)
	// GetErredUnprocessed returns an unprocessed jobs because of an err
	GetErredUnprocessed(ue InputJob, err error)
	// Cleanup called on the unprocessed jobs when the service shuts down
	Cleanup(ue []InputJob, err error)
}

// StreamToBatch makes batches from incoming stream of jobs, and submits the batches to the exec pool
type StreamToBatch struct {
	inputChan      <-chan InputJob
	executionPool  BacklogPool
	ctx            context.Context
	activeLoopWg   sync.WaitGroup
	batchProcessor BatchProcessor
}

// MakeStreamToBatch creates a new stream to batch converter
func MakeStreamToBatch(inputChan <-chan InputJob, execPool BacklogPool,
	batchProcessor BatchProcessor) *StreamToBatch {

	return &StreamToBatch{
		inputChan:      inputChan,
		executionPool:  execPool,
		batchProcessor: batchProcessor,
	}
}

// Start is called when the StreamToBatch is created and whenever it needs to restart after
// the ctx is canceled
func (sv *StreamToBatch) Start(ctx context.Context) {
	sv.ctx = ctx
	sv.activeLoopWg.Add(1)
	go sv.batchingLoop()
}

// WaitForStop waits until the batching loop terminates afer the ctx is canceled
func (sv *StreamToBatch) WaitForStop() {
	sv.activeLoopWg.Wait()
}

func (sv *StreamToBatch) batchingLoop() {
	defer sv.activeLoopWg.Done()
	timer := time.NewTicker(waitForNextJobDuration)
	defer timer.Stop()
	var processed bool
	var numberOfJobsInCurrent uint64
	var numberOfBatchAttempts uint64
	uJobs := make([]InputJob, 0, 8)
	defer func() { sv.batchProcessor.Cleanup(uJobs, ErrShuttingDownError) }()
	for {
		select {
		case job := <-sv.inputChan:
			numberOfBatchable, err := job.GetNumberOfBatchableItems()
			if err != nil {
				sv.batchProcessor.GetErredUnprocessed(job, err)
				continue
			}

			// if no batchable items here, send this as a task of its own
			if numberOfBatchable == 0 {
				sv.addBatchToThePoolNow([]InputJob{job})
				continue // job is handled, continue
			}

			// add this job to the list of batchable jobs
			numberOfJobsInCurrent = numberOfJobsInCurrent + numberOfBatchable
			uJobs = append(uJobs, job)
			if numberOfJobsInCurrent > txnPerWorksetThreshold {
				// enough jobs in the batch to efficiently process

				if numberOfJobsInCurrent > batchSizeBlockLimit {
					// do not consider adding more jobs to this batch.
					// bypass the exec pool situation and queue anyway
					// this is to prevent creation of very large batches
					sv.addBatchToThePoolNow(uJobs)
					processed = true
				} else {
					processed = sv.tryAddBatchToThePool(uJobs)
				}
				if processed {
					numberOfJobsInCurrent = 0
					uJobs = make([]InputJob, 0, 8)
					numberOfBatchAttempts = 0
				} else {
					// was not added because of the exec pool buffer length
					numberOfBatchAttempts++
				}
			}
		case <-timer.C:
			// timer ticked. it is time to send the batch even if it is not full
			if numberOfJobsInCurrent == 0 {
				// nothing batched yet... wait some more
				continue
			}
			if numberOfBatchAttempts > 1 {
				// bypass the exec pool situation and queue anyway
				// this is to prevent long delays in the propagation (sigs txn/vote)
				// at least one job has waited 3 x waitForNextJobDuration
				sv.addBatchToThePoolNow(uJobs)
				processed = true
			} else {
				processed = sv.tryAddBatchToThePool(uJobs)
			}
			if processed {
				numberOfJobsInCurrent = 0
				uJobs = make([]InputJob, 0, 8)
				numberOfBatchAttempts = 0
			} else {
				// was not added because of the exec pool buffer length. wait for some more
				numberOfBatchAttempts++
			}
		case <-sv.ctx.Done():
			for {
				select {
				case job := <-sv.inputChan:
					uJobs = append(uJobs, job)
				default:
					return
				}
			}
		}
	}
}

func (sv *StreamToBatch) tryAddBatchToThePool(uJobs []InputJob) (processed bool) {
	// if the exec pool buffer is full, can go back and collect
	// more jobs instead of waiting in the exec pool buffer
	// e.g. more signatures to the batch do not harm performance but introduce latency when delayed (see crypto.BenchmarkBatchVerifierBig)

	// if the buffer is full
	if l, c := sv.executionPool.BufferSize(); l == c {
		return false
	}
	sv.addBatchToThePoolNow(uJobs)
	return true
}

func (sv *StreamToBatch) addBatchToThePoolNow(unprocessed []InputJob) {
	// if the context is canceled when the task is in the queue, it should be canceled
	// copy the ctx here so that when the StreamToBatch is started again, and a new context
	// is created, this task still gets canceled due to the ctx at the time of this task
	taskCtx := sv.ctx
	function := func(arg interface{}) interface{} {
		uJobs := arg.([]InputJob)
		if taskCtx.Err() != nil {
			// ctx is canceled. the results will be returned
			sv.batchProcessor.Cleanup(uJobs, ErrShuttingDownError)
			return nil
		}

		sv.batchProcessor.ProcessBatch(uJobs)
		return nil
	}

	// EnqueueBacklog returns an error when the context is canceled
	err := sv.executionPool.EnqueueBacklog(sv.ctx, function, unprocessed, nil)
	// In case of an error (when the execpool is cancled/shut down), return the unprocessed jobs with the returned error.

	// Historic background: initially, the error was fatal, meaning the main loop would return and shut down. The reasoning behind this
	// was because the pool cannot recover once cancled, and all subsequent jobs would fail.  However, when the service stops, any
	// subsequent jobs sent to the input channel will block indefinitely, because the consumer end of the channel has stopped. Blocking
	// the jobs without reporting an error could be a problem, and since the agreement service has tests expecting an error against a
	// cancled exec pool, the behavior here is now changed.
	if err != nil {
		logging.Base().Errorf("addBatchToThePoolNow: EnqueueBacklog returned an error on the %d sig verifications: %v", len(unprocessed), err)
		sv.batchProcessor.Cleanup(unprocessed, err)
	}
}
