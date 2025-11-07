// Copyright (C) 2019-2025 Algorand, Inc.
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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// implements BatchProcessor interface for testing purposes
type mockBatchProcessor struct {
	notify chan struct{} // notify the test that cleanup was called
}

func (mbp *mockBatchProcessor) ProcessBatch(jobs []InputJob) {
	for i := range jobs {
		job := jobs[i].(*mockJob)
		job.processed = true
		job.batchSize = len(jobs)
		job.batchOrder = i
		if job.callback != nil {
			job.callback(job.id)
		}
	}
}

func (mbp *mockBatchProcessor) GetErredUnprocessed(ue InputJob, err error) {
	job := ue.(*mockJob)
	job.returnError = err
}

func (mbp *mockBatchProcessor) Cleanup(ue []InputJob, err error) {
	for i := range ue {
		mbp.GetErredUnprocessed(ue[i], err)
	}
	if mbp.notify != nil && len(ue) > 0 {
		mbp.notify <- struct{}{}
	}
}

// implements InputJob interface
type mockJob struct {
	id            int
	numberOfItems uint64
	jobError      error
	returnError   error
	processed     bool
	batchSize     int
	batchOrder    int
	callback      func(id int)
}

func (mj *mockJob) GetNumberOfBatchableItems() (count uint64, err error) {
	return mj.numberOfItems, mj.jobError
}

type mockPool struct {
	pool
	hold         chan struct{} // used to sync the EnqueueBacklog call with the test
	err          error         // when not nil, EnqueueBacklog will return the err instead of executing the task
	poolCapacity chan struct{} // mimics the pool capacity which blocks EnqueueBacklog
	asyncDelay   chan struct{} // used to control when the task gets executed after EnqueueBacklog queues and returns
}

func (mp *mockPool) EnqueueBacklog(enqueueCtx context.Context, t ExecFunc, arg interface{}, out chan interface{}) error {
	// allow the test to know when the exec pool is executing the job
	<-mp.hold
	// simulate the execution of the job by the pool
	if mp.err != nil {
		// return the mock error
		return mp.err
	}
	mp.poolCapacity <- struct{}{}
	go func() {
		mp.asyncDelay <- struct{}{}
		t(arg)
	}()
	return nil
}

func (mp *mockPool) BufferSize() (length, capacity int) {
	return len(mp.poolCapacity), cap(mp.poolCapacity)
}

func testStreamToBatchCore(wg *sync.WaitGroup, mockJobs <-chan *mockJob, done <-chan struct{}, t *testing.T) {
	defer wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	verificationPool := MakeBacklog(nil, 0, LowPriority, t)
	defer verificationPool.Shutdown()

	inputChan := make(chan InputJob)
	mbp := mockBatchProcessor{}
	sv := MakeStreamToBatch(inputChan, verificationPool, &mbp)
	sv.Start(ctx)

	for j := range mockJobs {
		inputChan <- j
	}
	<-done
	cancel()
	sv.WaitForStop()
}

// TestStreamToBatchBasic tests the basic functionality
func TestStreamToBatchBasic(t *testing.T) {
	partitiontest.PartitionTest(t)

	numJobs := 400
	// for GetNumberOfBatchableItems errors: 400 / 99
	numJobsToProcess := 400 - (400/99 + 1)
	// processedChan will notify whenn all the jobs are processed
	processedChan := make(chan struct{}, numJobsToProcess-1)
	done := make(chan struct{})
	// callback is needed to know when the processing should stop
	callback := func(id int) {
		select {
		case processedChan <- struct{}{}:
		default:
			// this was the last job
			close(done)
		}
	}
	numError := fmt.Errorf("err on GetNumberOfBatchableItems")
	mockJobs := make([]*mockJob, numJobs, numJobs)
	for i := 0; i < numJobs; i++ {
		mockJobs[i] = &mockJob{
			id: i,
			// get some jobs with 0 items too
			numberOfItems: uint64(i % 5),
			callback:      callback}

		if i%99 == 0 {
			// get GetNumberOfBatchableItems to report an error
			mockJobs[i].jobError = numError
		}
		if i%101 == 0 {
			// have a batch exceeding batchSizeBlockLimit limit
			mockJobs[i].numberOfItems = batchSizeBlockLimit + 1
		}
	}
	jobChan := make(chan *mockJob)
	wg := sync.WaitGroup{}
	wg.Add(2)
	go testStreamToBatchCore(&wg, jobChan, done, t)

	go func() {
		defer wg.Done()
		for i := range mockJobs {
			jobChan <- mockJobs[i]
		}
		close(jobChan)
		<-done
	}()
	wg.Wait()
	for i := 0; i < numJobs; i++ {
		if i%99 == 0 {
			// this should be GetNumberOfBatchableItems
			require.ErrorIs(t, mockJobs[i].returnError, numError)
			require.False(t, mockJobs[i].processed)
			continue
		}
		if i%5 == 0 {
			// this should be processed alone
			if 1 != mockJobs[i].batchSize {
				require.Equal(t, 1, mockJobs[i].batchSize)
			}
		}
		if i%101 == 0 {
			// this should be the last in the batch
			require.Equal(t, mockJobs[i].batchSize-1, mockJobs[i].batchOrder)
		}
		if mockJobs[i].returnError != nil {
			require.Nil(t, mockJobs[i].returnError)
		}
		require.True(t, mockJobs[i].processed)
	}
}

// TestNoInputYet let the service start and get to the timeout without any inputs
func TestNoInputYet(t *testing.T) {
	partitiontest.PartitionTest(t)

	numJobs := 1
	done := make(chan struct{})
	jobChan := make(chan *mockJob)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go testStreamToBatchCore(&wg, jobChan, done, t)
	callback := func(id int) {
		if id == numJobs-1 {
			close(done)
		}
	}
	// Wait to trigger the timer once with 0 elements
	time.Sleep(2 * waitForNextJobDuration)

	// send a job, make sure it goes through
	mockJob := &mockJob{
		numberOfItems: uint64(0),
		callback:      callback}
	jobChan <- mockJob
	<-done
	require.Nil(t, mockJob.returnError)
	require.True(t, mockJob.processed)
	require.Equal(t, 1, mockJob.batchSize)
	close(jobChan)
	wg.Wait()
}

// TestMutipleBatchAttempts tests the behavior when multiple batch attempts will fail and the stream blocks
func TestMutipleBatchAttempts(t *testing.T) {
	partitiontest.PartitionTest(t)

	mp := mockPool{
		hold:         make(chan struct{}),
		err:          nil,
		poolCapacity: make(chan struct{}, 1),
		asyncDelay:   make(chan struct{}, 10),
	}

	ctx, cancel := context.WithCancel(context.Background())

	inputChan := make(chan InputJob)
	mbp := mockBatchProcessor{}
	sv := MakeStreamToBatch(inputChan, &mp, &mbp)
	sv.Start(ctx)

	var jobCalled int
	jobCalledRef := &jobCalled
	callbackFeedback := make(chan struct{})

	mj := mockJob{
		numberOfItems: uint64(txnPerWorksetThreshold + 1),
		id:            1,
		callback: func(id int) {
			*jobCalledRef = *jobCalledRef + id
			<-callbackFeedback
		},
	}
	// first saturate the pool
	mp.poolCapacity <- struct{}{}
	inputChan <- &mj

	// wait for the job to be submitted to the pool
	// since this is only a single job with 1 task, and the pool is at capacity,
	// this will only happen when the numberOfBatchAttempts == 1
	mp.hold <- struct{}{}

	// here, the pool is saturated, and the stream should be blocked
	select {
	case inputChan <- &mj:
		require.Fail(t, "the stream should be blocked here")
	default:
	}

	// now let the pool regian capacity
	<-mp.poolCapacity

	// make sure it is processed before reading the value
	callbackFeedback <- struct{}{}
	require.Equal(t, 1, jobCalled)

	// the stream should be unblocked now
	inputChan <- &mj

	// let the next job go through
	mp.hold <- struct{}{}
	// give the pool the capacity for it to process
	<-mp.poolCapacity

	// make sure it is processed before reading the value
	callbackFeedback <- struct{}{}
	require.Equal(t, 2, jobCalled)

	cancel()
	sv.WaitForStop()
}

// TestErrors tests all the cases where exec pool returned error is handled
// by ending the stream processing
func TestErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	mp := mockPool{
		hold:         make(chan struct{}),
		err:          fmt.Errorf("Test error"),
		poolCapacity: make(chan struct{}, 5),
		asyncDelay:   make(chan struct{}, 10),
	}

	ctx := t.Context()

	inputChan := make(chan InputJob)
	mbp := mockBatchProcessor{}
	sv := MakeStreamToBatch(inputChan, &mp, &mbp)

	/***************************************************/
	// error adding to the pool when numberOfBatchable=0
	/***************************************************/
	sv.Start(ctx)
	mj := mockJob{
		numberOfItems: 0,
	}
	inputChan <- &mj
	// let the enqueue pool process and return an error
	mp.hold <- struct{}{}
	// if errored, should not process the callback on the job
	// This is based on the mockPool EnqueueBacklog behavior
	require.False(t, mj.processed)
	// the service should end
	sv.WaitForStop()

	/***************************************************/
	// error adding to the pool when < txnPerWorksetThreshold
	/***************************************************/
	// Case where the timer ticks
	sv.Start(ctx)
	mj.numberOfItems = txnPerWorksetThreshold - 1
	inputChan <- &mj
	// let the enqueue pool process and return an error
	mp.hold <- struct{}{}
	require.False(t, mj.processed)
	// the service should end
	sv.WaitForStop()

	/***************************************************/
	// error adding to the pool when <= batchSizeBlockLimit
	/***************************************************/
	// Case where the timer ticks
	sv.Start(ctx)
	mj.numberOfItems = batchSizeBlockLimit
	inputChan <- &mj
	// let the enqueue pool process and return an error
	mp.hold <- struct{}{}
	require.False(t, mj.processed)
	// the service should end
	sv.WaitForStop()

	/***************************************************/
	// error adding to the pool when > batchSizeBlockLimit
	/***************************************************/
	// Case where the timer ticks
	sv.Start(ctx)
	mj.numberOfItems = batchSizeBlockLimit + 1
	inputChan <- &mj
	// let the enqueue pool process and return an error
	mp.hold <- struct{}{}
	require.False(t, mj.processed)
	// the service should end
	sv.WaitForStop()
}

// TestPendingJobOnRestart makes sure a pending job in the exec pool is cancled
// when the Stream ctx is cancled, and a now one started with a new ctx
func TestPendingJobOnRestart(t *testing.T) {
	partitiontest.PartitionTest(t)

	mp := mockPool{
		hold:         make(chan struct{}),
		poolCapacity: make(chan struct{}, 2),
		asyncDelay:   make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	inputChan := make(chan InputJob)
	mbp := mockBatchProcessor{
		notify: make(chan struct{}, 1),
	}
	sv := MakeStreamToBatch(inputChan, &mp, &mbp)

	// start with a saturated pool so that the job will not go through before
	// the ctx is cancled
	mp.poolCapacity <- struct{}{}

	sv.Start(ctx)
	mj := mockJob{
		numberOfItems: 1,
	}
	inputChan <- &mj
	// wait for the job to be submitted to the exec pool, waiting for capacity
	mp.hold <- struct{}{}

	// now the job should be waiting in the exec pool queue waiting to be executed

	// cancel the ctx
	cancel()
	// make sure EnqueueBacklog has returned and the stream can terminate
	sv.WaitForStop()

	// start a new session
	ctx, cancel = context.WithCancel(context.Background())
	sv.Start(ctx)

	// submit a new job
	callbackFeedback := make(chan struct{}, 1)
	mjNew := mockJob{
		numberOfItems: 1,
		callback: func(id int) {
			callbackFeedback <- struct{}{}
		},
	}
	inputChan <- &mjNew
	mp.hold <- struct{}{}
	<-mp.poolCapacity

	// when the exec pool tries to execute the jobs,
	// the function in addBatchToThePoolNow should abort the old and process the new
	<-mp.asyncDelay
	<-mp.asyncDelay

	// wait for the notifiation from cleanup before checking the TestPendingJobOnRestart
	<-mbp.notify
	require.Error(t, mj.returnError)
	require.False(t, mj.processed)

	<-callbackFeedback
	require.True(t, mjNew.processed)

	cancel()
	sv.WaitForStop()
}
