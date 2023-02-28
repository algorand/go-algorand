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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// implements BatchProcessor interface for testing purposes
type mockBatchProcessor struct {
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

func testStreamToBatchCore(mockJobs <-chan *mockJob, done <-chan struct{}, t *testing.T) {
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
	done := make(chan struct{})
	// callback is needed to know when the processing should stop
	callback := func(id int) {
		if id == numJobs-1 {
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
	go func() {
		defer wg.Done()
		testStreamToBatchCore(jobChan, done, t)
	}()
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
			require.Equal(t, 1, mockJobs[i].batchSize)
		}
		if i%101 == 0 {
			// this should be the last in the batch
			require.Equal(t, mockJobs[i].batchSize-1, mockJobs[i].batchOrder)
		}
		require.Nil(t, mockJobs[i].returnError)
		require.True(t, mockJobs[i].processed)
	}
}

// TestNoInputYet let the servicd start and get to the timeout without any inputs
func TestNoInputYet(t *testing.T) {
	partitiontest.PartitionTest(t)

	numJobs := 1
	done := make(chan struct{})
	jobChan := make(chan *mockJob)
	go testStreamToBatchCore(jobChan, done, t)
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
}
