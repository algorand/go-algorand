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

package verify

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/execpool"
)

// ErrShuttingDownError is the error returned when a sig is not verified because the service is shutting down
var ErrShuttingDownError = errors.New("not verified, verifier is shutting down")

// waitForNextElmtDuration is the time to wait before sending the batch to the exec pool
// If the incoming rate is low, an input job in the batch may wait no less than
// waitForNextElmtDuration before it is set for verification.
// This can introduce a latency to the propagation of the sigs (e.g. in txn or vote) in the network,
// since every relay will go through this wait time before broadcasting the result.
// However, when the incoming rate is high, the batch will fill up quickly and will send
// for signature evaluation before waitForNextElmtDuration.
const waitForNextElmtDuration = 2 * time.Millisecond

// batchSizeBlockLimit is the limit when the batch exceeds, will be added to the exec pool, even if the pool is saturated
// and the batch verifier will block until the exec pool accepts the batch
const batchSizeBlockLimit = 1024

// UnverifiedSigJob is the interface the incoming sig verification elts need to implement
type UnverifiedSigJob interface {
	GetNumberOfBatchableSigsInGroup() (batchSigs uint64, err error)
}

// SigVerifyJobProcessor is the interface of the functions needed to extract signatures from the input jobs, post-process the results,
// send the results and cleanup when shutting down.
type ElementProcessor interface {
	// ProcessElements processes a batch packed from the stream in the execpool
	ProcessElements(uelts []UnverifiedElement)
	// GetErredUnverified returns an unverified jobs because of the err
	GetErredUnverified(ue UnverifiedElement, err error)
	// Cleanup called on the unverified elements when the verification shuts down
	Cleanup(ue []UnverifiedElement, err error)
}

// StreamVerifier verifies signatures in input jobs received through the inputChan channel, and returns the
// results through the resultChan
type StreamVerifier struct {
	inputChan        <-chan UnverifiedSigJob
	verificationPool execpool.BacklogPool
	ctx              context.Context
	activeLoopWg     sync.WaitGroup
	verifyProcessor  SigVerifyJobProcessor
}

// MakeStreamVerifier creates a new stream verifier to verify signatures in jobs received through inputChan
func MakeStreamVerifier(inputChan <-chan UnverifiedSigJob, verificationPool execpool.BacklogPool,
	verifyProcessor SigVerifyJobProcessor) *StreamVerifier {

	return &StreamVerifier{
		inputChan:        inputChan,
		verificationPool: verificationPool,
		verifyProcessor:  verifyProcessor,
	}
}

// Start is called when the verifier is created and whenever it needs to restart after
// the ctx is canceled
func (sv *StreamVerifier) Start(ctx context.Context) {
	sv.ctx = ctx
	sv.activeLoopWg.Add(1)
	go sv.batchingLoop()
}

// WaitForStop waits until the batching loop terminates afer the ctx is canceled
func (sv *StreamVerifier) WaitForStop() {
	sv.activeLoopWg.Wait()
}

func (sv *StreamVerifier) batchingLoop() {
	defer sv.activeLoopWg.Done()
	timer := time.NewTicker(waitForNextElmtDuration)
	defer timer.Stop()
	var added bool
	var numberOfSigsInCurrent uint64
	var numberOfBatchAttempts uint64
	uElmts := make([]UnverifiedSigJob, 0, 8)
	defer func() { sv.verifyProcessor.Cleanup(uElmts, ErrShuttingDownError) }()
	for {
		select {
		case elem := <-sv.inputChan:
			numberOfBatchableSigsInGroup, err := elem.GetNumberOfBatchableSigsInGroup()
			if err != nil {
				sv.verifyProcessor.GetErredUnverified(elem, err)
				continue
			}

			// if no batchable signatures here, send this as a task of its own
			if numberOfBatchableSigsInGroup == 0 {
				err := sv.addVerificationTaskToThePoolNow([]UnverifiedSigJob{elem})
				if err != nil {
					return
				}
				continue // elem is handled, continue
			}

			// add this job to the list of batchable signatures
			numberOfSigsInCurrent = numberOfSigsInCurrent + numberOfBatchableSigsInGroup
			uElmts = append(uElmts, elem)
			if numberOfSigsInCurrent > txnPerWorksetThreshold {
				// enough signatures in the batch to efficiently verify

				if numberOfSigsInCurrent > batchSizeBlockLimit {
					// do not consider adding more signatures to this batch.
					// bypass the exec pool situation and queue anyway
					// this is to prevent creation of very large batches
					err := sv.addVerificationTaskToThePoolNow(uElmts)
					if err != nil {
						return
					}
					added = true
				} else {
					added, err = sv.tryAddVerificationTaskToThePool(uElmts)
					if err != nil {
						return
					}
				}
				if added {
					numberOfSigsInCurrent = 0
					uElmts = make([]UnverifiedSigJob, 0, 8)
					numberOfBatchAttempts = 0
				} else {
					// was not added because of the exec pool buffer length
					numberOfBatchAttempts++
				}
			}
		case <-timer.C:
			// timer ticked. it is time to send the batch even if it is not full
			if numberOfSigsInCurrent == 0 {
				// nothing batched yet... wait some more
				continue
			}
			var err error
			if numberOfBatchAttempts > 1 {
				// bypass the exec pool situation and queue anyway
				// this is to prevent long delays in the propagation of the sigs (txn/vote)
				// at least one job has waited 3 x waitForNextElmtDuration
				err = sv.addVerificationTaskToThePoolNow(uElmts)
				added = true
			} else {
				added, err = sv.tryAddVerificationTaskToThePool(uElmts)
			}
			if err != nil {
				return
			}
			if added {
				numberOfSigsInCurrent = 0
				uElmts = make([]UnverifiedSigJob, 0, 8)
				numberOfBatchAttempts = 0
			} else {
				// was not added because of the exec pool buffer length. wait for some more signatures
				numberOfBatchAttempts++
			}
		case <-sv.ctx.Done():
			return
		}
	}
}

func (sv *StreamVerifier) tryAddVerificationTaskToThePool(uElmts []UnverifiedSigJob) (added bool, err error) {
	// if the exec pool buffer is full, can go back and collect
	// more signatures instead of waiting in the exec pool buffer
	// more signatures to the batch do not harm performance but introduce latency when delayed (see crypto.BenchmarkBatchVerifierBig)

	// if the buffer is full
	if l, c := sv.verificationPool.BufferSize(); l == c {
		return false, nil
	}
	err = sv.addVerificationTaskToThePoolNow(uElmts)
	if err != nil {
		// An error is returned when the context of the pool expires
		return false, err
	}
	return true, nil
}

func (sv *StreamVerifier) addVerificationTaskToThePoolNow(unvrifiedElts []UnverifiedSigJob) error {
	// if the context is canceled when the task is in the queue, it should be canceled
	// copy the ctx here so that when the StreamVerifier is started again, and a new context
	// is created, this task still gets canceled due to the ctx at the time of this task
	taskCtx := sv.ctx
	function := func(arg interface{}) interface{} {
		uElmts := arg.([]UnverifiedSigJob)
		if taskCtx.Err() != nil {
			// ctx is canceled. the results will be returned
			sv.verifyProcessor.Cleanup(uElmts, ErrShuttingDownError)
			return nil
		}

		sv.ep.ProcessElements(uElmts)
		return nil
	}

	// EnqueueBacklog returns an error when the context is canceled
	err := sv.verificationPool.EnqueueBacklog(sv.ctx, function, unvrifiedElts, nil)
	if err != nil {
		logging.Base().Infof("addVerificationTaskToThePoolNow: EnqueueBacklog returned an error and StreamVerifier will stop: %v", err)
	}
	return err
}
