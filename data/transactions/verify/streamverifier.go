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

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/execpool"
)

// ErrShuttingDownError is the error returned when a sig is not verified because the service is shutting down
var ErrShuttingDownError = errors.New("not verified, verifier is shutting down")

// waitForNextElmtDuration is the time to wait before sending the batch to the exec pool
// If the incoming element rate is low, an element in the batch may wait no less than
// waitForNextElmtDuration before it is set for verification.
// This can introduce a latency to the propagation of the elements (e.g. txn, vote) in the network,
// since every relay will go through this wait time before broadcasting the result.
// However, when the incoming element rate is high, the batch will fill up quickly and will send
// for signature evaluation before waitForNextElmtDuration.
const waitForNextElmtDuration = 2 * time.Millisecond

// batchSizeBlockLimit is the limit when the batch exceeds, will be added to the exec pool, even if the pool is saturated
// and the batch verifier will block until the exec pool accepts the batch
const batchSizeBlockLimit = 1024

// UnverifiedElement is the interface the incoming sig verification elts need to implement
type UnverifiedElement interface {
	GetNumberOfBatchableSigsInGroup() (batchSigs uint64, err error)
}

// ElementProcessor is the interface of the functions needed to extract signatures from the elements, post-process the results,
// send the results and cleanup when shutting down.
type ElementProcessor interface {
	// PreProcessUnverifiedElements prepares a BatchVerifier from an array of unverified elements
	// ctx is anything associated with the array of elements, which will be passed to PostProcessVerifiedElements
	PreProcessUnverifiedElements(uelts []UnverifiedElement) (batchVerifier *crypto.BatchVerifier, ctx interface{})
	// PostProcessVerifiedElements implments the passing of the results to their destination (cts from PreProcessUnverifiedElements)
	PostProcessVerifiedElements(ctx interface{}, failed []bool, err error)
	// GetErredUnverified returns an unverified element because of the err
	GetErredUnverified(ue UnverifiedElement, err error)
	// Cleanup called on the unverified elements when the verification shuts down
	Cleanup(ue []UnverifiedElement, err error)
}

// StreamVerifier verifies signatures in elements received through the inputChan channel, and returns the
// results through the resultChan
type StreamVerifier struct {
	inputChan        <-chan UnverifiedElement
	verificationPool execpool.BacklogPool
	ctx              context.Context
	activeLoopWg     sync.WaitGroup
	ep               ElementProcessor
}

// MakeStreamVerifier creates a new stream verifier to verify signatures in elements received through inputChan
func MakeStreamVerifier(inputChan <-chan UnverifiedElement, verificationPool execpool.BacklogPool,
	ep ElementProcessor) *StreamVerifier {

	return &StreamVerifier{
		inputChan:        inputChan,
		verificationPool: verificationPool,
		ep:               ep,
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
	uElmts := make([]UnverifiedElement, 0, 8)
	defer func() { sv.ep.Cleanup(uElmts, ErrShuttingDownError) }()
	for {
		select {
		case elem := <-sv.inputChan:
			numberOfBatchableSigsInGroup, err := elem.GetNumberOfBatchableSigsInGroup()
			if err != nil {
				sv.ep.GetErredUnverified(elem, err)
				continue
			}

			// if no batchable signatures here, send this as a task of its own
			if numberOfBatchableSigsInGroup == 0 {
				err := sv.addVerificationTaskToThePoolNow([]UnverifiedElement{elem})
				if err != nil {
					return
				}
				continue // elem is handled, continue
			}

			// add this element to the list of batchable elements
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
					uElmts = make([]UnverifiedElement, 0, 8)
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
				// this is to prevent long delays in the propagation of the elements (txn/vote)
				// at least one element here has waited 3 x waitForNextElmtDuration
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
				uElmts = make([]UnverifiedElement, 0, 8)
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

func (sv *StreamVerifier) tryAddVerificationTaskToThePool(uElmts []UnverifiedElement) (added bool, err error) {
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

func (sv *StreamVerifier) addVerificationTaskToThePoolNow(unvrifiedElts []UnverifiedElement) error {
	// if the context is canceled when the task is in the queue, it should be canceled
	// copy the ctx here so that when the StreamVerifier is started again, and a new context
	// is created, this task still gets canceled due to the ctx at the time of this task
	taskCtx := sv.ctx
	function := func(arg interface{}) interface{} {
		uElmts := arg.([]UnverifiedElement)
		if taskCtx.Err() != nil {
			// ctx is canceled. the results will be returned
			sv.ep.Cleanup(uElmts, ErrShuttingDownError)
			return nil
		}

		batchVerifier, ctx := sv.ep.PreProcessUnverifiedElements(uElmts)

		failed, err := batchVerifier.VerifyWithFeedback()
		// this error can only be crypto.ErrBatchHasFailedSigs

		sv.ep.PostProcessVerifiedElements(ctx, failed, err)
		return nil
	}

	// EnqueueBacklog returns an error when the context is canceled
	err := sv.verificationPool.EnqueueBacklog(sv.ctx, function, unvrifiedElts, nil)
	if err != nil {
		logging.Base().Infof("addVerificationTaskToThePoolNow: EnqueueBacklog returned an error and StreamVerifier will stop: %v", err)
	}
	return err
}
