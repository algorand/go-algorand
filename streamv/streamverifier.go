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

package streamv

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/execpool"
)

var errShuttingDownError = errors.New("not verified, verifier is shutting down")

// waitForNextTxnDuration is the time to wait before sending the batch to the exec pool
// If the incoming txn rate is low, a txn in the batch may  wait no less than
// waitForNextTxnDuration before it is set for verification.
// This can introduce a latency to the propagation of a transaction in the network,
// since every relay will go through this wait time before broadcasting the txn.
// However, when the incoming txn rate is high, the batch will fill up quickly and will send
// for signature evaluation before waitForNextTxnDuration.
const waitForNextTxnDuration = 2 * time.Millisecond

// The PaysetGroups is taking large set of transaction groups and attempt to verify their validity using multiple go-routines.
// When doing so, it attempts to break these into smaller "worksets" where each workset takes about 2ms of execution time in order
// to avoid context switching overhead while providing good validation cancellation responsiveness. Each one of these worksets is
// "populated" with roughly txnPerWorksetThreshold transactions. ( note that the real evaluation time is unknown, but benchmarks
// show that these are realistic numbers )
const txnPerWorksetThreshold = 32

// batchSizeBlockLimit is the limit when the batch exceeds, will be added to the exec pool, even if the pool is saturated
// and the batch verifier will block until the exec pool accepts the batch
const batchSizeBlockLimit = 1024

type UnverifiedElement interface {
	GetNumberOfBatchableSigsInGroup() (batchSigs uint64, err error)
}

type Helper interface {
	PreProcessUnverifiedElements(uelts []UnverifiedElement) (batchVerifier *crypto.BatchVerifier, ctx interface{})
	PostProcessVerifiedElements(ctx interface{}, failed []bool, err error)
	SendResult(ue UnverifiedElement, err error)
	cleanup(ue []UnverifiedElement, err error)
}

// StreamVerifier verifies txn groups received through the stxnChan channel, and returns the
// results through the resultChan
type StreamVerifier struct {
	stxnChan         <-chan UnverifiedElement
	verificationPool execpool.BacklogPool
	ctx              context.Context
	activeLoopWg     sync.WaitGroup
	helper           Helper
}

// MakeStreamVerifier creates a new stream verifier and returns the chans used to send txn groups
// to it and obtain the txn signature verification result from
func MakeStreamVerifier(stxnChan <-chan UnverifiedElement, verificationPool execpool.BacklogPool,
	helper Helper) *StreamVerifier {

	return &StreamVerifier{
		stxnChan:         stxnChan,
		verificationPool: verificationPool,
		helper:           helper,
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
	timer := time.NewTicker(waitForNextTxnDuration)
	defer timer.Stop()
	var added bool
	var numberOfSigsInCurrent uint64
	var numberOfBatchAttempts uint64
	uelts := make([]UnverifiedElement, 0, 8)
	defer func() { sv.helper.cleanup(uelts, errShuttingDownError) }()
	for {
		select {
		case stx := <-sv.stxnChan:
			numberOfBatchableSigsInGroup, err := stx.GetNumberOfBatchableSigsInGroup()
			if err != nil {
				// wrong number of signatures
				sv.helper.SendResult(stx, err)
				continue
			}

			// if no batchable signatures here, send this as a task of its own
			if numberOfBatchableSigsInGroup == 0 {
				err := sv.addVerificationTaskToThePoolNow([]UnverifiedElement{stx})
				if err != nil {
					return
				}
				continue // stx is handled, continue
			}

			// add this txngrp to the list of batchable txn groups
			numberOfSigsInCurrent = numberOfSigsInCurrent + numberOfBatchableSigsInGroup
			uelts = append(uelts, stx)
			if numberOfSigsInCurrent > txnPerWorksetThreshold {
				// enough transaction in the batch to efficiently verify

				if numberOfSigsInCurrent > batchSizeBlockLimit {
					// do not consider adding more txns to this batch.
					// bypass the exec pool situation and queue anyway
					// this is to prevent creation of very large batches
					err := sv.addVerificationTaskToThePoolNow(uelts)
					if err != nil {
						return
					}
					added = true
				} else {
					added, err = sv.tryAddVerificationTaskToThePool(uelts)
					if err != nil {
						return
					}
				}
				if added {
					numberOfSigsInCurrent = 0
					uelts = make([]UnverifiedElement, 0, 8)
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
				// this is to prevent long delays in transaction propagation
				// at least one transaction here has waited 3 x waitForNextTxnDuration
				err = sv.addVerificationTaskToThePoolNow(uelts)
				added = true
			} else {
				added, err = sv.tryAddVerificationTaskToThePool(uelts)
			}
			if err != nil {
				return
			}
			if added {
				numberOfSigsInCurrent = 0
				uelts = make([]UnverifiedElement, 0, 8)
				numberOfBatchAttempts = 0
			} else {
				// was not added because of the exec pool buffer length. wait for some more txns
				numberOfBatchAttempts++
			}
		case <-sv.ctx.Done():
			return
		}
	}
}

func (sv *StreamVerifier) tryAddVerificationTaskToThePool(uelts []UnverifiedElement) (added bool, err error) {
	// if the exec pool buffer is full, can go back and collect
	// more signatures instead of waiting in the exec pool buffer
	// more signatures to the batch do not harm performance but introduce latency when delayed (see crypto.BenchmarkBatchVerifierBig)

	// if the buffer is full
	if l, c := sv.verificationPool.BufferSize(); l == c {
		return false, nil
	}
	err = sv.addVerificationTaskToThePoolNow(uelts)
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
		uelts := arg.([]UnverifiedElement)
		if taskCtx.Err() != nil {
			// ctx is canceled. the results will be returned
			sv.helper.cleanup(uelts, errShuttingDownError)
			return nil
		}

		batchVerifier, ctx := sv.helper.PreProcessUnverifiedElements(uelts)

		failed, err := batchVerifier.VerifyWithFeedback()
		// this error can only be crypto.ErrBatchHasFailedSigs

		sv.helper.PostProcessVerifiedElements(ctx, failed, err)
		return nil
	}

	// EnqueueBacklog returns an error when the context is canceled
	err := sv.verificationPool.EnqueueBacklog(sv.ctx, function, unvrifiedElts, nil)
	if err != nil {
		logging.Base().Infof("addVerificationTaskToThePoolNow: EnqueueBacklog returned an error and StreamVerifier will stop: %v", err)
	}
	return err
}
