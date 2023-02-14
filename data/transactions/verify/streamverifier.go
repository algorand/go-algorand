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
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/execpool"
)

// batchSizeBlockLimit is the limit when the batch exceeds, will be added to the exec pool, even if the pool is saturated
// and the batch verifier will block until the exec pool accepts the batch
const batchSizeBlockLimit = 1024

// waitForNextTxnDuration is the time to wait before sending the batch to the exec pool
// If the incoming txn rate is low, a txn in the batch may  wait no less than
// waitForNextTxnDuration before it is set for verification.
// This can introduce a latency to the propagation of a transaction in the network,
// since every relay will go through this wait time before broadcasting the txn.
// However, when the incoming txn rate is high, the batch will fill up quickly and will send
// for signature evaluation before waitForNextTxnDuration.
const waitForNextTxnDuration = 2 * time.Millisecond

// UnverifiedElement is the element passed to the Stream verifier
// BacklogMessage is a *txBacklogMsg from data/txHandler.go which needs to be
// passed back to that context
type UnverifiedElement struct {
	TxnGroup       []transactions.SignedTxn
	BacklogMessage interface{}
}

// VerificationResult is the result of the txn group verification
// BacklogMessage is the reference associated with the txn group which was
// initially passed to the stream verifier
type VerificationResult struct {
	TxnGroup       []transactions.SignedTxn
	BacklogMessage interface{}
	Err            error
}

// StreamVerifier verifies txn groups received through the stxnChan channel, and returns the
// results through the resultChan
type StreamVerifier struct {
	resultChan       chan<- *VerificationResult
	droppedChan      chan<- *UnverifiedElement
	stxnChan         <-chan *UnverifiedElement
	verificationPool execpool.BacklogPool
	ctx              context.Context
	cache            VerifiedTransactionCache
	activeLoopWg     sync.WaitGroup
	nbw              *NewBlockWatcher
	ledger           logic.LedgerForSignature
}

// NewBlockWatcher is a struct used to provide a new block header to the
// stream verifier
type NewBlockWatcher struct {
	blkHeader atomic.Value
}

// MakeNewBlockWatcher construct a new block watcher with the initial blkHdr
func MakeNewBlockWatcher(blkHdr bookkeeping.BlockHeader) (nbw *NewBlockWatcher) {
	nbw = &NewBlockWatcher{}
	nbw.blkHeader.Store(&blkHdr)
	return nbw
}

// OnNewBlock implements the interface to subscribe to new block notifications from the ledger
func (nbw *NewBlockWatcher) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	bh := nbw.blkHeader.Load().(*bookkeeping.BlockHeader)
	if bh.Round >= block.BlockHeader.Round {
		return
	}
	nbw.blkHeader.Store(&block.BlockHeader)
}

func (nbw *NewBlockWatcher) getBlockHeader() (bh *bookkeeping.BlockHeader) {
	return nbw.blkHeader.Load().(*bookkeeping.BlockHeader)
}

type batchLoad struct {
	txnGroups             [][]transactions.SignedTxn
	groupCtxs             []*GroupContext
	elementBacklogMessage []interface{}
	messagesForTxn        []int
}

func makeBatchLoad(l int) (bl batchLoad) {
	bl.txnGroups = make([][]transactions.SignedTxn, 0, l)
	bl.groupCtxs = make([]*GroupContext, 0, l)
	bl.elementBacklogMessage = make([]interface{}, 0, l)
	bl.messagesForTxn = make([]int, 0, l)
	return bl
}

func (bl *batchLoad) addLoad(txngrp []transactions.SignedTxn, gctx *GroupContext, backlogMsg interface{}, numBatchableSigs int) {
	bl.txnGroups = append(bl.txnGroups, txngrp)
	bl.groupCtxs = append(bl.groupCtxs, gctx)
	bl.elementBacklogMessage = append(bl.elementBacklogMessage, backlogMsg)
	bl.messagesForTxn = append(bl.messagesForTxn, numBatchableSigs)

}

// LedgerForStreamVerifier defines the ledger methods used by the StreamVerifier.
type LedgerForStreamVerifier interface {
	logic.LedgerForSignature
	RegisterBlockListeners([]ledgercore.BlockListener)
	Latest() basics.Round
	BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error)
}

// MakeStreamVerifier creates a new stream verifier and returns the chans used to send txn groups
// to it and obtain the txn signature verification result from
func MakeStreamVerifier(stxnChan <-chan *UnverifiedElement, resultChan chan<- *VerificationResult,
	droppedChan chan<- *UnverifiedElement, ledger LedgerForStreamVerifier,
	verificationPool execpool.BacklogPool, cache VerifiedTransactionCache) (*StreamVerifier, error) {

	latest := ledger.Latest()
	latestHdr, err := ledger.BlockHdr(latest)
	if err != nil {
		return nil, errors.New("MakeStreamVerifier: Could not get header for previous block")
	}

	nbw := MakeNewBlockWatcher(latestHdr)
	ledger.RegisterBlockListeners([]ledgercore.BlockListener{nbw})

	return &StreamVerifier{
		resultChan:       resultChan,
		stxnChan:         stxnChan,
		droppedChan:      droppedChan,
		verificationPool: verificationPool,
		cache:            cache,
		nbw:              nbw,
		ledger:           ledger,
	}, nil
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

func (sv *StreamVerifier) cleanup(pending []*UnverifiedElement) {
	// report an error for the unchecked txns
	// drop the messages without reporting if the receiver does not consume
	for _, uel := range pending {
		sv.sendResult(uel.TxnGroup, uel.BacklogMessage, errShuttingDownError)
	}
}

func (sv *StreamVerifier) batchingLoop() {
	defer sv.activeLoopWg.Done()
	timer := time.NewTicker(waitForNextTxnDuration)
	defer timer.Stop()
	var added bool
	var numberOfSigsInCurrent uint64
	var numberOfBatchAttempts uint64
	ue := make([]*UnverifiedElement, 0, 8)
	defer func() { sv.cleanup(ue) }()
	for {
		select {
		case stx := <-sv.stxnChan:
			numberOfBatchableSigsInGroup, err := getNumberOfBatchableSigsInGroup(stx.TxnGroup)
			if err != nil {
				// wrong number of signatures
				sv.sendResult(stx.TxnGroup, stx.BacklogMessage, err)
				continue
			}

			// if no batchable signatures here, send this as a task of its own
			if numberOfBatchableSigsInGroup == 0 {
				err := sv.addVerificationTaskToThePoolNow([]*UnverifiedElement{stx})
				if err != nil {
					return
				}
				continue // stx is handled, continue
			}

			// add this txngrp to the list of batchable txn groups
			numberOfSigsInCurrent = numberOfSigsInCurrent + numberOfBatchableSigsInGroup
			ue = append(ue, stx)
			if numberOfSigsInCurrent > txnPerWorksetThreshold {
				// enough transaction in the batch to efficiently verify

				if numberOfSigsInCurrent > batchSizeBlockLimit {
					// do not consider adding more txns to this batch.
					// bypass the exec pool situation and queue anyway
					// this is to prevent creation of very large batches
					err := sv.addVerificationTaskToThePoolNow(ue)
					if err != nil {
						return
					}
					added = true
				} else {
					added, err = sv.tryAddVerificationTaskToThePool(ue)
					if err != nil {
						return
					}
				}
				if added {
					numberOfSigsInCurrent = 0
					ue = make([]*UnverifiedElement, 0, 8)
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
				err = sv.addVerificationTaskToThePoolNow(ue)
				added = true
			} else {
				added, err = sv.tryAddVerificationTaskToThePool(ue)
			}
			if err != nil {
				return
			}
			if added {
				numberOfSigsInCurrent = 0
				ue = make([]*UnverifiedElement, 0, 8)
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

func (sv *StreamVerifier) sendResult(veTxnGroup []transactions.SignedTxn, veBacklogMessage interface{}, err error) {
	// send the txn result out the pipe
	select {
	case sv.resultChan <- &VerificationResult{
		TxnGroup:       veTxnGroup,
		BacklogMessage: veBacklogMessage,
		Err:            err,
	}:
	default:
		// we failed to write to the output queue, since the queue was full.
		sv.droppedChan <- &UnverifiedElement{veTxnGroup, veBacklogMessage}
	}
}

func (sv *StreamVerifier) tryAddVerificationTaskToThePool(ue []*UnverifiedElement) (added bool, err error) {
	// if the exec pool buffer is full, can go back and collect
	// more signatures instead of waiting in the exec pool buffer
	// more signatures to the batch do not harm performance but introduce latency when delayed (see crypto.BenchmarkBatchVerifierBig)

	// if the buffer is full
	if l, c := sv.verificationPool.BufferSize(); l == c {
		return false, nil
	}
	err = sv.addVerificationTaskToThePoolNow(ue)
	if err != nil {
		// An error is returned when the context of the pool expires
		return false, err
	}
	return true, nil
}

func (sv *StreamVerifier) addVerificationTaskToThePoolNow(ue []*UnverifiedElement) error {
	// if the context is canceled when the task is in the queue, it should be canceled
	// copy the ctx here so that when the StreamVerifier is started again, and a new context
	// is created, this task still gets canceled due to the ctx at the time of this task
	taskCtx := sv.ctx
	function := func(arg interface{}) interface{} {
		if taskCtx.Err() != nil {
			// ctx is canceled. the results will be returned
			sv.cleanup(ue)
			return nil
		}

		ue := arg.([]*UnverifiedElement)
		batchVerifier := crypto.MakeBatchVerifier()

		bl := makeBatchLoad(len(ue))
		// TODO: separate operations here, and get the sig verification inside the LogicSig to the batch here
		blockHeader := sv.nbw.getBlockHeader()
		for _, ue := range ue {
			groupCtx, err := txnGroupBatchPrep(ue.TxnGroup, blockHeader, sv.ledger, batchVerifier, nil)
			if err != nil {
				// verification failed, no need to add the sig to the batch, report the error
				sv.sendResult(ue.TxnGroup, ue.BacklogMessage, err)
				continue
			}
			totalBatchCount := batchVerifier.GetNumberOfEnqueuedSignatures()
			bl.addLoad(ue.TxnGroup, groupCtx, ue.BacklogMessage, totalBatchCount)
		}

		failed, err := batchVerifier.VerifyWithFeedback()
		// this error can only be crypto.ErrBatchHasFailedSigs
		if err == nil { // success, all signatures verified
			for i := range bl.txnGroups {
				sv.sendResult(bl.txnGroups[i], bl.elementBacklogMessage[i], nil)
			}
			sv.cache.AddPayset(bl.txnGroups, bl.groupCtxs)
			return nil
		}

		verifiedTxnGroups := make([][]transactions.SignedTxn, 0, len(bl.txnGroups))
		verifiedGroupCtxs := make([]*GroupContext, 0, len(bl.groupCtxs))
		failedSigIdx := 0
		for txgIdx := range bl.txnGroups {
			txGroupSigFailed := false
			for failedSigIdx < bl.messagesForTxn[txgIdx] {
				if failed[failedSigIdx] {
					// if there is a failed sig check, then no need to check the rest of the
					// sigs for this txnGroup
					failedSigIdx = bl.messagesForTxn[txgIdx]
					txGroupSigFailed = true
				} else {
					// proceed to check the next sig belonging to this txnGroup
					failedSigIdx++
				}
			}
			var result error
			if !txGroupSigFailed {
				verifiedTxnGroups = append(verifiedTxnGroups, bl.txnGroups[txgIdx])
				verifiedGroupCtxs = append(verifiedGroupCtxs, bl.groupCtxs[txgIdx])
			} else {
				result = err
			}
			sv.sendResult(bl.txnGroups[txgIdx], bl.elementBacklogMessage[txgIdx], result)
		}
		// loading them all at once by locking the cache once
		sv.cache.AddPayset(verifiedTxnGroups, verifiedGroupCtxs)
		return nil
	}

	// EnqueueBacklog returns an error when the context is canceled
	err := sv.verificationPool.EnqueueBacklog(sv.ctx, function, ue, nil)
	if err != nil {
		logging.Base().Infof("addVerificationTaskToThePoolNow: EnqueueBacklog returned an error and StreamVerifier will stop: %v", err)
	}
	return err
}

func getNumberOfBatchableSigsInGroup(stxs []transactions.SignedTxn) (batchSigs uint64, err error) {
	batchSigs = 0
	for i := range stxs {
		count, err := getNumberOfBatchableSigsInTxn(&stxs[i])
		if err != nil {
			return 0, err
		}
		batchSigs = batchSigs + count
	}
	return
}

func getNumberOfBatchableSigsInTxn(stx *transactions.SignedTxn) (uint64, error) {
	sigType, err := checkTxnSigTypeCounts(stx)
	if err != nil {
		return 0, err
	}
	switch sigType {
	case regularSig:
		return 1, nil
	case multiSig:
		sig := stx.Msig
		batchSigs := uint64(0)
		for _, subsigi := range sig.Subsigs {
			if (subsigi.Sig != crypto.Signature{}) {
				batchSigs++
			}
		}
		return batchSigs, nil
	case logicSig:
		// Currently the sigs in here are not batched. Something to consider later.
		return 0, nil
	case stateProofTxn:
		return 0, nil
	default:
		// this case is impossible
		return 0, nil
	}
}
