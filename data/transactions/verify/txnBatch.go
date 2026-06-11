// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"fmt"
	"sync/atomic"

	"github.com/algorand/go-algorand/config/bounds"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/util/execpool"
)

// UnverifiedTxnSigJob is the sig verification job passed to the Stream verifier
// It represents an unverified txn whose signatures will be verified
// BacklogMessage is a *txBacklogMsg from data/txHandler.go which needs to be
// passed back to that context
// Implements UnverifiedSigJob
type UnverifiedTxnSigJob struct {
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

// stagedSig holds the arguments of one buffered EnqueueSignature call.
type stagedSig struct {
	sigVerifier crypto.SignatureVerifier
	message     crypto.Hashable
	sig         crypto.Signature
}

// batchLoad assembles a batch of signature-verification jobs: txnGroupBatchPrep stages each group's
// signatures via EnqueueSignature, and the caller commitGroup()s a fully-prepared group or drops it.
type batchLoad struct {
	verifier crypto.BatchVerifier // created and written only by batchLoad, so committed sigs stay in sync with messagesForTxn
	staged   []stagedSig          // current group's signatures, reused across groups (reset, not realloc)

	// one entry per committed group, indexed alike
	txnGroups      [][]transactions.SignedTxn
	groupCtxs      []*GroupContext
	backlogMessage []interface{}
	messagesForTxn []int // running total of committed sigs; group i owns slots [messagesForTxn[i-1], messagesForTxn[i])
}

func makeBatchLoad(l int) (bl *batchLoad) {
	return &batchLoad{
		verifier: crypto.MakeBatchVerifier(),
		// covers one sig per txn in a max-size group; multisig groups may grow it
		staged:         make([]stagedSig, 0, bounds.MaxTxGroupSize),
		txnGroups:      make([][]transactions.SignedTxn, 0, l),
		groupCtxs:      make([]*GroupContext, 0, l),
		backlogMessage: make([]interface{}, 0, l),
		messagesForTxn: make([]int, 0, l),
	}
}

// EnqueueSignature implements crypto.BatchEnqueuer by staging a signature for the current group
// rather than adding it to the shared verifier immediately.
func (bl *batchLoad) EnqueueSignature(sigVerifier crypto.SignatureVerifier, message crypto.Hashable, sig crypto.Signature) {
	bl.staged = append(bl.staged, stagedSig{sigVerifier, message, sig})
}

// resetGroup discards the current group's staged signatures (e.g. a group that failed checks)
func (bl *batchLoad) resetGroup() { bl.staged = bl.staged[:0] }

// commitGroup flushes the staged signatures into the shared verifier and records the group so its
// result can be recovered after verification. Called only if checking the group succeeded.
func (bl *batchLoad) commitGroup(txngrp []transactions.SignedTxn, gctx *GroupContext, backlogMsg interface{}) {
	for i := range bl.staged {
		bl.verifier.EnqueueSignature(bl.staged[i].sigVerifier, bl.staged[i].message, bl.staged[i].sig)
	}
	bl.staged = bl.staged[:0]
	bl.txnGroups = append(bl.txnGroups, txngrp)
	bl.groupCtxs = append(bl.groupCtxs, gctx)
	bl.backlogMessage = append(bl.backlogMessage, backlogMsg)
	bl.messagesForTxn = append(bl.messagesForTxn, bl.verifier.GetNumberOfEnqueuedSignatures())
}

// TxnGroupBatchSigVerifier provides Verify method to synchronously verify a group of transactions
// It starts a new block listener to receive latests block headers for the sig verification
type TxnGroupBatchSigVerifier struct {
	cache  VerifiedTransactionCache
	nbw    *NewBlockWatcher
	ledger logic.LedgerForSignature
}

type txnSigBatchProcessor struct {
	TxnGroupBatchSigVerifier
	resultChan  chan<- *VerificationResult
	droppedChan chan<- *UnverifiedTxnSigJob
}

// LedgerForStreamVerifier defines the ledger methods used by the StreamVerifier.
type LedgerForStreamVerifier interface {
	logic.LedgerForSignature
	RegisterBlockListeners([]ledgercore.BlockListener)
	Latest() basics.Round
	BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error)
}

func (tbp *txnSigBatchProcessor) Cleanup(pending []execpool.InputJob, err error) {
	// report an error for the unchecked txns
	// drop the messages without reporting if the receiver does not consume
	for i := range pending {
		uelt := pending[i].(*UnverifiedTxnSigJob)
		tbp.sendResult(uelt.TxnGroup, uelt.BacklogMessage, err)
	}
}

func (tbp txnSigBatchProcessor) GetErredUnprocessed(ue execpool.InputJob, err error) {
	uelt := ue.(*UnverifiedTxnSigJob)
	tbp.sendResult(uelt.TxnGroup, uelt.BacklogMessage, err)
}

func (tbp txnSigBatchProcessor) sendResult(veTxnGroup []transactions.SignedTxn, veBacklogMessage interface{}, err error) {
	// send the txn result out the pipe
	select {
	case tbp.resultChan <- &VerificationResult{
		TxnGroup:       veTxnGroup,
		BacklogMessage: veBacklogMessage,
		Err:            err,
	}:
	default:
		// we failed to write to the output queue, since the queue was full.
		tbp.droppedChan <- &UnverifiedTxnSigJob{veTxnGroup, veBacklogMessage}
	}
}

// MakeSigVerifier creats a new TxnGroupBatchSigVerifier for synchronous verification of transactions
func MakeSigVerifier(ledger LedgerForStreamVerifier, cache VerifiedTransactionCache) (TxnGroupBatchSigVerifier, error) {
	latest := ledger.Latest()
	latestHdr, err := ledger.BlockHdr(latest)
	if err != nil {
		return TxnGroupBatchSigVerifier{}, fmt.Errorf("MakeSigVerifier: Could not get header for previous block: %w", err)
	}

	nbw := MakeNewBlockWatcher(latestHdr)
	ledger.RegisterBlockListeners([]ledgercore.BlockListener{nbw})

	verifier := TxnGroupBatchSigVerifier{
		cache:  cache,
		nbw:    nbw,
		ledger: ledger,
	}

	return verifier, nil
}

// MakeSigVerifyJobProcessor returns the object implementing the stream verifier Helper interface
func MakeSigVerifyJobProcessor(
	ledger LedgerForStreamVerifier, cache VerifiedTransactionCache,
	resultChan chan<- *VerificationResult, droppedChan chan<- *UnverifiedTxnSigJob,
) (svp execpool.BatchProcessor, err error) {
	sigVerifier, err := MakeSigVerifier(ledger, cache)
	if err != nil {
		return nil, err
	}
	return &txnSigBatchProcessor{
		TxnGroupBatchSigVerifier: sigVerifier,
		droppedChan:              droppedChan,
		resultChan:               resultChan,
	}, nil
}

// Verify synchronously verifies the signatures of the transactions in the group
func (sv *TxnGroupBatchSigVerifier) Verify(stxs []transactions.SignedTxn) error {
	blockHeader := sv.nbw.getBlockHeader()
	_, err := txnGroup(stxs, blockHeader, sv.cache, sv.ledger, nil)
	return err
}

func (tbp *txnSigBatchProcessor) ProcessBatch(txns []execpool.InputJob) {
	bl := tbp.preProcessUnverifiedTxns(txns)
	failed, err := bl.verifier.VerifyWithFeedback()
	// this error can only be crypto.ErrBatchHasFailedSigs
	tbp.postProcessVerifiedJobs(bl, failed, err)
}

func (tbp *txnSigBatchProcessor) preProcessUnverifiedTxns(uTxns []execpool.InputJob) *batchLoad {
	bl := makeBatchLoad(len(uTxns))
	// TODO: separate operations here, and get the sig verification inside the LogicSig to the batch here
	blockHeader := tbp.nbw.getBlockHeader()

	for i := range uTxns {
		ut := uTxns[i].(*UnverifiedTxnSigJob)
		// txnGroupBatchPrep stages this group's signatures into bl as it walks the group.
		groupCtx, err := txnGroupBatchPrep(ut.TxnGroup, blockHeader, tbp.ledger, bl, nil)
		if err != nil {
			// the group failed checks partway; discard any sigs it already staged and report the error
			bl.resetGroup()
			tbp.sendResult(ut.TxnGroup, ut.BacklogMessage, err)
			continue
		}
		// commit the group's staged signatures and record it
		bl.commitGroup(ut.TxnGroup, groupCtx, ut.BacklogMessage)
	}
	return bl
}

// GetNumberOfBatchableItems returns the number of batchable signatures in the txn group
func (ue UnverifiedTxnSigJob) GetNumberOfBatchableItems() (batchSigs uint64, err error) {
	batchSigs = 0
	for i := range ue.TxnGroup {
		count, err := getNumberOfBatchableSigsInTxn(&ue.TxnGroup[i], i)
		if err != nil {
			return 0, err
		}
		batchSigs = batchSigs + count
	}
	return
}

func getNumberOfBatchableSigsInTxn(stx *transactions.SignedTxn, groupIndex int) (uint64, error) {
	sigType, err := checkTxnSigTypeCounts(stx, groupIndex)
	if err != nil {
		return 0, err
	}
	switch sigType {
	case regularSig:
		return 1, nil
	case multiSig:
		return uint64(stx.Msig.Signatures()), nil
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

func (tbp *txnSigBatchProcessor) postProcessVerifiedJobs(bl *batchLoad, failed []bool, err error) {
	if err == nil { // success, all signatures verified
		for i := range bl.txnGroups {
			tbp.sendResult(bl.txnGroups[i], bl.backlogMessage[i], nil)
		}
		tbp.cache.AddPayset(bl.groupCtxs)
		return
	}

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
			verifiedGroupCtxs = append(verifiedGroupCtxs, bl.groupCtxs[txgIdx])
		} else {
			result = err
		}
		tbp.sendResult(bl.txnGroups[txgIdx], bl.backlogMessage[txgIdx], result)
	}
	// loading them all at once by locking the cache once
	tbp.cache.AddPayset(verifiedGroupCtxs)
}
