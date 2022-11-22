// Copyright (C) 2019-2022 Algorand, Inc.
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
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/metrics"
)

var logicGoodTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_ok", Description: "Total transaction scripts executed and accepted"})
var logicRejTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_rej", Description: "Total transaction scripts executed and rejected"})
var logicErrTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_err", Description: "Total transaction scripts executed and errored"})

// ErrInvalidSignature is the error returned to report that at least one signature is invalid
var ErrInvalidSignature = errors.New("At least one signature didn't pass verification")

var errSignedTxnHasNoSig = errors.New("signedtxn has no sig")
var errSignedTxnMaxOneSig = errors.New("signedtxn should only have one of Sig or Msig or LogicSig")
var errShuttingDownError = errors.New("not verified, verifier is shutting down")

// The PaysetGroups is taking large set of transaction groups and attempt to verify their validity using multiple go-routines.
// When doing so, it attempts to break these into smaller "worksets" where each workset takes about 2ms of execution time in order
// to avoid context switching overhead while providing good validation cancelation responsiveness. Each one of these worksets is
// "populated" with roughly txnPerWorksetThreshold transactions. ( note that the real evaluation time is unknown, but benchmarks
// show that these are realistic numbers )
const txnPerWorksetThreshold = 32

// batchSizeBlockLimit is the limit when the batch exceeds, will be added to the exec pool, even if the pool is saturated
// and the batch verifier will block until the exec pool accepts the batch
const batchSizeBlockLimit = 512

// waitForNextTxnDuration is the time to wait before sending the batch to the exec pool
// If the incoming txn rate is low, a txn in the batch may  wait no less than
// waitForNextTxnDuration before it is set for verification.
// This can introduce a latency to the propagation of a transaction in the network,
// since every relay will go through this wait time before broadcasting the txn.
// However, when the incoming txn rate is high, the batch will fill up quickly and will send
// for signature evaluation before waitForNextTxnDuration.
const waitForNextTxnDuration = 5 * time.Millisecond

// waitForFirstTxnDuration is the time to wait for the first transaction in the batch
var waitForFirstTxnDuration = 2000 * time.Millisecond

// When the PaysetGroups is generating worksets, it enqueues up to concurrentWorksets entries to the execution pool. This serves several
// purposes :
// - if the verification task need to be aborted, there are only concurrentWorksets entries that are currently redundant on the execution pool queue.
// - that number of concurrent tasks would not get beyond the capacity of the execution pool back buffer.
// - if we were to "redundantly" execute all these during context cancelation, we would spent at most 2ms * 16 = 32ms time.
// - it allows us to linearly scan the input, and process elements only once we're going to queue them into the pool.
const concurrentWorksets = 16

// GroupContext is the set of parameters external to a transaction which
// stateless checks are performed against.
//
// For efficient caching, these parameters should either be constant
// or change slowly over time.
//
// Group data are omitted because they are committed to in the
// transaction and its ID.
type GroupContext struct {
	specAddrs        transactions.SpecialAddresses
	consensusVersion protocol.ConsensusVersion
	consensusParams  config.ConsensusParams
	minAvmVersion    uint64
	signedGroupTxns  []transactions.SignedTxn
	ledger           logic.LedgerForSignature
}

var errTxGroupInvalidFee = errors.New("txgroup fee requirement overflow")
var errTxnSigHasNoSig = errors.New("signedtxn has no sig")
var errTxnSigNotWellFormed = errors.New("signedtxn should only have one of Sig or Msig or LogicSig")
var errRekeyingNotSupported = errors.New("nonempty AuthAddr but rekeying is not supported")
var errUnknownSignature = errors.New("has one mystery sig. WAT?")

// TxGroupErrorReason is reason code for ErrTxGroupError
type TxGroupErrorReason int

const (
	// TxGroupErrorReasonGeneric is a generic (not tracked) reason code
	TxGroupErrorReasonGeneric TxGroupErrorReason = iota
	// TxGroupErrorReasonNotWellFormed is txn.WellFormed failure
	TxGroupErrorReasonNotWellFormed
	// TxGroupErrorReasonInvalidFee is invalid fee pooling in transaction group
	TxGroupErrorReasonInvalidFee
	// TxGroupErrorReasonHasNoSig is for transaction without any signature
	TxGroupErrorReasonHasNoSig
	// TxGroupErrorReasonSigNotWellFormed defines signature format errors
	TxGroupErrorReasonSigNotWellFormed
	// TxGroupErrorReasonMsigNotWellFormed defines multisig format errors
	TxGroupErrorReasonMsigNotWellFormed
	// TxGroupErrorReasonLogicSigFailed defines logic sig validation errors
	TxGroupErrorReasonLogicSigFailed

	// TxGroupErrorReasonNumValues is number of enum values
	TxGroupErrorReasonNumValues
)

// ErrTxGroupError is an error from txn pre-validation (well form-ness, signature format, etc).
// It can be unwrapped into underlying error, as well as has a specific failure reason code.
type ErrTxGroupError struct {
	err    error
	Reason TxGroupErrorReason
}

// Error returns an error message from the underlying error
func (e *ErrTxGroupError) Error() string {
	return e.err.Error()
}

// Unwrap returns an underlying error
func (e *ErrTxGroupError) Unwrap() error {
	return e.err
}

// PrepareGroupContext prepares a verification group parameter object for a given transaction
// group.
func PrepareGroupContext(group []transactions.SignedTxn, contextHdr *bookkeeping.BlockHeader, ledger logic.LedgerForSignature) (*GroupContext, error) {
	if len(group) == 0 {
		return nil, nil
	}
	consensusParams, ok := config.Consensus[contextHdr.CurrentProtocol]
	if !ok {
		return nil, protocol.Error(contextHdr.CurrentProtocol)
	}
	return &GroupContext{
		specAddrs: transactions.SpecialAddresses{
			FeeSink:     contextHdr.FeeSink,
			RewardsPool: contextHdr.RewardsPool,
		},
		consensusVersion: contextHdr.CurrentProtocol,
		consensusParams:  consensusParams,
		minAvmVersion:    logic.ComputeMinAvmVersion(transactions.WrapSignedTxnsWithAD(group)),
		signedGroupTxns:  group,
		ledger:           ledger,
	}, nil
}

// Equal compares two group contexts to see if they would represent the same verification context for a given transaction.
func (g *GroupContext) Equal(other *GroupContext) bool {
	return g.specAddrs == other.specAddrs &&
		g.consensusVersion == other.consensusVersion &&
		g.minAvmVersion == other.minAvmVersion
}

// txnBatchPrep verifies a SignedTxn having no obviously inconsistent data.
// Block-assembly time checks of LogicSig and accounting rules may still block the txn.
// It is the caller responsibility to call batchVerifier.Verify().
func txnBatchPrep(s *transactions.SignedTxn, txnIdx int, groupCtx *GroupContext, verifier *crypto.BatchVerifier) *ErrTxGroupError {
	if !groupCtx.consensusParams.SupportRekeying && (s.AuthAddr != basics.Address{}) {
		return &ErrTxGroupError{err: errRekeyingNotSupported, Reason: TxGroupErrorReasonGeneric}
	}

	if err := s.Txn.WellFormed(groupCtx.specAddrs, groupCtx.consensusParams); err != nil {
		return &ErrTxGroupError{err: err, Reason: TxGroupErrorReasonNotWellFormed}
	}

	return stxnCoreChecks(s, txnIdx, groupCtx, verifier)
}

// TxnGroup verifies a []SignedTxn as being signed and having no obviously inconsistent data.
func TxnGroup(stxs []transactions.SignedTxn, contextHdr *bookkeeping.BlockHeader, cache VerifiedTransactionCache, ledger logic.LedgerForSignature) (groupCtx *GroupContext, err error) {
	batchVerifier := crypto.MakeBatchVerifier()

	if groupCtx, err = txnGroupBatchPrep(stxs, contextHdr, ledger, batchVerifier); err != nil {
		return nil, err
	}

	if err := batchVerifier.Verify(); err != nil {
		return nil, err
	}

	if cache != nil {
		cache.Add(stxs, groupCtx)
	}

	return
}

// txnGroupBatchPrep verifies a []SignedTxn having no obviously inconsistent data.
// it is the caller responsibility to call batchVerifier.Verify()
func txnGroupBatchPrep(stxs []transactions.SignedTxn, contextHdr *bookkeeping.BlockHeader, ledger logic.LedgerForSignature, verifier *crypto.BatchVerifier) (*GroupContext, error) {
	groupCtx, err := PrepareGroupContext(stxs, contextHdr, ledger)
	if err != nil {
		return nil, err
	}

	minFeeCount := uint64(0)
	feesPaid := uint64(0)
	for i, stxn := range stxs {
		prepErr := txnBatchPrep(&stxn, i, groupCtx, verifier)
		if prepErr != nil {
			// re-wrap the error with more details
			prepErr.err = fmt.Errorf("transaction %+v invalid : %w", stxn, prepErr.err)
			return nil, prepErr
		}
		if stxn.Txn.Type != protocol.StateProofTx {
			minFeeCount++
		}
		feesPaid = basics.AddSaturate(feesPaid, stxn.Txn.Fee.Raw)
	}
	feeNeeded, overflow := basics.OMul(groupCtx.consensusParams.MinTxnFee, minFeeCount)
	if overflow {
		err = &ErrTxGroupError{err: errTxGroupInvalidFee, Reason: TxGroupErrorReasonInvalidFee}
		return nil, err
	}
	// feesPaid may have saturated. That's ok. Since we know
	// feeNeeded did not overflow, simple comparison tells us
	// feesPaid was enough.
	if feesPaid < feeNeeded {
		err = &ErrTxGroupError{
			err: fmt.Errorf(
				"txgroup had %d in fees, which is less than the minimum %d * %d",
				feesPaid, minFeeCount, groupCtx.consensusParams.MinTxnFee),
			Reason: TxGroupErrorReasonInvalidFee,
		}
		return nil, err
	}

	return groupCtx, nil
}

// stxnCoreChecks runs signatures validity checks and enqueues signature into batchVerifier for verification.
func stxnCoreChecks(s *transactions.SignedTxn, txnIdx int, groupCtx *GroupContext, batchVerifier *crypto.BatchVerifier) *ErrTxGroupError {
	numSigs := 0
	hasSig := false
	hasMsig := false
	hasLogicSig := false
	if s.Sig != (crypto.Signature{}) {
		numSigs++
		hasSig = true
	}
	if !s.Msig.Blank() {
		numSigs++
		hasMsig = true
	}
	if !s.Lsig.Blank() {
		numSigs++
		hasLogicSig = true
	}
	if numSigs == 0 {
		// Special case: special sender address can issue special transaction
		// types (state proof txn) without any signature.  The well-formed
		// check ensures that this transaction cannot pay any fee, and
		// cannot have any other interesting fields, except for the state proof payload.
		if s.Txn.Sender == transactions.StateProofSender && s.Txn.Type == protocol.StateProofTx {
			return nil
		}
		return &ErrTxGroupError{err: errTxnSigHasNoSig, Reason: TxGroupErrorReasonHasNoSig}
	}
	if numSigs > 1 {
		return &ErrTxGroupError{err: errTxnSigNotWellFormed, Reason: TxGroupErrorReasonSigNotWellFormed}
	}

	if hasSig {
		batchVerifier.EnqueueSignature(crypto.SignatureVerifier(s.Authorizer()), s.Txn, s.Sig)
		return nil
	}
	if hasMsig {
		if err := crypto.MultisigBatchPrep(s.Txn, crypto.Digest(s.Authorizer()), s.Msig, batchVerifier); err != nil {
			return &ErrTxGroupError{err: fmt.Errorf("multisig validation failed: %w", err), Reason: TxGroupErrorReasonMsigNotWellFormed}
		}
		return nil
	}
	if hasLogicSig {
		if err := logicSigVerify(s, txnIdx, groupCtx); err != nil {
			return &ErrTxGroupError{err: err, Reason: TxGroupErrorReasonLogicSigFailed}
		}
		return nil
	}
	return &ErrTxGroupError{err: errUnknownSignature, Reason: TxGroupErrorReasonGeneric}
}

// LogicSigSanityCheck checks that the signature is valid and that the program is basically well formed.
// It does not evaluate the logic.
func LogicSigSanityCheck(txn *transactions.SignedTxn, groupIndex int, groupCtx *GroupContext) error {
	batchVerifier := crypto.MakeBatchVerifier()

	if err := logicSigSanityCheckBatchPrep(txn, groupIndex, groupCtx, batchVerifier); err != nil {
		return err
	}
	return batchVerifier.Verify()
}

// logicSigSanityCheckBatchPrep checks that the signature is valid and that the program is basically well formed.
// It does not evaluate the logic.
// it is the caller responsibility to call batchVerifier.Verify()
func logicSigSanityCheckBatchPrep(txn *transactions.SignedTxn, groupIndex int, groupCtx *GroupContext, batchVerifier *crypto.BatchVerifier) error {
	lsig := txn.Lsig

	if groupCtx.consensusParams.LogicSigVersion == 0 {
		return errors.New("LogicSig not enabled")
	}
	if len(lsig.Logic) == 0 {
		return errors.New("LogicSig.Logic empty")
	}
	version, vlen := binary.Uvarint(lsig.Logic)
	if vlen <= 0 {
		return errors.New("LogicSig.Logic bad version")
	}
	if version > groupCtx.consensusParams.LogicSigVersion {
		return errors.New("LogicSig.Logic version too new")
	}
	if uint64(lsig.Len()) > groupCtx.consensusParams.LogicSigMaxSize {
		return errors.New("LogicSig.Logic too long")
	}

	if groupIndex < 0 {
		return errors.New("negative groupIndex")
	}
	txngroup := transactions.WrapSignedTxnsWithAD(groupCtx.signedGroupTxns)
	ep := logic.EvalParams{
		Proto:         &groupCtx.consensusParams,
		TxnGroup:      txngroup,
		MinAvmVersion: &groupCtx.minAvmVersion,
		SigLedger:     groupCtx.ledger, // won't be needed for CheckSignature
	}
	err := logic.CheckSignature(groupIndex, &ep)
	if err != nil {
		return err
	}

	hasMsig := false
	numSigs := 0
	if lsig.Sig != (crypto.Signature{}) {
		numSigs++
	}
	if !lsig.Msig.Blank() {
		hasMsig = true
		numSigs++
	}
	if numSigs == 0 {
		// if the txn.Authorizer() == hash(Logic) then this is a (potentially) valid operation on a contract-only account
		program := logic.Program(lsig.Logic)
		lhash := crypto.HashObj(&program)
		if crypto.Digest(txn.Authorizer()) == lhash {
			return nil
		}
		return errors.New("LogicNot signed and not a Logic-only account")
	}
	if numSigs > 1 {
		return errors.New("LogicSig should only have one of Sig or Msig but has more than one")
	}

	if !hasMsig {
		program := logic.Program(lsig.Logic)
		batchVerifier.EnqueueSignature(crypto.PublicKey(txn.Authorizer()), &program, lsig.Sig)
	} else {
		program := logic.Program(lsig.Logic)
		if err := crypto.MultisigBatchPrep(&program, crypto.Digest(txn.Authorizer()), lsig.Msig, batchVerifier); err != nil {
			return fmt.Errorf("logic multisig validation failed: %w", err)
		}
	}
	return nil
}

// logicSigVerify checks that the signature is valid, executing the program.
func logicSigVerify(txn *transactions.SignedTxn, groupIndex int, groupCtx *GroupContext) error {
	err := LogicSigSanityCheck(txn, groupIndex, groupCtx)
	if err != nil {
		return err
	}

	if groupIndex < 0 {
		return errors.New("negative groupIndex")
	}
	ep := logic.EvalParams{
		Proto:         &groupCtx.consensusParams,
		TxnGroup:      transactions.WrapSignedTxnsWithAD(groupCtx.signedGroupTxns),
		MinAvmVersion: &groupCtx.minAvmVersion,
		SigLedger:     groupCtx.ledger,
	}
	pass, err := logic.EvalSignature(groupIndex, &ep)
	if err != nil {
		logicErrTotal.Inc(nil)
		return fmt.Errorf("transaction %v: rejected by logic err=%v", txn.ID(), err)
	}
	if !pass {
		logicRejTotal.Inc(nil)
		return fmt.Errorf("transaction %v: rejected by logic", txn.ID())
	}
	logicGoodTotal.Inc(nil)
	return nil

}

// PaysetGroups verifies that the payset have a good signature and that the underlying
// transactions are properly constructed.
// Note that this does not check whether a payset is valid against the ledger:
// a PaysetGroups may be well-formed, but a payset might contain an overspend.
//
// This version of verify is performing the verification over the provided execution pool.
func PaysetGroups(ctx context.Context, payset [][]transactions.SignedTxn, blkHeader bookkeeping.BlockHeader, verificationPool execpool.BacklogPool, cache VerifiedTransactionCache, ledger logic.LedgerForSignature) (err error) {
	if len(payset) == 0 {
		return nil
	}

	// prepare up to 16 concurrent worksets.
	worksets := make(chan struct{}, concurrentWorksets)
	worksDoneCh := make(chan interface{}, concurrentWorksets)
	processing := 0

	tasksCtx, cancelTasksCtx := context.WithCancel(ctx)
	defer cancelTasksCtx()
	builder := worksetBuilder{payset: payset}
	var nextWorkset [][]transactions.SignedTxn
	for processing >= 0 {
		// see if we need to get another workset
		if len(nextWorkset) == 0 && !builder.completed() {
			nextWorkset = builder.next()
		}

		select {
		case <-tasksCtx.Done():
			return tasksCtx.Err()
		case worksets <- struct{}{}:
			if len(nextWorkset) > 0 {
				err := verificationPool.EnqueueBacklog(ctx, func(arg interface{}) interface{} {
					var grpErr error
					// check if we've canceled the request while this was in the queue.
					if tasksCtx.Err() != nil {
						return tasksCtx.Err()
					}

					txnGroups := arg.([][]transactions.SignedTxn)
					groupCtxs := make([]*GroupContext, len(txnGroups))

					batchVerifier := crypto.MakeBatchVerifierWithHint(len(payset))
					for i, signTxnsGrp := range txnGroups {
						groupCtxs[i], grpErr = txnGroupBatchPrep(signTxnsGrp, &blkHeader, ledger, batchVerifier)
						// abort only if it's a non-cache error.
						if grpErr != nil {
							return grpErr
						}
					}
					verifyErr := batchVerifier.Verify()
					if verifyErr != nil {
						return verifyErr
					}
					cache.AddPayset(txnGroups, groupCtxs)
					return nil
				}, nextWorkset, worksDoneCh)
				if err != nil {
					return err
				}
				processing++
				nextWorkset = nil
			}
		case processingResult := <-worksDoneCh:
			processing--
			<-worksets
			// if there is nothing in the queue, the nextWorkset doesn't contain any work and the builder has no more entries, then we're done.
			if processing == 0 && builder.completed() && len(nextWorkset) == 0 {
				// we're done.
				processing = -1
			}
			if processingResult != nil {
				err = processingResult.(error)
				if err != nil {
					return err
				}
			}
		}

	}
	return err
}

// worksetBuilder is a helper struct used to construct well sized worksets for the execution pool to process
type worksetBuilder struct {
	payset [][]transactions.SignedTxn
	idx    int
}

func (w *worksetBuilder) next() (txnGroups [][]transactions.SignedTxn) {
	txnCounter := 0 // how many transaction we already included in the current workset.
	// scan starting from the current position until we filled up the workset.
	for i := w.idx; i < len(w.payset); i++ {
		if txnCounter+len(w.payset[i]) > txnPerWorksetThreshold {
			if i == w.idx {
				i++
			}
			txnGroups = w.payset[w.idx:i]
			w.idx = i
			return
		}
		if i == len(w.payset)-1 {
			txnGroups = w.payset[w.idx:]
			w.idx = len(w.payset)
			return
		}
		txnCounter += len(w.payset[i])
	}
	// we can reach here only if w.idx >= len(w.payset). This is not really a usecase, but just
	// for code-completeness, we'll return an empty array here.
	return nil
}

// test to see if we have any more worksets we can extract from our payset.
func (w *worksetBuilder) completed() bool {
	return w.idx >= len(w.payset)
}

// UnverifiedElement is the element passed to the Stream verifier
// BacklogMessage is a reference to the backlog message, which needs to be passed
// with the result
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
	resultChan       chan<- VerificationResult
	stxnChan         <-chan UnverifiedElement
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
	blkHeader bookkeeping.BlockHeader
	mu        deadlock.RWMutex
}

// MakeNewBlockWatcher construct a new block watcher with the initial blkHdr
func MakeNewBlockWatcher(blkHdr bookkeeping.BlockHeader) (nbw *NewBlockWatcher) {
	nbw = &NewBlockWatcher{
		blkHeader: blkHdr,
	}
	return nbw
}

// OnNewBlock implements the interface to subscribe to new block notifications from the ledger
func (nbw *NewBlockWatcher) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	if nbw.blkHeader.Round >= block.BlockHeader.Round {
		return
	}
	nbw.mu.Lock()
	defer nbw.mu.Unlock()
	nbw.blkHeader = block.BlockHeader
}

func (nbw *NewBlockWatcher) getBlockHeader() (bh *bookkeeping.BlockHeader) {
	nbw.mu.RLock()
	defer nbw.mu.RUnlock()
	return &nbw.blkHeader
}

type batchLoad struct {
	txnGroups             [][]transactions.SignedTxn
	groupCtxs             []*GroupContext
	elementBacklogMessage []interface{}
	messagesForTxn        []int
}

func makeBatchLoad() (bl batchLoad) {
	bl.txnGroups = make([][]transactions.SignedTxn, 0)
	bl.groupCtxs = make([]*GroupContext, 0)
	bl.elementBacklogMessage = make([]interface{}, 0)
	bl.messagesForTxn = make([]int, 0)
	return bl
}

func (bl *batchLoad) addLoad(txngrp []transactions.SignedTxn, gctx *GroupContext, backlogMsg interface{}, numBatchableSigs int) {
	bl.txnGroups = append(bl.txnGroups, txngrp)
	bl.groupCtxs = append(bl.groupCtxs, gctx)
	bl.elementBacklogMessage = append(bl.elementBacklogMessage, backlogMsg)
	bl.messagesForTxn = append(bl.messagesForTxn, numBatchableSigs)

}

// MakeStreamVerifier creates a new stream verifier and returns the chans used to send txn groups
// to it and obtain the txn signature verification result from
func MakeStreamVerifier(stxnChan <-chan UnverifiedElement, resultChan chan<- VerificationResult,
	ledger logic.LedgerForSignature, nbw *NewBlockWatcher, verificationPool execpool.BacklogPool,
	cache VerifiedTransactionCache) (sv *StreamVerifier) {

	sv = &StreamVerifier{
		resultChan:       resultChan,
		stxnChan:         stxnChan,
		verificationPool: verificationPool,
		cache:            cache,
		nbw:              nbw,
		ledger:           ledger,
	}
	return sv
}

// Start is called when the verifier is created and whenever it needs to restart after
// the ctx is canceled
func (sv *StreamVerifier) Start(ctx context.Context) {
	sv.ctx = ctx
	sv.activeLoopWg.Add(1)
	go sv.batchingLoop()
}

func (sv *StreamVerifier) cleanup(pending *[]UnverifiedElement) {
	// report an error for the unchecked txns
	// drop the messages without reporting if the receiver does not consume
	for _, uel := range *pending {
		vr := VerificationResult{
			TxnGroup:       uel.TxnGroup,
			BacklogMessage: uel.BacklogMessage,
			Err:            errShuttingDownError,
		}
		sv.resultChan <- vr
	}
}

func (sv *StreamVerifier) batchingLoop() {
	defer sv.activeLoopWg.Done()
	timer := time.NewTicker(waitForFirstTxnDuration)
	var added bool
	var numberOfSigsInCurrent uint64
	var numberOfTimerResets uint64
	uelts := make([]UnverifiedElement, 0)
	defer sv.cleanup(&uelts)
	for {
		select {
		case stx := <-sv.stxnChan:
			isFirstInBatch := numberOfSigsInCurrent == 0
			numberOfBatchableSigsInGroup, err := getNumberOfBatchableSigsInGroup(stx.TxnGroup)
			if err != nil {
				// wrong number of signatures
				sv.sendResult(stx.TxnGroup, stx.BacklogMessage, err)
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
					added, err = sv.canAddVerificationTaskToThePool(uelts)
					if err != nil {
						return
					}
				}
				if added {
					numberOfSigsInCurrent = 0
					uelts = make([]UnverifiedElement, 0)
					// starting a new batch. Can wait long, since nothing is blocked
					timer.Reset(waitForFirstTxnDuration)
					numberOfTimerResets = 0
				} else {
					// was not added because of the exec pool buffer length
					timer.Reset(waitForNextTxnDuration)
					numberOfTimerResets++
				}
			} else {
				if isFirstInBatch {
					// an element is added and is waiting. shorten the waiting time
					timer.Reset(waitForNextTxnDuration)
					numberOfTimerResets = 0
				}
			}
		case <-timer.C:
			// timer ticked. it is time to send the batch even if it is not full
			if numberOfSigsInCurrent == 0 {
				// nothing batched yet... wait some more
				timer.Reset(waitForFirstTxnDuration)
				numberOfTimerResets = 0
				continue
			}
			var err error
			if numberOfTimerResets > 1 {
				// bypass the exec pool situation and queue anyway
				// this is to prevent long delays in transaction propagation
				// at least one transaction here has waited 3 x waitForNextTxnDuration
				err = sv.addVerificationTaskToThePoolNow(uelts)
				added = true
			} else {
				added, err = sv.canAddVerificationTaskToThePool(uelts)
			}
			if err != nil {
				return
			}
			if added {
				numberOfSigsInCurrent = 0
				uelts = make([]UnverifiedElement, 0)
				// starting a new batch. Can wait long, since nothing is blocked
				timer.Reset(waitForFirstTxnDuration)
				numberOfTimerResets = 0
			} else {
				// was not added because of the exec pool buffer length. wait for some more txns
				timer.Reset(waitForNextTxnDuration)
				numberOfTimerResets++
			}
		case <-sv.ctx.Done():
			return
		}
	}
}

func (sv *StreamVerifier) sendResult(veTxnGroup []transactions.SignedTxn, veBacklogMessage interface{}, err error) {
	vr := VerificationResult{
		TxnGroup:       veTxnGroup,
		BacklogMessage: veBacklogMessage,
		Err:            err,
	}
	// send the txn result out the pipe
	// this is expected not to block. the receiver end of this channel will drop transactions if the
	// postVerificationQueue is blocked, and report it
	sv.resultChan <- vr
}

func (sv *StreamVerifier) canAddVerificationTaskToThePool(uelts []UnverifiedElement) (added bool, err error) {
	// if the exec pool buffer is (half) full, can go back and collect
	// more signatures instead of waiting in the exec pool buffer
	// more signatures to the batch do not harm performance but introduce latency when delayed (see crypto.BenchmarkBatchVerifierBig)

	// if buffer is half full
	if l, c := sv.verificationPool.BufferLength(); l == c {
		return false, nil
	}
	err = sv.addVerificationTaskToThePoolNow(uelts)
	if err != nil {
		// An error is returned when the context of the pool expires
		return false, err
	}
	return true, nil
}

func (sv *StreamVerifier) addVerificationTaskToThePoolNow(uelts []UnverifiedElement) error {
	function := func(arg interface{}) interface{} {
		if sv.ctx.Err() != nil {
			return nil
		}

		uelts := arg.([]UnverifiedElement)
		batchVerifier := crypto.MakeBatchVerifier()

		bl := makeBatchLoad()
		// TODO: separate operations here, and get the sig verification inside the LogicSig to the batch here
		blockHeader := sv.nbw.getBlockHeader()
		for _, ue := range uelts {
			groupCtx, err := txnGroupBatchPrep(ue.TxnGroup, blockHeader, sv.ledger, batchVerifier)
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
	err := sv.verificationPool.EnqueueBacklog(sv.ctx, function, uelts, nil)
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

func getNumberOfBatchableSigsInTxn(stx *transactions.SignedTxn) (batchSigs uint64, err error) {
	var hasSig, hasMsig bool
	numSigs := 0
	if stx.Sig != (crypto.Signature{}) {
		numSigs++
		hasSig = true
	}
	if !stx.Msig.Blank() {
		numSigs++
		hasMsig = true
	}
	if !stx.Lsig.Blank() {
		numSigs++
	}

	if numSigs == 0 {
		// Special case: special sender address can issue special transaction
		// types (state proof txn) without any signature.  The well-formed
		// check ensures that this transaction cannot pay any fee, and
		// cannot have any other interesting fields, except for the state proof payload.
		if stx.Txn.Sender == transactions.StateProofSender && stx.Txn.Type == protocol.StateProofTx {
			return 0, nil
		}
		return 0, errSignedTxnHasNoSig
	}
	if numSigs != 1 {
		return 0, errSignedTxnMaxOneSig
	}
	if hasSig {
		return 1, nil
	}
	if hasMsig {
		sig := stx.Msig
		for _, subsigi := range sig.Subsigs {
			if (subsigi.Sig != crypto.Signature{}) {
				batchSigs++
			}
		}
	}
	return
}
