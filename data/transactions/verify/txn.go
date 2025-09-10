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

package verify

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/metrics"
)

var logicGoodTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_ok", Description: "Total transaction scripts executed and accepted"})
var logicRejTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_rej", Description: "Total transaction scripts executed and rejected"})
var logicErrTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_err", Description: "Total transaction scripts executed and errored"})
var logicCostTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_cost", Description: "Total cost of transaction scripts executed"})
var msigLessOrEqual4 = metrics.MakeCounter(metrics.MetricName{Name: "algod_verify_msig_4", Description: "Total transactions with 1-4 msigs"})
var msigLessOrEqual10 = metrics.MakeCounter(metrics.MetricName{Name: "algod_verify_msig_5_10", Description: "Total transactions with 5-10 msigs"})
var msigMore10 = metrics.MakeCounter(metrics.MetricName{Name: "algod_verify_msig_11", Description: "Total transactions with 11+ msigs"})
var msigLsigLessOrEqual4 = metrics.MakeCounter(metrics.MetricName{Name: "algod_verify_msig_lsig_4", Description: "Total transaction scripts with 1-4 msigs"})
var msigLsigLessOrEqual10 = metrics.MakeCounter(metrics.MetricName{Name: "algod_verify_msig_lsig_5_10", Description: "Total transaction scripts with 5-10 msigs"})
var msigLsigMore10 = metrics.MakeCounter(metrics.MetricName{Name: "algod_verify_msig_lsig_10", Description: "Total transaction scripts with 11+ msigs"})

// The PaysetGroups is taking large set of transaction groups and attempt to verify their validity using multiple go-routines.
// When doing so, it attempts to break these into smaller "worksets" where each workset takes about 2ms of execution time in order
// to avoid context switching overhead while providing good validation cancellation responsiveness. Each one of these worksets is
// "populated" with roughly txnPerWorksetThreshold transactions. ( note that the real evaluation time is unknown, but benchmarks
// show that these are realistic numbers )
const txnPerWorksetThreshold = 32

// When the PaysetGroups is generating worksets, it enqueues up to concurrentWorksets entries to the execution pool. This serves several
// purposes :
// - if the verification task need to be aborted, there are only concurrentWorksets entries that are currently redundant on the execution pool queue.
// - that number of concurrent tasks would not get beyond the capacity of the execution pool back buffer.
// - if we were to "redundantly" execute all these during context cancellation, we would spent at most 2ms * 16 = 32ms time.
// - it allows us to linearly scan the input, and process elements only once we're going to queue them into the pool.
const concurrentWorksets = 16

// GroupContext holds values used to evaluate the LogicSigs in a group.  The
// first set are the parameters external to a transaction which could
// potentially change the result of LogicSig evaluation. Example: If the
// consensusVersion changes, a rule might change that matters. Certainly this is
// _very_ rare, but we don't want to use the result of a LogicSig evaluation
// across a protocol upgrade boundary.
//
// The second set are derived from the first set and from the transaction
// data. They are stored here only for efficiency, not for correctness, so they
// are not checked in Equal()
type GroupContext struct {
	// These fields determine whether a logicsig must be re-evaluated.
	specAddrs        transactions.SpecialAddresses
	consensusVersion protocol.ConsensusVersion

	// These fields just hold useful data that ought not be recomputed (unless the above changes)
	consensusParams config.ConsensusParams
	signedGroupTxns []transactions.SignedTxn
	evalParams      *logic.EvalParams
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
	// TxGroupErrorReasonNotWellFormed is txn.WellFormed failure or malformed logic signature
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

// TxGroupError is an error from txn pre-validation (well form-ness, signature format, etc).
// It can be unwrapped into underlying error, as well as has a specific failure reason code.
type TxGroupError struct {
	err error
	// GroupIndex is the index of the transaction in the group that failed. NOTE: this will be -1 if
	// the error is not specific to a single transaction.
	GroupIndex int
	Reason     TxGroupErrorReason
}

// Error returns an error message from the underlying error
func (e *TxGroupError) Error() string {
	return e.err.Error()
}

// Unwrap returns an underlying error
func (e *TxGroupError) Unwrap() error {
	return e.err
}

// PrepareGroupContext prepares a GroupCtx for a given transaction group.
func PrepareGroupContext(group []transactions.SignedTxn, contextHdr *bookkeeping.BlockHeader, ledger logic.LedgerForSignature, evalTracer logic.EvalTracer) (*GroupContext, error) {
	if len(group) == 0 {
		return nil, nil
	}
	consensusParams, ok := config.Consensus[contextHdr.CurrentProtocol]
	if !ok {
		return nil, protocol.Error(contextHdr.CurrentProtocol)
	}

	ep := logic.NewSigEvalParams(group, &consensusParams, ledger)
	ep.Tracer = evalTracer
	return &GroupContext{
		specAddrs: transactions.SpecialAddresses{
			FeeSink:     contextHdr.FeeSink,
			RewardsPool: contextHdr.RewardsPool,
		},
		consensusVersion: contextHdr.CurrentProtocol,
		consensusParams:  consensusParams,
		signedGroupTxns:  group,
		evalParams:       ep,
	}, nil
}

// Equal compares two group contexts to see if they would represent the same verification context for a given transaction.
func (g *GroupContext) Equal(other *GroupContext) bool {
	return g.specAddrs == other.specAddrs &&
		g.consensusVersion == other.consensusVersion
}

// txnBatchPrep verifies a SignedTxn having no obviously inconsistent data.
// Block-assembly time checks of LogicSig and accounting rules may still block the txn.
// It is the caller responsibility to call batchVerifier.Verify().
func txnBatchPrep(gi int, groupCtx *GroupContext, verifier crypto.BatchVerifier) *TxGroupError {
	s := &groupCtx.signedGroupTxns[gi]
	if !groupCtx.consensusParams.SupportRekeying && (s.AuthAddr != basics.Address{}) {
		return &TxGroupError{err: errRekeyingNotSupported, GroupIndex: gi, Reason: TxGroupErrorReasonGeneric}
	}

	if err := s.Txn.WellFormed(groupCtx.specAddrs, groupCtx.consensusParams); err != nil {
		return &TxGroupError{err: err, GroupIndex: gi, Reason: TxGroupErrorReasonNotWellFormed}
	}

	return stxnCoreChecks(gi, groupCtx, verifier)
}

// TxnGroup verifies a []SignedTxn as being signed and having no obviously inconsistent data.
func TxnGroup(stxs []transactions.SignedTxn, contextHdr *bookkeeping.BlockHeader, cache VerifiedTransactionCache, ledger logic.LedgerForSignature) (groupCtx *GroupContext, err error) {
	return txnGroup(stxs, contextHdr, cache, ledger, nil)
}

// TxnGroupWithTracer verifies a []SignedTxn as being signed and having no obviously inconsistent data, while using a tracer.
func TxnGroupWithTracer(stxs []transactions.SignedTxn, contextHdr *bookkeeping.BlockHeader, cache VerifiedTransactionCache, ledger logic.LedgerForSignature, evalTracer logic.EvalTracer) (groupCtx *GroupContext, err error) {
	return txnGroup(stxs, contextHdr, cache, ledger, evalTracer)
}

func txnGroup(stxs []transactions.SignedTxn, contextHdr *bookkeeping.BlockHeader, cache VerifiedTransactionCache, ledger logic.LedgerForSignature, evalTracer logic.EvalTracer) (groupCtx *GroupContext, err error) {
	batchVerifier := crypto.MakeBatchVerifier()

	if groupCtx, err = txnGroupBatchPrep(stxs, contextHdr, ledger, batchVerifier, evalTracer); err != nil {
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
func txnGroupBatchPrep(stxs []transactions.SignedTxn, contextHdr *bookkeeping.BlockHeader, ledger logic.LedgerForSignature, verifier crypto.BatchVerifier, evalTracer logic.EvalTracer) (*GroupContext, error) {
	groupCtx, err := PrepareGroupContext(stxs, contextHdr, ledger, evalTracer)
	if err != nil {
		return nil, err
	}

	minFeeCount := uint64(0)
	feesPaid := uint64(0)
	lSigPooledSize := 0
	for i, stxn := range stxs {
		prepErr := txnBatchPrep(i, groupCtx, verifier)
		if prepErr != nil {
			// re-wrap the error with more details
			prepErr.err = fmt.Errorf("transaction %+v invalid : %w", stxn, prepErr.err)
			return nil, prepErr
		}
		feesPaid = basics.AddSaturate(feesPaid, stxn.Txn.Fee.Raw)
		lSigPooledSize += stxn.Lsig.Len()
		if stxn.Txn.Type == protocol.StateProofTx {
			// State proofs are free, bail before incrementing
			continue
		}
		if stxn.Txn.Type == protocol.HeartbeatTx && stxn.Txn.Group.IsZero() {
			// In apply.Heartbeat, we further confirm that the heartbeat is for
			// a challenged account. Such heartbeats are free, bail before
			// incrementing
			continue
		}
		minFeeCount++
	}
	if groupCtx.consensusParams.EnableLogicSigSizePooling {
		lSigMaxPooledSize := len(stxs) * int(groupCtx.consensusParams.LogicSigMaxSize)
		if lSigPooledSize > lSigMaxPooledSize {
			errorMsg := fmt.Errorf(
				"txgroup had %d bytes of LogicSigs, more than the available pool of %d bytes",
				lSigPooledSize, lSigMaxPooledSize,
			)
			return nil, &TxGroupError{err: errorMsg, GroupIndex: -1, Reason: TxGroupErrorReasonNotWellFormed}
		}
	}
	feeNeeded, overflow := basics.OMul(groupCtx.consensusParams.MinTxnFee, minFeeCount)
	if overflow {
		err = &TxGroupError{err: errTxGroupInvalidFee, GroupIndex: -1, Reason: TxGroupErrorReasonInvalidFee}
		return nil, err
	}
	// feesPaid may have saturated. That's ok. Since we know
	// feeNeeded did not overflow, simple comparison tells us
	// feesPaid was enough.
	if feesPaid < feeNeeded {
		err = &TxGroupError{
			err: fmt.Errorf(
				"txgroup had %d in fees, which is less than the minimum %d * %d",
				feesPaid, minFeeCount, groupCtx.consensusParams.MinTxnFee),
			GroupIndex: -1,
			Reason:     TxGroupErrorReasonInvalidFee,
		}
		return nil, err
	}

	return groupCtx, nil
}

type sigOrTxnType int

const regularSig sigOrTxnType = 1
const multiSig sigOrTxnType = 2
const logicSig sigOrTxnType = 3
const stateProofTxn sigOrTxnType = 4

// checkTxnSigTypeCounts checks the number of signature types and reports an error in case of a violation
func checkTxnSigTypeCounts(s *transactions.SignedTxn, groupIndex int) (sigType sigOrTxnType, err *TxGroupError) {
	numSigCategories := 0
	if !s.Sig.Blank() {
		numSigCategories++
		sigType = regularSig
	}
	if !s.Msig.Blank() {
		numSigCategories++
		sigType = multiSig
	}
	if !s.Lsig.Blank() {
		numSigCategories++
		sigType = logicSig
	}
	if numSigCategories == 0 {
		// Special case: special sender address can issue special transaction
		// types (state proof txn) without any signature.  The well-formed
		// check ensures that this transaction cannot pay any fee, and
		// cannot have any other interesting fields, except for the state proof payload.
		if s.Txn.Sender == transactions.StateProofSender && s.Txn.Type == protocol.StateProofTx {
			return stateProofTxn, nil
		}
		return 0, &TxGroupError{err: errTxnSigHasNoSig, GroupIndex: groupIndex, Reason: TxGroupErrorReasonHasNoSig}
	}
	if numSigCategories > 1 {
		return 0, &TxGroupError{err: errTxnSigNotWellFormed, GroupIndex: groupIndex, Reason: TxGroupErrorReasonSigNotWellFormed}
	}
	return sigType, nil
}

// stxnCoreChecks runs signatures validity checks and enqueues signature into batchVerifier for verification.
func stxnCoreChecks(gi int, groupCtx *GroupContext, batchVerifier crypto.BatchVerifier) *TxGroupError {
	s := &groupCtx.signedGroupTxns[gi]
	sigType, err := checkTxnSigTypeCounts(s, gi)
	if err != nil {
		return err
	}

	if s.Txn.Type == protocol.HeartbeatTx {
		id := basics.OneTimeIDForRound(s.Txn.LastValid, s.Txn.HbKeyDilution)
		s.Txn.HbProof.BatchPrep(s.Txn.HbVoteID, id, s.Txn.HbSeed, batchVerifier)
	}

	switch sigType {
	case regularSig:
		batchVerifier.EnqueueSignature(crypto.SignatureVerifier(s.Authorizer()), s.Txn, s.Sig)
		return nil
	case multiSig:
		if err := crypto.MultisigBatchPrep(s.Txn, crypto.Digest(s.Authorizer()), s.Msig, batchVerifier); err != nil {
			return &TxGroupError{err: fmt.Errorf("multisig validation failed: %w", err), GroupIndex: gi, Reason: TxGroupErrorReasonMsigNotWellFormed}
		}
		sigs := s.Msig.Signatures()
		if sigs <= 4 {
			msigLessOrEqual4.Inc(nil)
		} else if sigs <= 10 {
			msigLessOrEqual10.Inc(nil)
		} else {
			msigMore10.Inc(nil)
		}
		return nil

	case logicSig:
		if err := logicSigVerify(gi, groupCtx); err != nil {
			return &TxGroupError{err: err, GroupIndex: gi, Reason: TxGroupErrorReasonLogicSigFailed}
		}
		return nil

	case stateProofTxn:
		return nil

	default:
		return &TxGroupError{err: errUnknownSignature, GroupIndex: gi, Reason: TxGroupErrorReasonGeneric}
	}
}

// LogicSigSanityCheck checks that the signature is valid and that the program is basically well formed.
// It does not evaluate the logic.
func LogicSigSanityCheck(gi int, groupCtx *GroupContext) error {
	batchVerifier := crypto.MakeBatchVerifier()

	if err := logicSigSanityCheckBatchPrep(gi, groupCtx, batchVerifier); err != nil {
		return err
	}
	return batchVerifier.Verify()
}

// logicSigSanityCheckBatchPrep checks that the signature is valid and that the program is basically well formed.
// It does not evaluate the logic.
// it is the caller responsibility to call batchVerifier.Verify()
func logicSigSanityCheckBatchPrep(gi int, groupCtx *GroupContext, batchVerifier crypto.BatchVerifier) error {
	if groupCtx.consensusParams.LogicSigVersion == 0 {
		return errors.New("LogicSig not enabled")
	}

	if gi < 0 {
		return errors.New("negative group index")
	}
	txn := &groupCtx.signedGroupTxns[gi]
	lsig := txn.Lsig

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
	if !groupCtx.consensusParams.EnableLogicSigSizePooling && uint64(lsig.Len()) > groupCtx.consensusParams.LogicSigMaxSize {
		return errors.New("LogicSig too long")
	}

	err := logic.CheckSignature(gi, groupCtx.evalParams)
	if err != nil {
		return err
	}

	hasMsig := false
	hasLMsig := false
	numSigs := 0
	if !lsig.Sig.Blank() {
		numSigs++
	}
	if !lsig.Msig.Blank() {
		hasMsig = true
		numSigs++
	}
	if !lsig.LMsig.Blank() {
		hasLMsig = true
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
		return errors.New("LogicSig should only have one of Sig, Msig, or LMsig but has more than one")
	}

	if !hasMsig && !hasLMsig {
		program := logic.Program(lsig.Logic)
		batchVerifier.EnqueueSignature(crypto.PublicKey(txn.Authorizer()), &program, lsig.Sig)
	} else {
		var program crypto.Hashable
		var msig crypto.MultisigSig
		if hasLMsig {
			if !groupCtx.consensusParams.LogicSigLMsig {
				return errors.New("LogicSig LMsig field not supported in this consensus version")
			}
			program = logic.MultisigProgram{Addr: crypto.Digest(txn.Authorizer()), Program: lsig.Logic}
			msig = crypto.MultisigSig(lsig.LMsig)
		} else {
			if !groupCtx.consensusParams.LogicSigMsig {
				return errors.New("LogicSig Msig field not supported in this consensus version")
			}
			program = logic.Program(lsig.Logic)
			msig = lsig.Msig
		}
		if err := crypto.MultisigBatchPrep(program, crypto.Digest(txn.Authorizer()), msig, batchVerifier); err != nil {
			return fmt.Errorf("logic multisig validation failed: %w", err)
		}

		sigs := msig.Signatures()
		if sigs <= 4 {
			msigLsigLessOrEqual4.Inc(nil)
		} else if sigs <= 10 {
			msigLsigLessOrEqual10.Inc(nil)
		} else {
			msigLsigMore10.Inc(nil)
		}
	}
	return nil
}

// logicSigVerify checks that the signature is valid, executing the program.
func logicSigVerify(gi int, groupCtx *GroupContext) error {
	err := LogicSigSanityCheck(gi, groupCtx)
	if err != nil {
		return err
	}

	pass, cx, err := logic.EvalSignatureFull(gi, groupCtx.evalParams)
	if err != nil {
		logicErrTotal.Inc(nil)
		return fmt.Errorf("transaction %v: %w", groupCtx.signedGroupTxns[gi].ID(), err)
	}
	if !pass {
		logicRejTotal.Inc(nil)
		return fmt.Errorf("transaction %v: rejected by logic", groupCtx.signedGroupTxns[gi].ID())
	}
	logicGoodTotal.Inc(nil)
	logicCostTotal.AddUint64(uint64(cx.Cost()), nil)
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
				err1 := verificationPool.EnqueueBacklog(ctx, func(arg interface{}) interface{} {
					var grpErr error
					// check if we've canceled the request while this was in the queue.
					if tasksCtx.Err() != nil {
						return tasksCtx.Err()
					}

					txnGroups := arg.([][]transactions.SignedTxn)
					groupCtxs := make([]*GroupContext, len(txnGroups))

					batchVerifier := crypto.MakeBatchVerifierWithHint(len(payset))
					for i, signTxnsGrp := range txnGroups {
						groupCtxs[i], grpErr = txnGroupBatchPrep(signTxnsGrp, &blkHeader, ledger, batchVerifier, nil)
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
				if err1 != nil {
					return err1
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
