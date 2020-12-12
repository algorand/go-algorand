// Copyright (C) 2019-2020 Algorand, Inc.
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

// The PaysetGroups is taking large set of transaction groups and attempt to verify their validity using multiple go-routines.
// When doing so, it attempts to break these into smaller "worksets" where each workset takes about 2ms of execution time in order
// to avoid context switching overhead while providing good validation cancelation responsiveness. Each one of these worksets is
// "populated" with roughly txnPerWorksetThreshold transactions. ( note that the real evaluation time is unknown, but benchmarks
// showen that these are realistic numbers )
const txnPerWorksetThreshold = 32

// When the PaysetGroups is generating worksets, it enqueues up to concurrentWorksets entries to the execution pool. This serves several
// purposes :
// - if the verification task need to be aborted, there are only concurrentWorksets entries that are currently redundent on the execution pool queue.
// - that number of concurrent tasks would not get beyond the capacity of the execution pool back buffer.
// - if we were to "redundently" execute all these during context cancelation, we would spent at most 2ms * 16 = 32ms time.
// - it allows us to linearly scan the input, and process elements only once we're going to queue them into the pool.
const concurrentWorksets = 16

// Context encapsulates the context needed to perform stateless checks
// on a signed transaction.
type Context struct {
	groupParams *GroupParams
	groupIndex  int // the index of the transaction in the group.
}

// GroupParams is the set of parameters external to a transaction which
// stateless checks are performed against.
//
// For efficient caching, these parameters should either be constant
// or change slowly over time.
//
// Group data are omitted because they are committed to in the
// transaction and its ID.
type GroupParams struct {
	CurrSpecAddrs   transactions.SpecialAddresses
	CurrProto       protocol.ConsensusVersion
	MinTealVersion  uint64
	SignedGroupTxns []transactions.SignedTxn
}

// PrepareContexts prepares verification contexts for a transaction
// group.
func PrepareContexts(group []transactions.SignedTxn, contextHdr bookkeeping.BlockHeader) []Context {
	if len(group) == 0 {
		return nil
	}
	ctxs := make([]Context, len(group))
	minTealVersion := logic.ComputeMinTealVersion(group)
	params := GroupParams{
		CurrSpecAddrs: transactions.SpecialAddresses{
			FeeSink:     contextHdr.FeeSink,
			RewardsPool: contextHdr.RewardsPool,
		},
		CurrProto:       contextHdr.CurrentProtocol,
		MinTealVersion:  minTealVersion,
		SignedGroupTxns: group,
	}

	for i := range group {
		ctx := Context{
			groupParams: &params,
			groupIndex:  i,
		}
		ctxs[i] = ctx
	}
	return ctxs
}

// Equal compares two contexts to see if they would represent the same verification context for a given transaction.
func (ctx Context) Equal(other Context) bool {
	return ctx.groupIndex == other.groupIndex &&
		ctx.groupParams.MinTealVersion == other.groupParams.MinTealVersion &&
		ctx.groupParams.CurrProto == other.groupParams.CurrProto
}

// Txn verifies a SignedTxn as being signed and having no obviously inconsistent data.
// Block-assembly time checks of LogicSig and accounting rules may still block the txn.
func Txn(s *transactions.SignedTxn, ctx Context) error {
	proto, ok := config.Consensus[ctx.groupParams.CurrProto]
	if !ok {
		return protocol.Error(ctx.groupParams.CurrProto)
	}

	if !proto.SupportRekeying && (s.AuthAddr != basics.Address{}) {
		return errors.New("nonempty AuthAddr but rekeying not supported")
	}

	if err := s.Txn.WellFormed(ctx.groupParams.CurrSpecAddrs, proto); err != nil {
		return err
	}

	if s.Txn.Src().IsZero() {
		return errors.New("empty address")
	}

	return stxnVerifyCore(s, &ctx)
}

// TxnGroup verifies a []SignedTxn as being signed and having no obviously inconsistent data.
func TxnGroup(stxs []transactions.SignedTxn, contextHdr bookkeeping.BlockHeader, cache VerifiedTransactionCache) (err error) {
	ctxs := PrepareContexts(stxs, contextHdr)
	for i, stxn := range stxs {
		err = Txn(&stxn, ctxs[i])
		if err != nil {
			err = fmt.Errorf("transaction %+v invalid : %w", stxn, err)
			return
		}
	}
	if cache != nil {
		err = cache.Add(stxs, ctxs)
	}
	return
}

type asyncVerifyContext struct {
	s     *transactions.SignedTxn
	outCh chan error
	ctx   *Context
}

func stxnAsyncVerify(arg interface{}) interface{} {
	cx := arg.(*asyncVerifyContext)
	err := stxnVerifyCore(cx.s, cx.ctx)
	if err != nil {
		cx.outCh <- err
	} else {
		close(cx.outCh)
	}
	return nil
}

func stxnVerifyCore(s *transactions.SignedTxn, ctx *Context) error {
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
		// types (compact cert txn) without any signature.  The well-formed
		// check ensures that this transaction cannot pay any fee, and
		// cannot have any other interesting fields, except for the compact
		// cert payload.
		if s.Txn.Sender == transactions.CompactCertSender && s.Txn.Type == protocol.CompactCertTx {
			return nil
		}

		return errors.New("signedtxn has no sig")
	}
	if numSigs > 1 {
		return errors.New("signedtxn should only have one of Sig or Msig or LogicSig")
	}

	if hasSig {
		if crypto.SignatureVerifier(s.Authorizer()).Verify(s.Txn, s.Sig) {
			return nil
		}
		return errors.New("signature validation failed")
	}
	if hasMsig {
		if ok, _ := crypto.MultisigVerify(s.Txn, crypto.Digest(s.Authorizer()), s.Msig); ok {
			return nil
		}
		return errors.New("multisig validation failed")
	}
	if hasLogicSig {
		return LogicSig(s, ctx)
	}
	return errors.New("has one mystery sig. WAT?")
}

// LogicSigSanityCheck checks that the signature is valid and that the program is basically well formed.
// It does not evaluate the logic.
func LogicSigSanityCheck(txn *transactions.SignedTxn, ctx *Context) error {
	lsig := txn.Lsig
	proto, ok := config.Consensus[ctx.groupParams.CurrProto]
	if !ok {
		return protocol.Error(ctx.groupParams.CurrProto)
	}
	if proto.LogicSigVersion == 0 {
		return errors.New("LogicSig not enabled")
	}
	if len(lsig.Logic) == 0 {
		return errors.New("LogicSig.Logic empty")
	}
	version, vlen := binary.Uvarint(lsig.Logic)
	if vlen <= 0 {
		return errors.New("LogicSig.Logic bad version")
	}
	if version > proto.LogicSigVersion {
		return errors.New("LogicSig.Logic version too new")
	}
	if uint64(lsig.Len()) > proto.LogicSigMaxSize {
		return errors.New("LogicSig.Logic too long")
	}

	ep := logic.EvalParams{
		Txn:            txn,
		Proto:          &proto,
		TxnGroup:       ctx.groupParams.SignedGroupTxns,
		GroupIndex:     ctx.groupIndex,
		MinTealVersion: &ctx.groupParams.MinTealVersion,
	}
	cost, err := logic.Check(lsig.Logic, ep)
	if err != nil {
		return err
	}
	if cost > int(proto.LogicSigMaxCost) {
		return fmt.Errorf("LogicSig.Logic too slow, %d > %d", cost, proto.LogicSigMaxCost)
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
		if !crypto.SignatureVerifier(txn.Authorizer()).Verify(&program, lsig.Sig) {
			return errors.New("logic signature validation failed")
		}
	} else {
		program := logic.Program(lsig.Logic)
		if ok, _ := crypto.MultisigVerify(&program, crypto.Digest(txn.Authorizer()), lsig.Msig); !ok {
			return errors.New("logic multisig validation failed")
		}
	}
	return nil
}

// LogicSig checks that the signature is valid, executing the program.
func LogicSig(txn *transactions.SignedTxn, ctx *Context) error {
	proto, ok := config.Consensus[ctx.groupParams.CurrProto]
	if !ok {
		return protocol.Error(ctx.groupParams.CurrProto)
	}

	err := LogicSigSanityCheck(txn, ctx)
	if err != nil {
		return err
	}

	ep := logic.EvalParams{
		Txn:            txn,
		Proto:          &proto,
		TxnGroup:       ctx.groupParams.SignedGroupTxns,
		GroupIndex:     ctx.groupIndex,
		MinTealVersion: &ctx.groupParams.MinTealVersion,
	}
	pass, err := logic.Eval(txn.Lsig.Logic, ep)
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
func PaysetGroups(ctx context.Context, payset [][]transactions.SignedTxn, blkHeader bookkeeping.BlockHeader, verificationPool execpool.BacklogPool, cache VerifiedTransactionCache) (err error) {
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
					// check if we've canceled the request while this was in the queue.
					if tasksCtx.Err() != nil {
						return tasksCtx.Err()
					}
					txnGroups := arg.([][]transactions.SignedTxn)
					for _, signTxnsGrp := range txnGroups {
						err := TxnGroup(signTxnsGrp, blkHeader, cache)
						// abort only if it's a non-cache error.
						if err != nil {
							if _, cacheErr := err.(*VerifiedTxnCacheError); !cacheErr {
								return err
							}
						}
					}
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
