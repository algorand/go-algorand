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

// Context encapsulates the context needed to perform stateless checks
// on a signed transaction.
type Context struct {
	Params
	Group      []transactions.SignedTxn
	GroupIndex int
}

// Params is the set of parameters external to a transaction which
// stateless checks are performed against.
//
// For efficient caching, these parameters should either be constant
// or change slowly over time.
//
// Group data are omitted because they are committed to in the
// transaction and its ID.
type Params struct {
	CurrSpecAddrs  transactions.SpecialAddresses
	CurrProto      protocol.ConsensusVersion
	MinTealVersion uint64
}

// PrepareContexts prepares verification contexts for a transaction
// group.
func PrepareContexts(group []transactions.SignedTxn, contextHdr bookkeeping.BlockHeader) []Context {
	ctxs := make([]Context, len(group))
	minTealVersion := logic.ComputeMinTealVersion(group)
	for i := range group {
		spec := transactions.SpecialAddresses{
			FeeSink:     contextHdr.FeeSink,
			RewardsPool: contextHdr.RewardsPool,
		}
		ctx := Context{
			Params: Params{
				CurrSpecAddrs:  spec,
				CurrProto:      contextHdr.CurrentProtocol,
				MinTealVersion: minTealVersion,
			},
			Group:      group,
			GroupIndex: i,
		}
		ctxs[i] = ctx
	}

	return ctxs
}

// TxnPool verifies that a SignedTxn has a good signature and that the underlying
// transaction is properly constructed.
// Note that this does not check whether a payset is valid against the ledger:
// a SignedTxn may be well-formed, but a payset might contain an overspend.
//
// This version of verify is performing the verification over the provided execution pool.
func TxnPool(s *transactions.SignedTxn, ctx Context, verificationPool execpool.BacklogPool) error {
	proto, ok := config.Consensus[ctx.CurrProto]
	if !ok {
		return protocol.Error(ctx.CurrProto)
	}
	if err := s.Txn.WellFormed(ctx.CurrSpecAddrs, proto); err != nil {
		return err
	}

	zeroAddress := basics.Address{}
	if s.Txn.Src() == zeroAddress {
		return errors.New("empty address")
	}
	if !proto.SupportRekeying && (s.AuthAddr != basics.Address{}) {
		return errors.New("nonempty AuthAddr but rekeying not supported")
	}

	outCh := make(chan error, 1)
	cx := asyncVerifyContext{s: s, outCh: outCh, ctx: &ctx}
	verificationPool.EnqueueBacklog(context.Background(), stxnAsyncVerify, &cx, nil)
	if err, hasErr := <-outCh; hasErr {
		return err
	}
	return nil
}

// Txn verifies a SignedTxn as being signed and having no obviously inconsistent data.
// Block-assembly time checks of LogicSig and accounting rules may still block the txn.
func Txn(s *transactions.SignedTxn, ctx Context) error {
	proto, ok := config.Consensus[ctx.CurrProto]
	if !ok {
		return protocol.Error(ctx.CurrProto)
	}
	if err := s.Txn.WellFormed(ctx.CurrSpecAddrs, proto); err != nil {
		return err
	}

	zeroAddress := basics.Address{}
	if s.Txn.Src() == zeroAddress {
		return errors.New("empty address")
	}
	if !proto.SupportRekeying && (s.AuthAddr != basics.Address{}) {
		return errors.New("nonempty AuthAddr but rekeying not supported")
	}

	return stxnVerifyCore(s, &ctx)
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
	proto, ok := config.Consensus[ctx.CurrProto]
	if !ok {
		return protocol.Error(ctx.CurrProto)
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
		TxnGroup:       ctx.Group,
		GroupIndex:     ctx.GroupIndex,
		MinTealVersion: &ctx.MinTealVersion,
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
	proto, ok := config.Consensus[ctx.CurrProto]
	if !ok {
		return protocol.Error(ctx.CurrProto)
	}

	err := LogicSigSanityCheck(txn, ctx)
	if err != nil {
		return err
	}

	ep := logic.EvalParams{
		Txn:            txn,
		Proto:          &proto,
		TxnGroup:       ctx.Group,
		GroupIndex:     ctx.GroupIndex,
		MinTealVersion: &ctx.MinTealVersion,
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
