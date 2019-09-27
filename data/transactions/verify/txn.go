// Copyright (C) 2019 Algorand, Inc.
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
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/util/execpool"
)

// TxnPool verifies that a SignedTxn has a good signature and that the underlying
// transaction is properly constructed.
// Note that this does not check whether a payset is valid against the ledger:
// a SignedTxn may be well-formed, but a payset might contain an overspend.
//
// This version of verify is performing the verification over the provided execution pool.
func TxnPool(s *transactions.SignedTxn, spec transactions.SpecialAddresses, proto config.ConsensusParams, verificationPool execpool.BacklogPool) error {
	if err := s.Txn.WellFormed(spec, proto); err != nil {
		return err
	}

	zeroAddress := basics.Address{}
	if s.Txn.Src() == zeroAddress {
		return errors.New("empty address")
	}

	if s.Sig != (crypto.Signature{}) && !s.Msig.Blank() {
		return errors.New("signedtxn should only have one of Sig or Msig")
	}

	outCh := make(chan error, 1)
	cx := asyncVerifyContext{s, outCh, &proto}
	verificationPool.EnqueueBacklog(context.Background(), stxnAsyncVerify, &cx, nil)
	if err, hasErr := <-outCh; hasErr {
		return err
	}
	return nil
}

// Txn verifies a SignedTxn as being signed and having no obviously inconsistent data.
// Block-assembly time checks of LogicSig and accounting rules may still block the txn.
func Txn(s *transactions.SignedTxn, spec transactions.SpecialAddresses, proto config.ConsensusParams) error {
	if err := s.Txn.WellFormed(spec, proto); err != nil {
		return err
	}

	zeroAddress := basics.Address{}
	if s.Txn.Src() == zeroAddress {
		return errors.New("empty address")
	}

	return stxnVerifyCore(s, &proto)
}

type asyncVerifyContext struct {
	s     *transactions.SignedTxn
	outCh chan error
	proto *config.ConsensusParams
}

func stxnAsyncVerify(arg interface{}) interface{} {
	cx := arg.(*asyncVerifyContext)
	err := stxnVerifyCore(cx.s, cx.proto)
	if err != nil {
		cx.outCh <- err
	} else {
		close(cx.outCh)
	}
	return nil
}

func stxnVerifyCore(s *transactions.SignedTxn, proto *config.ConsensusParams) error {
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
		return errors.New("signedtxn has no sig")
	}
	if numSigs > 1 {
		return errors.New("signedtxn should only have one of Sig or Msig or LogicSig")
	}

	if hasSig {
		if crypto.SignatureVerifier(s.Txn.Src()).Verify(s.Txn, s.Sig) {
			return nil
		}
		return errors.New("signature validation failed")
	}
	if hasMsig {
		if ok, _ := crypto.MultisigVerify(s.Txn, crypto.Digest(s.Txn.Src()), s.Msig); ok {
			return nil
		}
		return errors.New("multisig validation failed")
	}
	if hasLogicSig {
		return LogicSig(&s.Lsig, proto, s)
	}
	return errors.New("has one mystery sig. WAT?")
}

// LogicSig checks that the signature is valid and that the program is basically well formed.
// It does not evaluate the logic.
func LogicSig(lsig *transactions.LogicSig, proto *config.ConsensusParams, stxn *transactions.SignedTxn) error {
	if len(lsig.Logic) == 0 {
		return errors.New("LogicSig.Logic empty")
	}
	version, vlen := binary.Uvarint(lsig.Logic)
	if vlen < 0 {
		return errors.New("LogicSig.Logic bad version")
	}
	if version > proto.LogicSigVersion {
		return errors.New("LogicSig.Logic version too new")
	}
	if uint64(lsig.Len()) > proto.LogicSigMaxSize {
		return errors.New("LogicSig.Logic too long")
	}

	ep := logic.EvalParams{Txn: stxn, Proto: proto}
	cost, err := logic.Check(stxn.Lsig.Logic, ep)
	if err != nil {
		return err
	}
	if cost > int(proto.LogicSigMaxCost) {
		return fmt.Errorf("LogicSig.Logic too slow, %d > %d", cost, proto.LogicSigMaxCost)
	}

	hasSig := false
	hasMsig := false
	numSigs := 0
	if lsig.Sig != (crypto.Signature{}) {
		hasSig = true
		numSigs++
	}
	if !lsig.Msig.Blank() {
		hasMsig = true
		numSigs++
	}
	if numSigs == 0 {
		// if the txn.Sender == hash(Logic) then this is a (potentially) valid operation on a contract-only account
		program := transactions.Program(lsig.Logic)
		lhash := crypto.HashObj(&program)
		if crypto.Digest(stxn.Txn.Sender) == lhash {
			return nil
		}
		return errors.New("LogicNot signed and not a Logic-only account")
	}
	if numSigs > 1 {
		return errors.New("LogicSig should only have one of Sig or Msig but has more than one")
	}

	if hasSig {
		program := transactions.Program(lsig.Logic)
		if crypto.SignatureVerifier(stxn.Txn.Src()).Verify(&program, lsig.Sig) {
			return nil
		}
		return errors.New("logic signature validation failed")
	}
	if hasMsig {
		program := transactions.Program(lsig.Logic)
		if ok, _ := crypto.MultisigVerify(&program, crypto.Digest(stxn.Txn.Src()), lsig.Msig); ok {
			return nil
		}
		return errors.New("logic multisig validation failed")
	}

	return errors.New("inconsistent internal state verifying LogicSig")
}
