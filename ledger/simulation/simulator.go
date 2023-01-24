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

package simulation

import (
	"errors"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// ==============================
// > Simulator Ledger
// ==============================

// simulatorLedger patches the ledger interface to use a constant latest round.
type simulatorLedger struct {
	*data.Ledger
	start basics.Round
}

// Latest is part of the LedgerForSimulator interface.
// We override this to use the set latest to prevent racing with the network
func (l simulatorLedger) Latest() basics.Round {
	return l.start
}

// LookupLatest would implicitly use the latest round in the _underlying_
// Ledger, it would give wrong results if that ledger has moved forward. But it
// should never be called, as the REST API is the only code using this function,
// and the REST API should never have access to a simulatorLedger.
func (l simulatorLedger) LookupLatest(addr basics.Address) (basics.AccountData, basics.Round, basics.MicroAlgos, error) {
	err := errors.New("unexpected call to LookupLatest")
	return basics.AccountData{}, 0, basics.MicroAlgos{}, err
}

// ==============================
// > Simulator Tracer
// ==============================

type evalTracer struct {
	logic.NullEvalTracer
}

func makeTracer() logic.EvalTracer {
	return &evalTracer{}
}

// ==============================
// > Simulator Errors
// ==============================

// SimulatorError is the base error type for all simulator errors.
type SimulatorError struct {
	err error
}

func (s SimulatorError) Error() string {
	return s.err.Error()
}

func (s SimulatorError) Unwrap() error {
	return s.err
}

// InvalidTxGroupError occurs when an invalid transaction group was submitted to the simulator.
type InvalidTxGroupError struct {
	SimulatorError
}

// EvalFailureError represents an error that occurred during evaluation.
type EvalFailureError struct {
	SimulatorError
}

// ==============================
// > Simulator
// ==============================

// Simulator is a transaction group simulator for the block evaluator.
type Simulator struct {
	ledger simulatorLedger
}

// MakeSimulator creates a new simulator from a ledger.
func MakeSimulator(ledger *data.Ledger) *Simulator {
	return &Simulator{
		ledger: simulatorLedger{ledger, ledger.Latest()},
	}
}

func txnHasNoSignature(txn transactions.SignedTxn) bool {
	return txn.Sig.Blank() && txn.Msig.Blank() && txn.Lsig.Blank()
}

// A randomly generated private key. The actual value does not matter, as long as this is a valid
// private key.
var proxySigner = crypto.PrivateKey{
	128, 128, 92, 23, 212, 119, 175, 51, 157, 2, 165,
	215, 137, 37, 82, 42, 52, 227, 54, 41, 243, 67,
	141, 76, 208, 17, 199, 17, 140, 46, 113, 0, 159,
	50, 105, 52, 77, 104, 118, 200, 104, 220, 105, 21,
	147, 162, 191, 236, 115, 201, 197, 128, 8, 91, 224,
	78, 104, 209, 2, 185, 110, 28, 42, 97,
}

// check verifies that the transaction is well-formed and has valid or missing signatures.
// An invalid transaction group error is returned if the transaction is not well-formed or there are invalid signatures.
// To make things easier, we support submitting unsigned transactions and will respond whether signatures are missing.
func (s Simulator) check(hdr bookkeeping.BlockHeader, txgroup []transactions.SignedTxn, debugger logic.EvalTracer) (bool, error) {
	proxySignerSecrets, err := crypto.SecretKeyToSignatureSecrets(proxySigner)
	if err != nil {
		return false, err
	}

	// Find and prep any transactions that are missing signatures. We will modify a copy of these
	// transactions to pass signature verification. The modifications will not affect the input
	// txgroup slice.
	//
	// Note: currently we only support missing transaction signatures, but it should be possible to
	// support unsigned delegated LogicSigs as well. A single-signature unsigned delegated LogicSig
	// is indistinguishable from an escrow LogicSig, so we would need to decide on another way of
	// denoting that a LogicSig's delegation signature is omitted, e.g. by setting all the bits of
	// the signature.
	missingSigs := make([]int, 0, len(txgroup))
	txnsToVerify := make([]transactions.SignedTxn, len(txgroup))
	for i, stxn := range txgroup {
		if stxn.Txn.Type == protocol.StateProofTx {
			return false, errors.New("cannot simulate StateProof transactions")
		}
		if txnHasNoSignature(stxn) {
			missingSigs = append(missingSigs, i)

			// Replace the signed txn with one signed by the proxySigner. At evaluation this would
			// raise an error, since the proxySigner's public key likely does not have authority
			// over the sender's account. However, this will pass validation, since the signature
			// itself is valid.
			txnsToVerify[i] = stxn.Txn.Sign(proxySignerSecrets)
		} else {
			txnsToVerify[i] = stxn
		}
	}

	// Verify the signed transactions are well-formed and have valid signatures
	_, err = verify.TxnGroupWithTracer(txnsToVerify, &hdr, nil, s.ledger, debugger)
	if err != nil {
		return false, InvalidTxGroupError{SimulatorError{err}}
	}

	return len(missingSigs) != 0, nil
}

func (s Simulator) evaluate(hdr bookkeeping.BlockHeader, stxns []transactions.SignedTxn, tracer logic.EvalTracer) (*ledgercore.ValidatedBlock, error) {
	// s.ledger has 'StartEvaluator' because *data.Ledger is embedded in the simulatorLedger
	// and data.Ledger embeds *ledger.Ledger
	eval, err := s.ledger.StartEvaluator(hdr, len(stxns), 0)
	if err != nil {
		return nil, err
	}
	eval.Tracer = tracer

	group := transactions.WrapSignedTxnsWithAD(stxns)

	err = eval.TransactionGroup(group)
	if err != nil {
		return nil, EvalFailureError{SimulatorError{err}}
	}

	// Finally, process any pending end-of-block state changes.
	vb, err := eval.GenerateBlock()
	if err != nil {
		return nil, err
	}

	return vb, nil
}

// Simulate simulates a transaction group using the simulator. Will error if the transaction group is not well-formed.
func (s Simulator) Simulate(txgroup []transactions.SignedTxn) (*ledgercore.ValidatedBlock, bool, error) {
	prevBlockHdr, err := s.ledger.BlockHdr(s.ledger.start)
	if err != nil {
		return nil, false, err
	}
	nextBlock := bookkeeping.MakeBlock(prevBlockHdr)
	hdr := nextBlock.BlockHeader
	simulatorTracer := makeTracer()

	// check that the transaction is well-formed and mark whether signatures are missing
	missingSignatures, err := s.check(hdr, txgroup, simulatorTracer)
	if err != nil {
		return nil, false, err
	}

	vb, err := s.evaluate(hdr, txgroup, simulatorTracer)
	return vb, missingSignatures, err
}
