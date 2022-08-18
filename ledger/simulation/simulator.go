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

package simulation

import (
	"errors"

	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/ledgercore"
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

// check verifies that the transaction is well-formed and has valid or missing signatures.
// An invalid transaction group error is returned if the transaction is not well-formed or there are invalid signatures.
// To make things easier, we support submitting unsigned transactions and will respond whether signatures are missing.
func (s Simulator) check(hdr bookkeeping.BlockHeader, txgroup []transactions.SignedTxn) (isMissingSigs bool, err error) {
	// verify the signed transactions are well-formed and have valid or missing signatures
	_, err = verify.TxnGroupWithMissingSignatures(txgroup, hdr, nil)
	if err != nil {
		err = InvalidTxGroupError{SimulatorError{err}}
		return
	}

	// determine whether signatures are missing
	for _, tx := range txgroup {
		if verify.TxnIsMissingSig(&tx) {
			isMissingSigs = true
			break
		}
	}

	return
}

func (s Simulator) evaluate(hdr bookkeeping.BlockHeader, stxns []transactions.SignedTxn) (*ledgercore.ValidatedBlock, error) {
	// s.ledger has 'StartEvaluator' because *data.Ledger is embedded in the simulatorLedger
	// and data.Ledger embeds *ledger.Ledger
	eval, err := s.ledger.StartEvaluator(hdr, len(stxns), 0)
	if err != nil {
		return nil, err
	}

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
func (s Simulator) Simulate(txgroup []transactions.SignedTxn) (vb *ledgercore.ValidatedBlock, missingSignatures bool, err error) {
	prevBlockHdr, err := s.ledger.BlockHdr(s.ledger.start)
	if err != nil {
		return
	}
	nextBlock := bookkeeping.MakeBlock(prevBlockHdr)
	hdr := nextBlock.BlockHeader

	// check that the transaction is well-formed and mark whether signatures are missing
	missingSignatures, err = s.check(hdr, txgroup)
	if err != nil {
		return
	}

	vb, err = s.evaluate(hdr, txgroup)
	return
}
