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
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/pkg/errors"
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
	panic("unexpected call to LookupLatest")
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

// InvalidSignatureError occurs when a transaction has an invalid signature.
type InvalidSignatureError struct {
	SimulatorError
}

// ScopedSimulatorError is a simulator error that has 2 errors, one for internal use and one for
// displaying publicly. THe external error is useful for API routes/etc.
type ScopedSimulatorError struct {
	SimulatorError        // the original error for internal use
	External       string // the external error for public use
}

// ==============================
// > Simulator Helper Methods
// ==============================

func isInvalidSignatureError(err error) bool {
	return errors.As(err, &verify.SignatureError{})
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
// A failure message is returned if the transaction is not well-formed.
func (s Simulator) check(hdr bookkeeping.BlockHeader, txgroup []transactions.SignedTxn) error {
	_, err := verify.TxnGroup(txgroup, hdr, nil)
	if err != nil {
		// invalid signature error
		if isInvalidSignatureError(err) {
			return InvalidSignatureError{SimulatorError{err}}
		}

		// otherwise the transaction group was invalid in some way
		return InvalidTxGroupError{SimulatorError{err}}
	}

	return nil
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
		return nil, err
	}

	// Finally, process any pending end-of-block state changes.
	vb, err := eval.GenerateBlock()
	if err != nil {
		return nil, err
	}

	return vb, nil
}

// Simulate simulates a transaction group using the simulator. Will error if the transaction group is not well-formed or an
// unexpected error occurs. Otherwise, evaluation failure messages are returned.
func (s Simulator) Simulate(txgroup []transactions.SignedTxn) (generated.SimulationResult, error) {
	prevBlockHdr, err := s.ledger.BlockHdr(s.ledger.start)
	if err != nil {
		return generated.SimulationResult{}, err
	}
	nextBlock := bookkeeping.MakeBlock(prevBlockHdr)
	hdr := nextBlock.BlockHeader

	var result generated.SimulationResult

	// check that the transaction is well-formed
	err = s.check(hdr, txgroup)
	if err != nil {
		switch err.(type) {
		case InvalidSignatureError:
			errMessage := err.Error()
			result.SignatureFailureMessage = &errMessage
		default:
			return result, err
		}
	}

	_, err = s.evaluate(hdr, txgroup)
	if err != nil {
		errStr := err.Error()
		result.FailureMessage = &errStr
	}

	return result, nil
}
