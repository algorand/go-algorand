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

package v2

import (
	"fmt"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger"
	"github.com/pkg/errors"
)

// ==============================
// > Simulator Ledger
// ==============================

// simulatorLedger patches the ledger interface to use a constant latest round.
type simulatorLedger struct {
	ledger.DebuggerLedgerForEval
	latest basics.Round
}

// Latest is part of the LedgerForSimulator interface.
// We override this to use the set latest to prevent racing with the network
func (l simulatorLedger) Latest() basics.Round {
	return l.latest
}

func makeSimulatorLedgerFromDebuggerLedger(ledger ledger.DebuggerLedgerForEval) simulatorLedger {
	return simulatorLedger{ledger, ledger.Latest()}
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
func MakeSimulator(debuggerLedger ledger.DebuggerLedgerForEval) *Simulator {
	ledger := makeSimulatorLedgerFromDebuggerLedger(debuggerLedger)
	return &Simulator{
		ledger: ledger,
	}
}

// checkWellFormed checks that the transaction is well-formed. A failure message is returned if the transaction is not well-formed.
func (s Simulator) checkWellFormed(txgroup []transactions.SignedTxn) error {
	hdr, err := s.ledger.BlockHdr(s.ledger.Latest())
	if err != nil {
		return ScopedSimulatorError{SimulatorError{fmt.Errorf("please contact us, this shouldn't happen. Current block error: %v", err)}, "current block error"}
	}

	_, err = verify.TxnGroup(txgroup, hdr, nil)
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

// SimulateSignedTxGroup simulates a transaction group using the simulator. Will error if the transaction group is not well-formed or an
// unexpected error occurs. Otherwise, evaluation failure messages are returned.
func (s Simulator) SimulateSignedTxGroup(txgroup []transactions.SignedTxn) (generated.SimulationResult, error) {
	var result generated.SimulationResult

	// check that the transaction is well-formed. Signatures are checked after evaluation
	err := s.checkWellFormed(txgroup)
	if err != nil {
		switch err.(type) {
		case InvalidSignatureError:
			errMessage := err.Error()
			result.SignatureFailureMessage = &errMessage
		default:
			return result, err
		}
	}

	_, _, evalErr := ledger.EvalForDebugger(s.ledger, txgroup)
	if evalErr != nil {
		errStr := evalErr.Error()
		result.FailureMessage = &errStr
	}

	return result, nil
}
