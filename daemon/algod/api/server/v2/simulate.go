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
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger"
)

// ==============================
// > Simulation Ledger
// ==============================

// LedgerForSimulator is a ledger interface for the simulator.
type LedgerForSimulator interface {
	ledger.DebuggerLedgerForEval
}

type apiSimulatorLedgerConnector struct {
	LedgerForAPI
	hdr bookkeeping.BlockHeader
}

// Latest is part of the LedgerForSimulator interface.
// We override this to use the set hdr to prevent racing with the network
func (l apiSimulatorLedgerConnector) Latest() basics.Round {
	return l.hdr.Round
}

// BlockHdr is part of the LedgerForSimulator interface.
// We override this to use the set hdr to prevent racing with the network
func (l apiSimulatorLedgerConnector) BlockHdr(round basics.Round) (bookkeeping.BlockHeader, error) {
	if round != l.Latest() {
		err := fmt.Errorf(
			"BlockHdr() evaluator called this function for the wrong round %d, "+
				"latest round is %d",
			round, l.Latest())
		return bookkeeping.BlockHeader{}, err
	}

	return l.LedgerForAPI.BlockHdr(round)
}

// BlockHdrCached is part of the LedgerForSimulator interface.
func (l apiSimulatorLedgerConnector) BlockHdrCached(round basics.Round) (bookkeeping.BlockHeader, error) {
	return l.BlockHdr(round)
}

// GenesisHash is part of LedgerForSimulator interface.
func (l apiSimulatorLedgerConnector) GenesisHash() crypto.Digest {
	return l.hdr.GenesisHash
}

// GenesisProto is part of LedgerForSimulator interface.
func (l apiSimulatorLedgerConnector) GenesisProto() config.ConsensusParams {
	return config.Consensus[l.hdr.CurrentProtocol]
}

// GetCreatorForRound is part of LedgerForSimulator interface.
func (l apiSimulatorLedgerConnector) GetCreatorForRound(round basics.Round, cidx basics.CreatableIndex, ctype basics.CreatableType) (creator basics.Address, ok bool, err error) {
	if round != l.Latest() {
		err = fmt.Errorf(
			"GetCreatorForRound() evaluator called this function for the wrong round %d, "+
				"latest round is %d",
			round, l.Latest())
		return
	}

	return l.GetCreator(cidx, ctype)
}

func makeLedgerForSimulatorFromLedgerForAPI(ledgerForAPI LedgerForAPI, hdr bookkeeping.BlockHeader) LedgerForSimulator {
	return &apiSimulatorLedgerConnector{ledgerForAPI, hdr}
}

// ==============================
// > Simulator Errors
// ==============================

// SimulatorError is the base error type for all simulator errors.
type SimulatorError struct {
	error
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
	invalidSignatureErrorFragments := []string{
		"signedtxn has no sig",
		"signedtxn should only have one of Sig or Msig or LogicSig",
		"multisig validation failed",
		"has one mystery sig",
	}

	for _, fragment := range invalidSignatureErrorFragments {
		if strings.Contains(err.Error(), fragment) {
			return true
		}
	}

	return false
}

// ==============================
// > Simulator
// ==============================

// Simulator is a transaction group simulator for the block evaluator.
type Simulator struct {
	ledger LedgerForSimulator
}

// MakeSimulator creates a new simulator from a ledger.
func MakeSimulator(ledger LedgerForSimulator) *Simulator {
	return &Simulator{
		ledger: ledger,
	}
}

// MakeSimulatorFromAPILedger creates a new simulator from an API ledger.
func MakeSimulatorFromAPILedger(ledgerForAPI LedgerForAPI, hdr bookkeeping.BlockHeader) *Simulator {
	ledger := makeLedgerForSimulatorFromLedgerForAPI(ledgerForAPI, hdr)
	return MakeSimulator(ledger)
}

// checkWellFormed checks that the transaction is well-formed. A failure message is returned if the transaction is not well-formed.
func (s Simulator) checkWellFormed(txgroup []transactions.SignedTxn) error {
	hdr, err := s.ledger.BlockHdr(s.ledger.Latest())
	if err != nil {
		return ScopedSimulatorError{SimulatorError{fmt.Errorf("please contact us, this shouldn't happen. Current block error: %v", err)}, "current block error"}
	}

	batchVerifier := crypto.MakeBatchVerifier()
	_, err = verify.TxnGroupBatchVerify(txgroup, hdr, nil, batchVerifier)
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
		errMessage := err.Error()
		switch err.(type) {
		case InvalidSignatureError:
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
