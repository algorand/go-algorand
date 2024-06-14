// Copyright (C) 2019-2024 Algorand, Inc.
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
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// Request packs simulation related txn-group(s), and configurations that are overlapping the ones in real transactions.
type Request struct {
	Round                 basics.Round
	TxnGroups             [][]transactions.SignedTxn
	AllowEmptySignatures  bool
	AllowMoreLogging      bool
	AllowUnnamedResources bool
	ExtraOpcodeBudget     uint64
	TraceConfig           ExecTraceConfig
	FixSigners            bool
}

// simulatorLedger patches the ledger interface to use a constant latest round.
type simulatorLedger struct {
	*data.Ledger
	start basics.Round
}

// Latest is part of the ledger.Ledger interface.
// We override this to use the set latest to prevent racing with the network
func (l simulatorLedger) Latest() basics.Round {
	return l.start
}

// LatestTotals is part of the ledger.Ledger interface.
func (l simulatorLedger) LatestTotals() (basics.Round, ledgercore.AccountTotals, error) {
	totals, err := l.Totals(l.start)
	return l.start, totals, err
}

// LookupLatest would implicitly use the latest round in the _underlying_
// Ledger, it would give wrong results if that ledger has moved forward. But it
// should never be called, as the REST API is the only code using this function,
// and the REST API should never have access to a simulatorLedger.
func (l simulatorLedger) LookupLatest(addr basics.Address) (basics.AccountData, basics.Round, basics.MicroAlgos, error) {
	err := errors.New("unexpected call to LookupLatest")
	return basics.AccountData{}, 0, basics.MicroAlgos{}, err
}

// StartEvaluator is part of the ledger.Ledger interface. We override this so that
// the eval.LedgerForEvaluator value passed into eval.StartEvaluator is a simulatorLedger,
// not a data.Ledger. This ensures our overridden LookupLatest method will be used.
func (l simulatorLedger) StartEvaluator(hdr bookkeeping.BlockHeader, paysetHint, maxTxnBytesPerBlock int, tracer logic.EvalTracer) (*eval.BlockEvaluator, error) {
	if tracer == nil {
		return nil, errors.New("tracer is nil")
	}
	return eval.StartEvaluator(&l, hdr,
		eval.EvaluatorOptions{
			PaysetHint:          paysetHint,
			Generate:            true,
			Validate:            true,
			MaxTxnBytesPerBlock: maxTxnBytesPerBlock,
			Tracer:              tracer,
		})
}

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

// InvalidRequestError occurs when an invalid transaction group was submitted to the simulator.
type InvalidRequestError struct {
	SimulatorError
}

// EvalFailureError represents an error that occurred during evaluation.
type EvalFailureError struct {
	SimulatorError
}

// Simulator is a transaction group simulator for the block evaluator.
type Simulator struct {
	ledger       simulatorLedger
	developerAPI bool
}

// MakeSimulator creates a new simulator from a ledger.
func MakeSimulator(ledger *data.Ledger, developerAPI bool) *Simulator {
	return &Simulator{
		ledger:       simulatorLedger{ledger, 0}, // start round to be specified in Simulate method
		developerAPI: developerAPI,
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
func (s Simulator) check(hdr bookkeeping.BlockHeader, txgroup []transactions.SignedTxnWithAD, tracer logic.EvalTracer, overrides ResultEvalOverrides) error {
	proxySignerSecrets, err := crypto.SecretKeyToSignatureSecrets(proxySigner)
	if err != nil {
		return err
	}

	// If signaturesOptional is enabled, find and prep any transactions that are missing signatures.
	// We will modify a copy of these transactions to pass signature verification. The modifications
	// will not affect the input txgroup slice.
	//
	// Note: currently we only support missing transaction signatures, but it should be possible to
	// support unsigned delegated LogicSigs as well. A single-signature unsigned delegated LogicSig
	// is indistinguishable from an escrow LogicSig, so we would need to decide on another way of
	// denoting that a LogicSig's delegation signature is omitted, e.g. by setting all the bits of
	// the signature.
	txnsToVerify := make([]transactions.SignedTxn, len(txgroup))
	for i, stxnad := range txgroup {
		stxn := stxnad.SignedTxn
		if stxn.Txn.Type == protocol.StateProofTx {
			return errors.New("cannot simulate StateProof transactions")
		}
		if overrides.AllowEmptySignatures && txnHasNoSignature(stxn) {
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
	_, err = verify.TxnGroupWithTracer(txnsToVerify, &hdr, nil, s.ledger, tracer)
	if err != nil {
		err = InvalidRequestError{SimulatorError{err}}
	}
	return err
}

func (s Simulator) evaluate(hdr bookkeeping.BlockHeader, group []transactions.SignedTxnWithAD, tracer logic.EvalTracer) (*ledgercore.ValidatedBlock, error) {
	// s.ledger has 'StartEvaluator' because *data.Ledger is embedded in the simulatorLedger
	// and data.Ledger embeds *ledger.Ledger
	eval, err := s.ledger.StartEvaluator(hdr, len(group), 0, tracer)
	if err != nil {
		return nil, err
	}

	err = eval.TransactionGroup(group)
	if err != nil {
		return nil, EvalFailureError{SimulatorError{err}}
	}

	// Finally, process any pending end-of-block state changes.
	ub, err := eval.GenerateBlock(nil)
	if err != nil {
		return nil, err
	}

	// Since we skip agreement, this block is imperfect w/ respect to seed/proposer/payouts
	vb := ledgercore.MakeValidatedBlock(ub.UnfinishedBlock(), ub.UnfinishedDeltas())

	return &vb, nil
}

func (s Simulator) simulateWithTracer(txgroup []transactions.SignedTxnWithAD, tracer logic.EvalTracer, overrides ResultEvalOverrides) (*ledgercore.ValidatedBlock, error) {
	prevBlockHdr, err := s.ledger.BlockHdr(s.ledger.start)
	if err != nil {
		return nil, err
	}
	nextBlock := bookkeeping.MakeBlock(prevBlockHdr)
	hdr := nextBlock.BlockHeader

	if overrides.FixSigners {
		// Map of rekeys for senders in the group
		staticRekeys := make(map[basics.Address]basics.Address)

		for i := range txgroup {
			stxn := &txgroup[i].SignedTxn
			sender := stxn.Txn.Sender

			if authAddr, ok := staticRekeys[sender]; ok && txnHasNoSignature(*stxn) {
				// If there is a static rekey for the sender set the auth addr to that address
				stxn.AuthAddr = authAddr
				if stxn.AuthAddr == sender {
					stxn.AuthAddr = basics.Address{}
				}
			} else {
				// Otherwise lookup the sender's account and set the txn auth addr to the account's auth addr
				if txnHasNoSignature(*stxn) {
					var data ledgercore.AccountData
					data, _, _, err = s.ledger.LookupAccount(s.ledger.start, sender)
					if err != nil {
						return nil, err
					}

					stxn.AuthAddr = data.AuthAddr
					if stxn.AuthAddr == sender {
						stxn.AuthAddr = basics.Address{}
					}
				}
			}

			// Stop processing transactions after the first application because auth addr correction will be done in AfterProgram
			if stxn.Txn.Type == protocol.ApplicationCallTx {
				break
			}

			if stxn.Txn.RekeyTo != (basics.Address{}) {
				staticRekeys[sender] = stxn.Txn.RekeyTo
			}
		}

	}

	// check that the transaction is well-formed and mark whether signatures are missing
	err = s.check(hdr, txgroup, tracer, overrides)
	if err != nil {
		return nil, err
	}

	// check that the extra budget is not exceeding simulation extra budget limit
	if overrides.ExtraOpcodeBudget > MaxExtraOpcodeBudget {
		return nil, InvalidRequestError{
			SimulatorError{
				fmt.Errorf(
					"extra budget %d > simulation extra budget limit %d",
					overrides.ExtraOpcodeBudget, MaxExtraOpcodeBudget),
			},
		}
	}

	vb, err := s.evaluate(hdr, txgroup, tracer)
	return vb, err
}

// Simulate simulates a transaction group using the simulator. Will error if the transaction group is not well-formed.
func (s Simulator) Simulate(simulateRequest Request) (Result, error) {
	if simulateRequest.FixSigners && !simulateRequest.AllowEmptySignatures {
		return Result{}, InvalidRequestError{
			SimulatorError{
				errors.New("FixSigners requires AllowEmptySignatures to be enabled"),
			},
		}
	}

	if simulateRequest.Round != 0 {
		s.ledger.start = simulateRequest.Round
	} else {
		// Access underlying data.Ledger to get the real latest round
		s.ledger.start = s.ledger.Ledger.Latest()
	}

	if len(simulateRequest.TxnGroups) != 1 {
		return Result{}, InvalidRequestError{
			SimulatorError{
				err: fmt.Errorf("expected 1 transaction group, got %d", len(simulateRequest.TxnGroups)),
			},
		}
	}

	group := transactions.WrapSignedTxnsWithAD(simulateRequest.TxnGroups[0])

	simulatorTracer, err := makeEvalTracer(s.ledger.start, group, simulateRequest, s.developerAPI)
	if err != nil {
		return Result{}, err
	}

	block, err := s.simulateWithTracer(group, simulatorTracer, simulatorTracer.result.EvalOverrides)
	if err != nil {
		var verifyError *verify.TxGroupError
		switch {
		case errors.As(err, &verifyError):
			if verifyError.GroupIndex < 0 {
				// This group failed verification, but the problem can't be blamed on a single transaction.
				return Result{}, InvalidRequestError{SimulatorError{err}}
			}
			simulatorTracer.result.TxnGroups[0].FailureMessage = verifyError.Error()
			simulatorTracer.result.TxnGroups[0].FailedAt = TxnPath{uint64(verifyError.GroupIndex)}
		case errors.As(err, &EvalFailureError{}):
			simulatorTracer.result.TxnGroups[0].FailureMessage = err.Error()
			simulatorTracer.result.TxnGroups[0].FailedAt = simulatorTracer.failedAt
		default:
			// error is not related to evaluation
			return Result{}, err
		}
	}

	if simulatorTracer.result.TxnGroups[0].UnnamedResourcesAccessed != nil {
		// Remove private fields for easier test comparison
		simulatorTracer.result.TxnGroups[0].UnnamedResourcesAccessed.removePrivateFields()
		if !simulatorTracer.result.TxnGroups[0].UnnamedResourcesAccessed.HasResources() {
			simulatorTracer.result.TxnGroups[0].UnnamedResourcesAccessed = nil
		}
		for i := range simulatorTracer.result.TxnGroups[0].Txns {
			txnResult := &simulatorTracer.result.TxnGroups[0].Txns[i]
			txnResult.UnnamedResourcesAccessed.removePrivateFields()
			if !txnResult.UnnamedResourcesAccessed.HasResources() {
				// Clean up any unused local resource assignments
				txnResult.UnnamedResourcesAccessed = nil
			}
		}
	}

	simulatorTracer.result.Block = block

	// Update total cost by aggregating individual txn costs
	totalCost := uint64(0)
	for _, txn := range simulatorTracer.result.TxnGroups[0].Txns {
		totalCost += txn.AppBudgetConsumed
	}
	simulatorTracer.result.TxnGroups[0].AppBudgetConsumed = totalCost

	// Set the FixedSigner for each transaction that had a signer change during evaluation
	for i := range simulatorTracer.result.TxnGroups[0].Txns {
		sender := simulatorTracer.result.TxnGroups[0].Txns[i].Txn.Txn.Sender
		inputSigner := simulatorTracer.result.TxnGroups[0].Txns[i].Txn.AuthAddr
		if inputSigner.IsZero() {
			// A zero AuthAddr indicates the sender is the signer
			inputSigner = sender
		}

		actualSigner := simulatorTracer.groups[0][i].SignedTxn.AuthAddr
		if actualSigner.IsZero() {
			// A zero AuthAddr indicates the sender is the signer
			actualSigner = sender
		}

		if inputSigner != actualSigner {
			simulatorTracer.result.TxnGroups[0].Txns[i].FixedSigner = actualSigner
		}
	}

	return *simulatorTracer.result, nil
}
