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

package ledgercore

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

// ErrNoSpace indicates insufficient space for transaction in block
var ErrNoSpace = errors.New("block does not have space for transaction")

// Verify each custom error type implements the error interface, and declare which are pointer/value receivers.
var (
	_ error = (*TxnNotWellFormedError)(nil)
	_ error = (*TransactionInLedgerError)(nil)
	_ error = (*LeaseInLedgerError)(nil)
	_ error = BlockInLedgerError{}
	_ error = ErrNoEntry{}
	_ error = ErrNonSequentialBlockEval{}
	_ error = (*TxGroupMalformedError)(nil)
)

// TxnNotWellFormedError indicates a transaction was not well-formed when evaluated by the BlockEvaluator
//
//msgp:ignore TxnNotWellFormedError
type TxnNotWellFormedError string

func (err *TxnNotWellFormedError) Error() string {
	return string(*err)
}

// TransactionInLedgerError is returned when a transaction cannot be added because it has already been committed, either
// to the blockchain's ledger or to the history of changes tracked by a BlockEvaluator.
type TransactionInLedgerError struct {
	Txid             transactions.Txid
	InBlockEvaluator bool
}

// Error satisfies builtin interface `error`
func (tile *TransactionInLedgerError) Error() string {
	return fmt.Sprintf("transaction already in ledger: %v", tile.Txid)
}

// LeaseInLedgerError is returned when a transaction cannot be added because it has a lease that already being used in the relevant rounds
type LeaseInLedgerError struct {
	txid             transactions.Txid
	lease            Txlease
	InBlockEvaluator bool
}

// MakeLeaseInLedgerError builds a LeaseInLedgerError object
func MakeLeaseInLedgerError(txid transactions.Txid, lease Txlease, inBlockEvaluator bool) *LeaseInLedgerError {
	return &LeaseInLedgerError{
		txid:             txid,
		lease:            lease,
		InBlockEvaluator: inBlockEvaluator,
	}
}

// Error implements the error interface for the LeaseInLedgerError stuct
func (lile *LeaseInLedgerError) Error() string {
	// format the lease as address.
	leaseValue := basics.Address(lile.lease.Lease)
	return fmt.Sprintf("transaction %v using an overlapping lease (sender, lease):(%s, %s)", lile.txid, lile.lease.Sender.String(), leaseValue.String())
}

// BlockInLedgerError is returned when a block cannot be added because it has already been done
type BlockInLedgerError struct {
	LastRound basics.Round
	NextRound basics.Round
}

// Error satisfies builtin interface `error`
func (bile BlockInLedgerError) Error() string {
	return fmt.Sprintf("block number already in ledger: block %d < next Round %d", bile.LastRound, bile.NextRound)
}

// ErrNoEntry is used to indicate that a block is not present in the ledger.
type ErrNoEntry struct {
	Round     basics.Round
	Latest    basics.Round
	Committed basics.Round
}

// Error satisfies builtin interface `error`
func (err ErrNoEntry) Error() string {
	return fmt.Sprintf("ledger does not have entry %d (latest %d, committed %d)", err.Round, err.Latest, err.Committed)
}

// ErrNonSequentialBlockEval provides feedback when the evaluator cannot be created for
// stale/future rounds.
type ErrNonSequentialBlockEval struct {
	EvaluatorRound basics.Round // EvaluatorRound is the round the evaluator was created for
	LatestRound    basics.Round // LatestRound is the latest round available on disk
}

// Error satisfies builtin interface `error`
func (err ErrNonSequentialBlockEval) Error() string {
	return fmt.Sprintf("block evaluation for round %d requires sequential evaluation while the latest round is %d", err.EvaluatorRound, err.LatestRound)
}

// TxGroupMalformedErrorReasonCode is a reason code for TxGroupMalformed
//
//msgp:ignore TxGroupMalformedErrorReasonCode
type TxGroupMalformedErrorReasonCode int

const (
	// TxGroupMalformedErrorReasonGeneric is a generic (not specific) reason code
	TxGroupMalformedErrorReasonGeneric TxGroupMalformedErrorReasonCode = iota
	// TxGroupMalformedErrorReasonExceedMaxSize indicates too large txgroup
	TxGroupMalformedErrorReasonExceedMaxSize
	// TxGroupMalformedErrorReasonInconsistentGroupID indicates different group IDs in a txgroup
	TxGroupMalformedErrorReasonInconsistentGroupID
	// TxGroupMalformedErrorReasonEmptyGroupID is for empty group ID but multiple transactions in a txgroup
	TxGroupMalformedErrorReasonEmptyGroupID
	// TxGroupMalformedErrorReasonIncompleteGroup indicates expected group ID does not match to provided
	TxGroupMalformedErrorReasonIncompleteGroup
)

// TxGroupMalformedError indicates txgroup has group ID problems or too large
type TxGroupMalformedError struct {
	Msg    string
	Reason TxGroupMalformedErrorReasonCode
}

func (e *TxGroupMalformedError) Error() string {
	return e.Msg
}
