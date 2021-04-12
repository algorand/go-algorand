// Copyright (C) 2019-2021 Algorand, Inc.
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
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

// TransactionInLedgerError is returned when a transaction cannot be added because it has already been done
type TransactionInLedgerError struct {
	Txid transactions.Txid
}

// Error satisfies builtin interface `error`
func (tile TransactionInLedgerError) Error() string {
	return fmt.Sprintf("transaction already in ledger: %v", tile.Txid)
}

// LeaseInLedgerError is returned when a transaction cannot be added because it has a lease that already being used in the relavant rounds
type LeaseInLedgerError struct {
	txid  transactions.Txid
	lease Txlease
}

// MakeLeaseInLedgerError builds a LeaseInLedgerError object
func MakeLeaseInLedgerError(txid transactions.Txid, lease Txlease) *LeaseInLedgerError {
	return &LeaseInLedgerError{
		txid:  txid,
		lease: lease,
	}
}

// Error implements the error interface for the LeaseInLedgerError stuct
func (lile *LeaseInLedgerError) Error() string {
	// format the lease as address.
	addr := basics.Address(lile.lease.Lease)
	return fmt.Sprintf("transaction %v using an overlapping lease %s", lile.txid, addr.String())
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

// LogicEvalError indicates TEAL evaluation failure
type LogicEvalError struct {
	Err error
}

// Error satisfies builtin interface `error`
func (err LogicEvalError) Error() string {
	return fmt.Sprintf("logic eval error: %v", err.Err)
}
