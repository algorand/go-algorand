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

package pools

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

// accountDeductions keeps track of an amount that must be subtracted from an account,
// and whether a transaction in the pool closes the account
type accountDeductions struct {
	amount basics.MicroAlgos
	close  bool
}

// pendingTransactions keeps track of transactions and total number of algos that an account has outstanding to be spent
type pendingTransactions struct {
	deductions accountDeductions
	txids      map[transactions.Txid]bool
}

// accountsToPendingTransactions keeps track of all accounts that have pending transactions
type accountsToPendingTransactions map[basics.Address]pendingTransactions

func (algosPendingSpend accountsToPendingTransactions) deductionsWithTransaction(tx transactions.Transaction) (accountDeductions, error) {
	// get the spender's account
	addr := tx.Src()
	pending := algosPendingSpend[addr]

	// cannot close account when that account has pending transactions
	if pending.txids != nil && tx.CloseRemainderTo != (basics.Address{}) {
		return pending.deductions, fmt.Errorf("cannot close account while transactions are pending")
	}

	// ensure the transaction is not already pending spend
	if pending.txids != nil && pending.txids[tx.ID()] {
		return pending.deductions, fmt.Errorf("transaction already pending spend")
	}

	if pending.deductions.close {
		return pending.deductions, fmt.Errorf("transacting with an account scheduled to close")
	}

	// account for the money spent out of the account

	amount, closed, err := tx.SenderDeduction()
	if err != nil {
		return pending.deductions, err
	}

	newPendingSpend := pending.deductions
	newPendingSpend.close = closed

	var overflowed bool
	newPendingSpend.amount, overflowed = basics.OAddA(newPendingSpend.amount, amount)
	// refuse this transaction if overflowed
	if overflowed {
		return newPendingSpend, fmt.Errorf("overflow while accounting for deductions pending spend")
	}

	// return the balance that would be after adding this transaction to the pool
	return newPendingSpend, nil
}

func (algosPendingSpend accountsToPendingTransactions) accountForTransactionDeductions(tx transactions.Transaction, deductions accountDeductions) {
	// get the spender's record, make a new one if doesn't exist
	update, exists := algosPendingSpend[tx.Src()]
	if !exists {
		update.txids = make(map[transactions.Txid]bool)
	}

	// mark this transaction as pending spend, and account for the sender's new balance of to-be-spent deductions
	update.txids[tx.ID()] = true
	update.deductions = deductions
	algosPendingSpend[tx.Src()] = update
}

func (algosPendingSpend accountsToPendingTransactions) remove(tx transactions.Transaction) error {
	// get the spender's account
	addr := tx.Src()
	pendingSpend := algosPendingSpend[addr]

	amount, closed, err := tx.SenderDeduction()
	if err != nil {
		return err
	}

	// subtract the fee and amount of the transaction from their balance of deductions pending spend
	// if the transaction was closing the account, undo the close
	var ot basics.OverflowTracker
	pendingSpend.deductions.amount = ot.SubA(pendingSpend.deductions.amount, amount)
	if closed {
		pendingSpend.deductions.close = false
	}

	// delete the corresponding transaction
	delete(pendingSpend.txids, tx.ID())
	if len(pendingSpend.txids) == 0 {
		// no more transactions left pending, remove this account's record
		delete(algosPendingSpend, addr)
	} else {
		// update this account's record
		algosPendingSpend[addr] = pendingSpend
	}

	// return an error if the operation overflowed, this happens only if there is a bug in accounting transactions
	if ot.Overflowed {
		return fmt.Errorf("overflowed while removing transaction %v that was pending spend", tx)
	}

	return nil
}
