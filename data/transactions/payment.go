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

package transactions

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
)

// PaymentTxnFields captures the fields used by payment transactions.
type PaymentTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Receiver basics.Address    `codec:"rcv"`
	Amount   basics.MicroAlgos `codec:"amt"`

	// When CloseRemainderTo is set, it indicates that the
	// transaction is requesting that the account should be
	// closed, and all remaining funds be transferred to this
	// address.
	CloseRemainderTo basics.Address `codec:"close"`
}

func (payment PaymentTxnFields) checkSpender(header Header, spec SpecialAddresses, proto config.ConsensusParams) error {
	if header.Sender == payment.CloseRemainderTo {
		return fmt.Errorf("transaction cannot close account to its sender %v", header.Sender)
	}

	// the FeeSink account may only spend to the IncentivePool
	if header.Sender == spec.FeeSink {
		if payment.Receiver != spec.RewardsPool {
			return fmt.Errorf("cannot spend from fee sink's address %v to non incentive pool address %v", header.Sender, payment.Receiver)
		}
		if payment.CloseRemainderTo != (basics.Address{}) {
			return fmt.Errorf("cannot close fee sink %v to %v", header.Sender, payment.CloseRemainderTo)
		}
	}
	return nil
}

// Apply changes the balances according to this transaction.
// The ApplyData argument should reflect the changes made by
// apply().  It may already include changes made by the caller
// (i.e., Transaction.Apply), so apply() must update it rather
// than overwriting it.  For example, Transaction.Apply() may
// have updated ad.SenderRewards, and this function should only
// add to ad.SenderRewards (if needed), but not overwrite it.
func (payment PaymentTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	// move tx money
	if !payment.Amount.IsZero() || payment.Receiver != (basics.Address{}) {
		err := balances.Move(header.Sender, payment.Receiver, payment.Amount, &ad.SenderRewards, &ad.ReceiverRewards)
		if err != nil {
			return err
		}
	}

	if payment.CloseRemainderTo != (basics.Address{}) {
		rec, err := balances.Get(header.Sender)
		if err != nil {
			return err
		}

		closeAmount := rec.AccountData.MicroAlgos
		ad.ClosingAmount = closeAmount
		err = balances.Move(header.Sender, payment.CloseRemainderTo, closeAmount, &ad.SenderRewards, &ad.CloseRewards)
		if err != nil {
			return err
		}

		// Confirm that we have no balance left
		rec, err = balances.Get(header.Sender)
		if !rec.AccountData.MicroAlgos.IsZero() {
			return fmt.Errorf("balance %d still not zero after CloseRemainderTo", rec.AccountData.MicroAlgos.Raw)
		}

		// Clear out entire account record, to allow the DB to GC it
		rec.AccountData = basics.AccountData{}
		err = balances.Put(rec)
		if err != nil {
			return err
		}
	}

	return nil
}
