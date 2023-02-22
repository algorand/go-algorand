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

package apply

import (
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

func checkSpender(payment transactions.PaymentTxnFields, header transactions.Header, spec transactions.SpecialAddresses, proto config.ConsensusParams) error {
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

// Payment changes the balances according to this transaction.
// The ApplyData argument should reflect the changes made by
// apply().  It may already include changes made by the caller
// (i.e., Transaction.Apply), so apply() must update it rather
// than overwriting it.  For example, Transaction.Apply() may
// have updated ad.SenderRewards, and this function should only
// add to ad.SenderRewards (if needed), but not overwrite it.
func Payment(payment transactions.PaymentTxnFields, header transactions.Header, balances Balances, spec transactions.SpecialAddresses, ad *transactions.ApplyData) error {
	// move tx money
	if !payment.Amount.IsZero() || payment.Receiver != (basics.Address{}) {
		err := balances.Move(header.Sender, payment.Receiver, payment.Amount, &ad.SenderRewards, &ad.ReceiverRewards)
		if err != nil {
			return err
		}
	}

	if payment.CloseRemainderTo != (basics.Address{}) {
		rec, err := balances.Get(header.Sender, true)
		if err != nil {
			return err
		}

		closeAmount := rec.MicroAlgos
		ad.ClosingAmount = closeAmount
		err = balances.Move(header.Sender, payment.CloseRemainderTo, closeAmount, &ad.SenderRewards, &ad.CloseRewards)
		if err != nil {
			return err
		}

		// Confirm that we have no balance left
		rec, err = balances.Get(header.Sender, true)
		if err != nil {
			return err
		}
		if !rec.MicroAlgos.IsZero() {
			return fmt.Errorf("balance %d still not zero after CloseRemainderTo", rec.MicroAlgos.Raw)
		}

		// Confirm that there is no asset-related state in the account
		totalAssets := rec.TotalAssets
		if totalAssets > 0 {
			return fmt.Errorf("cannot close: %d outstanding assets", totalAssets)
		}

		totalAssetParams := rec.TotalAssetParams
		if totalAssetParams > 0 {
			// This should be impossible because every asset created
			// by an account (in AssetParams) must also appear in Assets,
			// which we checked above.
			return fmt.Errorf("cannot close: %d outstanding created assets", totalAssetParams)
		}

		// Confirm that there is no application-related state remaining
		totalAppLocalStates := rec.TotalAppLocalStates
		if totalAppLocalStates > 0 {
			return fmt.Errorf("cannot close: %d outstanding applications opted in. Please opt out or clear them", totalAppLocalStates)
		}

		// Confirm that there is no box-related state in the account
		if rec.TotalBoxes > 0 {
			return fmt.Errorf("cannot close: %d outstanding boxes", rec.TotalBoxes)
		}
		if rec.TotalBoxBytes > 0 {
			// This should be impossible because every box byte comes from the existence of a box.
			return fmt.Errorf("cannot close: %d outstanding box bytes", rec.TotalBoxBytes)
		}

		// Can't have created apps remaining either
		totalAppParams := rec.TotalAppParams
		if totalAppParams > 0 {
			return fmt.Errorf("cannot close: %d outstanding created applications", totalAppParams)
		}

		// Clear out entire account record, to allow the DB to GC it
		err = balances.CloseAccount(header.Sender)
		if err != nil {
			return err
		}
	}

	return nil
}
