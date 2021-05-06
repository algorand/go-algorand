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

package apply

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

// Keyreg applies a KeyRegistration transaction using the Balances interface.
func Keyreg(keyreg transactions.KeyregTxnFields, header transactions.Header, balances Balances, spec transactions.SpecialAddresses, ad *transactions.ApplyData) error {
	if header.Sender == spec.FeeSink {
		return fmt.Errorf("cannot register participation key for fee sink's address %v ", header.Sender)
	}

	// Get the user's balance entry
	record, err := balances.Get(header.Sender, false)
	if err != nil {
		return err
	}

	// non-participatory accounts cannot be brought online (or offline)
	if record.Status == basics.NotParticipating {
		return fmt.Errorf("cannot change online/offline status of non-participating account %v", header.Sender)
	}

	if balances.ConsensusParams().EnableKeyregCoherencyCheck {
		// ensure that the VoteLast is greater or equal to the VoteFirst
		if keyreg.VoteFirst > keyreg.VoteLast {
			return fmt.Errorf("the transaction first voting round need to be less than its last voting round")
		}

		// The trio of [VotePK, SelectionPK, VoteKeyDilution] needs to be all zeros or all non-zero for the transaction to be valid.
		if !((keyreg.VotePK == crypto.OneTimeSignatureVerifier{} && keyreg.SelectionPK == crypto.VRFVerifier{} && keyreg.VoteKeyDilution == 0) ||
			(keyreg.VotePK != crypto.OneTimeSignatureVerifier{} && keyreg.SelectionPK != crypto.VRFVerifier{} && keyreg.VoteKeyDilution != 0)) {
			return fmt.Errorf("the following transaction fields need to be clear/set togather : votekey, selkey, votekd")
		}

		// if it's a going offline transaction
		if keyreg.VoteKeyDilution == 0 {
			// check that we don't have any VoteFirst/VoteLast fields.
			if keyreg.VoteFirst != 0 || keyreg.VoteLast != 0 {
				return fmt.Errorf("on going offline key registration transaction, the vote first and vote last fields should not be set")
			}
		} else {
			// we're going online
			if keyreg.Nonparticipation {
				return fmt.Errorf("on going online transactions, the nonpart field is expected to be clear")
			}
		}
	}

	// Update the registered keys and mark account as online
	// (or, if the voting or selection keys are zero, offline/not-participating)
	record.VoteID = keyreg.VotePK
	record.SelectionID = keyreg.SelectionPK
	if (keyreg.VotePK == crypto.OneTimeSignatureVerifier{} || keyreg.SelectionPK == crypto.VRFVerifier{}) {
		if keyreg.Nonparticipation {
			if balances.ConsensusParams().SupportBecomeNonParticipatingTransactions {
				record.Status = basics.NotParticipating
			} else {
				return fmt.Errorf("transaction tries to mark an account as nonparticipating, but that transaction is not supported")
			}
		} else {
			record.Status = basics.Offline
		}
		record.VoteFirstValid = 0
		record.VoteLastValid = 0
		record.VoteKeyDilution = 0
	} else {
		record.Status = basics.Online
		record.VoteFirstValid = keyreg.VoteFirst
		record.VoteLastValid = keyreg.VoteLast
		record.VoteKeyDilution = keyreg.VoteKeyDilution
	}

	// Write the updated entry
	err = balances.Put(header.Sender, record)
	if err != nil {
		return err
	}

	return nil
}
