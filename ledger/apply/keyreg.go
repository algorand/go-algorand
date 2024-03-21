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

package apply

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

var errKeyregGoingOnlineExpiredParticipationKey = errors.New("transaction tries to mark an account as online with last voting round in the past")
var errKeyregGoingOnlineFirstVotingInFuture = errors.New("transaction tries to mark an account as online with first voting round beyond the next voting round")

// Keyreg applies a KeyRegistration transaction using the Balances interface.
func Keyreg(keyreg transactions.KeyregTxnFields, header transactions.Header, balances Balances, spec transactions.SpecialAddresses, ad *transactions.ApplyData, round basics.Round) error {
	if header.Sender == spec.FeeSink {
		return fmt.Errorf("cannot register participation key for fee sink's address %v", header.Sender)
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

	params := balances.ConsensusParams()

	// Update the registered keys and mark account as online
	// (or, if the voting or selection keys are zero, offline/not-participating)
	record.VoteID = keyreg.VotePK
	record.SelectionID = keyreg.SelectionPK
	if params.EnableStateProofKeyregCheck {
		record.StateProofID = keyreg.StateProofPK
	}
	if keyreg.VotePK.IsEmpty() || keyreg.SelectionPK.IsEmpty() {
		if keyreg.Nonparticipation {
			if params.SupportBecomeNonParticipatingTransactions {
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
		// IncentiveEligible is not reset, because the account has gracefully
		// gone offline. They should be able to get back online without paying again.
	} else {
		if params.EnableKeyregCoherencyCheck {
			if keyreg.VoteLast <= round {
				return errKeyregGoingOnlineExpiredParticipationKey
			}
			if keyreg.VoteFirst > round+1 {
				return errKeyregGoingOnlineFirstVotingInFuture
			}
		}
		record.Status = basics.Online
		if params.Payouts.Enabled {
			record.LastHeartbeat = header.FirstValid
		}
		record.VoteFirstValid = keyreg.VoteFirst
		record.VoteLastValid = keyreg.VoteLast
		record.VoteKeyDilution = keyreg.VoteKeyDilution
		if header.Fee.Raw >= params.Payouts.GoOnlineFee && params.Payouts.Enabled {
			record.IncentiveEligible = true
		}
	}

	// Write the updated entry
	err = balances.Put(header.Sender, record)
	if err != nil {
		return err
	}

	return nil
}
