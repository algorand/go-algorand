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

package testing

import (
	"github.com/algorand/go-algorand/data/basics"
)

// MakeAccountData returns a AccountData with non-empty voting fields for online accounts
func MakeAccountData(status basics.Status, algos basics.MicroAlgos) basics.AccountData {
	ad := basics.AccountData{Status: status, MicroAlgos: algos}
	if status == basics.Online {
		ad.VoteFirstValid = 1
		ad.VoteLastValid = 100_000
	}
	return ad
}

// OnlineAccountData converts basics.AccountData to basics.OnlineAccountData.
// Account is expected to be Online otherwise it is cleared out.
// This function is intended for testing purposes only.
func OnlineAccountData(u basics.AccountData) basics.OnlineAccountData {
	if u.Status != basics.Online {
		// if the account is not Online and agreement requests it for some reason, clear it out
		return basics.OnlineAccountData{}
	}

	return basics.OnlineAccountData{
		MicroAlgosWithRewards: u.MicroAlgos,
		VotingData: basics.VotingData{
			VoteID:          u.VoteID,
			SelectionID:     u.SelectionID,
			StateProofID:    u.StateProofID,
			VoteFirstValid:  u.VoteFirstValid,
			VoteLastValid:   u.VoteLastValid,
			VoteKeyDilution: u.VoteKeyDilution,
		},
		IncentiveEligible: u.IncentiveEligible,
		LastProposed:      u.LastProposed,
		LastHeartbeat:     u.LastHeartbeat,
	}
}
