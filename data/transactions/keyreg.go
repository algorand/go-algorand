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

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

// KeyregTxnFields captures the fields used for key registration transactions.
type KeyregTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	VotePK          crypto.OneTimeSignatureVerifier `codec:"votekey"`
	SelectionPK     crypto.VRFVerifier              `codec:"selkey"`
	VoteFirst       basics.Round                    `codec:"votefst"`
	VoteLast        basics.Round                    `codec:"votelst"`
	VoteKeyDilution uint64                          `codec:"votekd"`
}

// Apply changes the balances according to this transaction.
func (keyreg KeyregTxnFields) apply(header Header, balances Balances, spec SpecialAddresses, ad *ApplyData) error {
	if header.Sender == spec.FeeSink {
		return fmt.Errorf("cannot register participation key for fee sink's address %v ", header.Sender)
	}

	// Get the user's balance entry
	record, err := balances.Get(header.Sender)
	if err != nil {
		return err
	}

	// non-participatory accounts cannot be brought online (or offline)
	if record.Status == basics.NotParticipating {
		return fmt.Errorf("cannot change online/offline status of non-participating account %v", header.Sender)
	}

	// Update the registered keys and mark account as online (or, if the voting or selection keys are zero, offline)
	record.VoteID = keyreg.VotePK
	record.SelectionID = keyreg.SelectionPK
	if (keyreg.VotePK == crypto.OneTimeSignatureVerifier{} || keyreg.SelectionPK == crypto.VRFVerifier{}) {
		record.Status = basics.Offline
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
	err = balances.Put(record)
	if err != nil {
		return err
	}

	return nil
}
