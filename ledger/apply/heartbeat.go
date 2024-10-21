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

// Heartbeat applies a Heartbeat transaction using the Balances interface.
func Heartbeat(hb transactions.HeartbeatTxnFields, header transactions.Header, balances Balances, provider HdrProvider, round basics.Round) error {
	// Get the account's balance entry
	account, err := balances.Get(hb.HbAddress, false)
	if err != nil {
		return err
	}

	sv := account.VoteID
	if sv.IsEmpty() {
		return fmt.Errorf("heartbeat address %s has no voting keys", hb.HbAddress)
	}
	id := basics.OneTimeIDForRound(header.LastValid, account.VoteKeyDilution)

	hdr, err := provider.BlockHdr(header.FirstValid - 1)
	if err != nil {
		return err
	}
	if hdr.Seed != hb.HbSeed {
		return fmt.Errorf("provided seed %v does not match round %d's seed %v", hb.HbSeed, header.FirstValid-1, hdr.Seed)
	}

	if !sv.Verify(id, hdr.Seed, hb.HbProof) {
		return errors.New("Improper heartbeat")
	}

	account.LastHeartbeat = round

	// Write the updated entry
	err = balances.Put(hb.HbAddress, account)
	if err != nil {
		return err
	}

	return nil
}
