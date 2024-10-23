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

	// Note the contrast with agreement. We are using the account's _current_
	// partkey to verify the heartbeat. This is required because we can only
	// look 320 rounds back for voting information. If a heartbeat was delayed a
	// few rounds (even 1), we could not ask "what partkey was in effect at
	// firstValid-320?"  Using the current keys means that an account that
	// changes keys would invalidate any heartbeats it has already sent out
	// (that haven't been evaluated yet). Maybe more importantly, after going
	// offline, an account can no longer heartbeat, since it has no _current_
	// keys. Yet it is still expected to vote for 320 rounds.  Therefore,
	// challenges do not apply to accounts that are offline (even if they should
	// still be voting).

	// Conjure up an OnlineAccountData from current state, for convenience of
	// oad.KeyDilution().
	oad := basics.OnlineAccountData{
		VotingData: account.VotingData,
	}

	sv := oad.VoteID
	if sv.IsEmpty() {
		return fmt.Errorf("heartbeat address %s has no voting keys", hb.HbAddress)
	}
	kd := oad.KeyDilution(balances.ConsensusParams())

	// heartbeats are expected to sign with the partkey for their last-valid round
	id := basics.OneTimeIDForRound(header.LastValid, kd)

	// heartbeats sign a message consisting of the BlockSeed of the round before
	// first-valid, to discourage unsavory behaviour like presigning a bunch of
	// heartbeats for later use keeping an unavailable account online.
	hdr, err := provider.BlockHdr(header.FirstValid - 1)
	if err != nil {
		return err
	}
	if hdr.Seed != hb.HbSeed {
		return fmt.Errorf("provided seed %v does not match round %d's seed %v", hb.HbSeed, header.FirstValid-1, hdr.Seed)
	}

	if !sv.Verify(id, hdr.Seed, hb.HbProof) {
		return fmt.Errorf("heartbeat failed verification with VoteID %v", sv)
	}

	account.LastHeartbeat = round

	// Write the updated entry
	err = balances.Put(hb.HbAddress, account)
	if err != nil {
		return err
	}

	return nil
}
