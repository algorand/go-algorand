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
func Heartbeat(hb transactions.HeartbeatTxnFields, header transactions.Header, balances Balances, provider hdrProvider, round basics.Round) error {
	// Get the account's balance entry
	account, err := balances.Get(hb.HbAddress, false)
	if err != nil {
		return err
	}

	// In txnGroupBatchPrep, we do not charge for singleton (Group.IsZero)
	// heartbeats. But we only _want_ to allow free heartbeats if the account is
	// under challenge. If this is an underpaid singleton heartbeat, reject it
	// unless the account is under challenge.

	proto := balances.ConsensusParams()
	if header.Fee.Raw < proto.MinTxnFee && header.Group.IsZero() {
		kind := "free"
		if header.Fee.Raw > 0 {
			kind = "cheap"
		}

		if account.Status != basics.Online {
			return fmt.Errorf("%s heartbeat is not allowed for %s %+v", kind, account.Status, hb.HbAddress)
		}
		if !account.IncentiveEligible {
			return fmt.Errorf("%s heartbeat is not allowed when not IncentiveEligible %+v", kind, hb.HbAddress)
		}
		ch := FindChallenge(proto.Payouts, round, provider, ChRisky)
		if ch.IsZero() {
			return fmt.Errorf("%s heartbeat for %s is not allowed with no challenge", kind, hb.HbAddress)
		}
		if !ch.Failed(hb.HbAddress, account.LastSeen()) {
			return fmt.Errorf("%s heartbeat for %s is not challenged by %+v", kind, hb.HbAddress, ch)
		}
	}

	// Note the contrast with agreement. We require the account's _current_
	// partkey be used to sign the heartbeat. This is required because we can
	// only look 320 rounds back for voting information. If a heartbeat was
	// delayed a few rounds (even 1), we could not ask "what partkey was in
	// effect at firstValid-320?"  Using the current keys means that an account
	// that changes keys would invalidate any heartbeats it has already sent out
	// (that haven't been evaluated yet). Maybe more importantly, after going
	// offline, an account can no longer heartbeat, since it has no _current_
	// keys. Yet it is still expected to vote for 320 rounds.  Therefore,
	// challenges do not apply to accounts that are offline (even if they should
	// still be voting).

	// heartbeats sign a message consisting of the BlockSeed of the first-valid
	// round, to discourage unsavory behaviour like presigning a bunch of
	// heartbeats for later use keeping an unavailable account online.
	hdr, err := provider.BlockHdr(header.FirstValid)
	if err != nil {
		return err
	}
	if hdr.Seed != hb.HbSeed {
		return fmt.Errorf("provided seed %v does not match round %d's seed %v",
			hb.HbSeed, header.FirstValid, hdr.Seed)
	}
	if account.VotingData.VoteID != hb.HbVoteID {
		return fmt.Errorf("provided voter ID %v does not match %v's voter ID %v",
			hb.HbVoteID, hb.HbAddress, account.VotingData.VoteID)
	}
	if account.VotingData.VoteKeyDilution != hb.HbKeyDilution {
		return fmt.Errorf("provided key dilution %d does not match %v's key dilution %d",
			hb.HbKeyDilution, hb.HbAddress, account.VotingData.VoteKeyDilution)
	}

	account.LastHeartbeat = round

	// Write the updated entry
	err = balances.Put(hb.HbAddress, account)
	if err != nil {
		return err
	}

	return nil
}
