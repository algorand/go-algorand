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

package transactions

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
)

// HeartbeatTxnFields captures the fields used for an account to prove it is
// online (really, it proves that an entity with the account's part keys is able
// to submit transactions, so it should be able to propose/vote.)
type HeartbeatTxnFields struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// HbAddress is the account this txn is proving onlineness for.
	HbAddress basics.Address `codec:"a"`

	// HbProof is a signature using HeartbeatAddress's partkey, thereby showing it is online.
	HbProof crypto.HeartbeatProof `codec:"prf"`

	// The final three fields are included to allow early, concurrent check of
	// the HbProof.

	// HbSeed must be the block seed for the this transaction's firstValid
	// block. It is the message that must be signed with HbAddress's part key.
	HbSeed committee.Seed `codec:"sd"`

	// HbVoteID must match the HbAddress account's current VoteID.
	HbVoteID crypto.OneTimeSignatureVerifier `codec:"vid"`

	// HbKeyDilution must match HbAddress account's current KeyDilution.
	HbKeyDilution uint64 `codec:"kd"`
}

// wellFormed performs some stateless checks on the Heartbeat transaction
func (hb HeartbeatTxnFields) wellFormed(header Header, proto config.ConsensusParams) error {
	// If this is a free/cheap heartbeat, it must be very simple.
	if header.Fee.Raw < proto.MinTxnFee && header.Group.IsZero() {
		kind := "free"
		if header.Fee.Raw > 0 {
			kind = "cheap"
		}

		if len(header.Note) > 0 {
			return fmt.Errorf("tx.Note is set in %s heartbeat", kind)
		}
		if header.Lease != [32]byte{} {
			return fmt.Errorf("tx.Lease is set in %s heartbeat", kind)
		}
		if !header.RekeyTo.IsZero() {
			return fmt.Errorf("tx.RekeyTo is set in %s heartbeat", kind)
		}
	}

	if (hb.HbProof == crypto.HeartbeatProof{}) {
		return errors.New("tx.HbProof is empty")
	}
	if (hb.HbSeed == committee.Seed{}) {
		return errors.New("tx.HbSeed is empty")
	}
	if hb.HbVoteID.IsEmpty() {
		return errors.New("tx.HbVoteID is empty")
	}
	if hb.HbKeyDilution == 0 {
		return errors.New("tx.HbKeyDilution is zero")
	}
	return nil
}
