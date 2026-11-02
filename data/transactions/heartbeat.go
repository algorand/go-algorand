// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	// HbChallengeDiscount requests the challenge fee discount: when set, the
	// required fee is reduced by one min fee. It is optional even for a
	// challenged account (an account willing to pay the normal fee can leave it
	// off), so it is a request, not an assertion. apply verifies HbAddress is
	// actually under challenge before granting it. The flag is only allowed
	// once transaction size pricing is enabled (proto.TxnSizePricingEnabled());
	// it makes sense to think in terms of transaction fields changing fees
	// now, so it needs no separate consensus flag. Before then, the discount
	// was inferred from an underpaid singleton heartbeat instead (see
	// wellFormed and apply).
	HbChallengeDiscount bool `codec:"c"`
}

// wellFormed performs some stateless checks on the Heartbeat transaction
func (hb HeartbeatTxnFields) wellFormed(header Header, proto config.ConsensusParams) error {
	// A heartbeat that claims the challenge discount must be very simple, so it
	// can't smuggle in other work at a reduced fee. kind describes how the
	// discount is being claimed (only for error messages); an empty kind means
	// no discount, so no restrictions apply.
	var kind string
	if proto.TxnSizePricingEnabled() {
		// The discount is claimed explicitly with HbChallengeDiscount.
		if hb.HbChallengeDiscount {
			kind = "discounted"
		}
	} else {
		// Before the explicit-discount rule, HbChallengeDiscount has no meaning
		// and must not be set, so it can't alter a heartbeat's encoding under the
		// old rules.
		if hb.HbChallengeDiscount {
			return errors.New("tx.HbChallengeDiscount set before it is allowed")
		}
		// The discount is instead inferred: a singleton heartbeat that underpays
		// the normal fee is claiming it.
		factor := basics.AddSaturate(header.FeeContribution(proto), 1e6)
		// Fee a normal (non-cheap) heartbeat owes, computed the same way as a
		// top-level group: no cost multiplier (1e6), no prior residue. FeeForUsage saturates.
		requiredFee, _, _ := proto.MinFee().FeeForUsage(factor, 1e6, 0)
		if header.Fee.LessThan(requiredFee) && header.Group.IsZero() {
			kind = "free"
			if header.Fee.Raw > 0 {
				kind = "cheap"
			}
		}
	}

	if kind != "" {
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
