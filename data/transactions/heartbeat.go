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

package transactions

import (
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
