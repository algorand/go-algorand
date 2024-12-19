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

package ledgercore

import (
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
)

// An OnlineAccount corresponds to an account whose AccountData.Status
// is Online. This is used for a Merkle tree commitment of online
// accounts, which is subsequently used to validate participants for
// a state proof.
type OnlineAccount struct {
	// These are a subset of the fields from the corresponding AccountData.
	Address                 basics.Address
	MicroAlgos              basics.MicroAlgos
	RewardsBase             uint64
	NormalizedOnlineBalance uint64
	VoteFirstValid          basics.Round
	VoteLastValid           basics.Round
	StateProofID            merklesignature.Commitment
}
