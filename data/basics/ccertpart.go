// Copyright (C) 2019-2021 Algorand, Inc.
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

package basics

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// A Participant corresponds to an account whose AccountData.Status
// is Online, and for which the expected sigRound satisfies
// AccountData.VoteFirstValid <= sigRound <= AccountData.VoteLastValid.
//
// In the Algorand ledger, it is possible for multiple accounts to have
// the same PK.  Thus, the PK is not necessarily unique among Participants.
// However, each account will produce a unique Participant struct, to avoid
// potential DoS attacks where one account claims to have the same VoteID PK
// as another account.
type Participant struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// PK is AccountData.VoteID.
	PK crypto.OneTimeSignatureVerifier `codec:"p"`

	// Weight is AccountData.MicroAlgos.
	Weight uint64 `codec:"w"`

	// KeyDilution is AccountData.KeyDilution() with the protocol for sigRound
	// as expected by the Builder.
	KeyDilution uint64 `codec:"d"`
}

// ToBeHashed implements the crypto.Hashable interface.
func (p Participant) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.CompactCertPart, protocol.Encode(&p)
}
