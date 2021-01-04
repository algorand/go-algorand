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

package committee

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// A Selector deterministically defines a cryptographic sortition committee. It
// contains both the input to the sortition VRF and the size of the sortition
// committee.
type Selector interface {
	// The hash of a struct which implements Selector is used as the input
	// to the VRF.
	crypto.Hashable

	// CommitteeSize returns the size of the committee determined by this
	// Selector.
	CommitteeSize(config.ConsensusParams) uint64
}

// BalanceRecord pairs an account's address with its associated data.
//
// This struct is used to decouple LedgerReader.AccountData from basics.BalanceRecord.
//msgp:ignore BalanceRecord
type BalanceRecord struct {
	basics.AccountData
	Addr basics.Address
}

// Membership encodes the parameters used to verify membership in a committee.
type Membership struct {
	Record     BalanceRecord
	Selector   Selector
	TotalMoney basics.MicroAlgos
}

// A Seed contains cryptographic entropy which can be used to determine a
// committee.
type Seed [32]byte

// ToBeHashed implements the crypto.Hashable interface
func (s Seed) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Seed, s[:]
}
