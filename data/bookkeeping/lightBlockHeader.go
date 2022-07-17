// Copyright (C) 2019-2022 Algorand, Inc.
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

package bookkeeping

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
)

// LightBlockHeader represents a minimal block header. It contains all the necessary fields
// for verifying proofs on transactions.
// In addition, this struct is designed to be used on environments where only SHA256 function exists
type LightBlockHeader struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Seed                committee.Seed       `codec:"s"`
	RoundNumber         basics.Round         `codec:"r"`
	GenesisHash         crypto.Digest        `codec:"gh"`
	Sha256TxnCommitment crypto.GenericDigest `codec:"tc,allocbound=crypto.Sha256Size"`
}

// ToLightBlockHeader creates returns a LightBlockHeader from a given block header
func (bh *BlockHeader) ToLightBlockHeader() LightBlockHeader {
	return LightBlockHeader{
		Seed:                bh.Seed,
		GenesisHash:         bh.GenesisHash,
		RoundNumber:         bh.Round,
		Sha256TxnCommitment: bh.Sha256Commitment[:],
	}
}

// ToBeHashed implements the crypto.Hashable interface
func (bh *LightBlockHeader) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.BlockHeader256, protocol.Encode(bh)
}
