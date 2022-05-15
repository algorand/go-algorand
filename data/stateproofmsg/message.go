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

package stateproofmsg

import (
	"github.com/algorand/go-algorand/crypto"
	sp "github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/protocol"
)

// Message represents the message to be certified.
type Message struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	// Commitment over the sha256 of the block headers in the interval between two state proofs.
	BlockHeadersCommitment []byte `codec:"b,allocbound=crypto.Sha256Size"`
	VotersCommitment       []byte `codec:"v,allocbound=crypto.SumhashDigestSize"`
	LnProvenWeight         uint64 `codec:"P"`
	FirstAttestedRound     uint64 `codec:"f"`
	LastAttestedRound      uint64 `codec:"l"`
}

// ToBeHashed returns the bytes of the message.
func (m Message) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.StateProofMessage, protocol.Encode(&m)
}

// IntoStateProofMessageHash returns a hashed representation fitting the state proof messages.
func (m Message) IntoStateProofMessageHash() sp.MessageHash {
	digest := crypto.GenericHashObj(crypto.HashFactory{HashType: sp.MessageHashType}.NewHash(), m)
	result := sp.MessageHash{}
	copy(result[:], digest)
	return result
}
