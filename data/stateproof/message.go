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

package stateproof

import (
	"github.com/algorand/go-algorand/crypto"
	cc "github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/protocol"
)

// Message represents the message to be certified.
type Message struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	// Commitment over the sha256 of the block headers in the interval between two compact certificates.
	BlockHeadersCommitment []byte `codec:"b"`
}

// ToBeHashed returns the bytes of the message.
func (m Message) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.CompactCertMessage, protocol.Encode(&m)
}

// IntoStateProofMessageHash returns a hashed representation fitting the compact certificate messages.
func (m Message) IntoStateProofMessageHash() cc.StateProofMessageHash {
	digest := crypto.GenericHashObj(crypto.HashFactory{HashType: cc.StateProofMessageHashType}.NewHash(), m)
	result := cc.StateProofMessageHash{}
	copy(result[:], digest)
	return result
}
