// Copyright (C) 2019-2023 Algorand, Inc.
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

package merklesignature

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
)

// HashType/ hashSize relate to the type of hash this package uses.
const (
	MerkleSignatureSchemeHashFunction = crypto.Sumhash
	MerkleSignatureSchemeRootSize     = crypto.SumhashDigestSize
	// KeyLifetimeDefault defines the default lifetime of a key in the merkle signature scheme (in rounds).
	KeyLifetimeDefault = 256

	// SchemeSaltVersion is the current salt version of merkleSignature
	SchemeSaltVersion = byte(0)

	// CryptoPrimitivesID is an identification that the Merkle Signature Scheme uses a subset sum hash function
	// and a falcon signature scheme.
	CryptoPrimitivesID = uint16(0)
)

// NoKeysCommitment is a const hash value of the empty MerkleSignature Commitment.
var NoKeysCommitment = Commitment{}

func init() {
	// no keys generated, inner tree of merkle signature scheme is empty.
	o, err := New(KeyLifetimeDefault+1, KeyLifetimeDefault+2, KeyLifetimeDefault)
	if err != nil {
		panic(fmt.Errorf("initializing empty merkle signature scheme failed, err: %w", err))
	}
	if len(o.GetAllKeys()) > 0 {
		panic("mss tree has more than just root.")
	}
	copy(NoKeysCommitment[:], o.GetVerifier().Commitment[:])
}
