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

package merklesignature

import (
	"fmt"
	"github.com/algorand/go-algorand/crypto"
)

// HashType/ hashSize relate to the type of hash this package uses.
const (
	MerkleSignatureSchemeHashFunction = crypto.Sumhash
	MerkleSignatureSchemeRootSize     = crypto.SumhashDigestSize
)

// NoKeysCommitment is the hash of the empty MerkleSignature Commitment.
// When fetching an online account from the ledger, the code must ensure that the account's commitment is not an array of zeros.
// If it is, we replace that commitment with the empty NoKeysCommitment (a specific hash value).
var NoKeysCommitment = Commitment{}

func init() {
	// no keys generated, inner tree of merkle siganture scheme is empty.
	o, err := New(KeyLifetimeDefault+1, KeyLifetimeDefault+2, KeyLifetimeDefault)
	if err != nil {
		panic(fmt.Errorf("initializing empty merkle signature scheme failed, err: %w", err))
	}
	if len(o.GetAllKeys()) > 0 {
		panic("mss tree has more than just root.")
	}
	copy(NoKeysCommitment[:], o.GetVerifier().Commitment[:])
}
