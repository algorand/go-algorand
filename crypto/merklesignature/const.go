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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
)

// HashType/ hashSize relate to the type of hash this package uses.
const (
	MerkleSignatureSchemeHashFunction = crypto.Sumhash
	MerkleSignatureSchemeRootSize     = crypto.SumhashDigestSize
)

// MssNoKeysCommitment is the hash of the empty MerkleSignature Commitment.
// When fetching an online account from the ledger, the code must ensure that the account's commitment is not an array of zeros.
// If it is, we replace that commitment with the empty MssNoKeysCommitment (a specific hash value).
var MssNoKeysCommitment = Commitment{}

func init() {
	// no keys generated, inner tree of merkle siganture scheme is empty.
	t, err := merklearray.BuildVectorCommitmentTree(&committablePublicKeyArray{nil, 0, 0}, crypto.HashFactory{HashType: MerkleSignatureSchemeHashFunction})
	if err != nil {
		panic("initializing empty merkle signature scheme failed")
	}

	if len(t.Levels) > 1 {
		panic("mss tree has more than just root.")
	}
	copy(MssNoKeysCommitment[:], t.Root()[:])
}
