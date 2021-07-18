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

package merklekeystore

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
)

// Verifier Is a way to verify a Signature produced by merklekeystore.Signer.
// it also serves as a commit over all keys contained in the merklekeystore.Signer.
type Verifier struct {
	root       crypto.Digest `codec:"r"`
	startRound uint64
	endRound   uint64
}

// Verify receives a signature over a specific crypto.Hashable object, and makes certain the signature is correct.
func (v *Verifier) Verify(obj crypto.Hashable, sig Signature) error {
	isInTree := merklearray.Verify(v.root, map[uint64]crypto.Digest{sig.pos: crypto.HashObj(sig.VerifyingKey)}, sig.Proof)
	if isInTree != nil {
		return isInTree
	}
	return sig.VerifyingKey.GetVerifier().Verify(obj, sig.ByteSignature)
}
