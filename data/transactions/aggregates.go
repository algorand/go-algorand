// Copyright (C) 2020 Algorand, Inc.
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

package transactions

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkle"
	"github.com/algorand/go-algorand/protocol"
)

type (
	// A Payset represents a common, unforgeable, consistent, ordered set of SignedTxn objects.
	Payset []SignedTxnInBlock
)

// Commit returns a commitment to the Payset.
//
// If the flat argument is true, the commitment is a hash of the entire payset.
//
// If the flat argument is false, the commitment is the root of a merkle tree
// whose leaves are the Txids in the Payset.  Note that the transaction root
// depends on the order in which the Txids appear, and that Txids do NOT cover
// transaction signatures.
func (payset Payset) Commit(flat bool) crypto.Digest {
	if flat {
		return crypto.HashObj(payset)
	}

	// Merkle (non-flat) mode is used only without SupportSignedTxnInBlock,
	// so it's fine to reach inside the SignedTxnInBlock.
	paysetTxids := make([][]byte, len(payset))
	for i := 0; i < len(payset); i++ {
		txid := payset[i].SignedTxn.ID()
		paysetTxids[i] = append([]byte{}, txid[:]...)
	}

	return merkle.Root(paysetTxids)
}

// ToBeHashed implements the crypto.Hashable interface
func (payset Payset) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.PaysetFlat, protocol.Encode(payset)
}
