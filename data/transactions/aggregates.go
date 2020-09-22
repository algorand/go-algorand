// Copyright (C) 2019-2020 Algorand, Inc.
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
	//msgp:allocbound Payset 100000
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
	return payset.commit(flat, false)
}

// CommitGenesis is like Commit, but with special handling for zero-length
// but non-nil paysets.
func (payset Payset) CommitGenesis(flat bool) crypto.Digest {
	return payset.commit(flat, true)
}

// commit handles the logic for both Commit and CommitGenesis
func (payset Payset) commit(flat bool, genesis bool) crypto.Digest {
	// We used to build up Paysets from a nil slice with `append` during
	// block evaluation, meaning zero-length paysets would remain nil.
	// After we started allocating them up front, we started calling Commit
	// on zero-length but non-nil Paysets. However, we want payset
	// encodings to remain the same with or without this optimization.
	//
	// Additionally, the genesis block commits to a zero-length but non-nil
	// payset (the only block to do so), so we have to let the nil value
	// pass through.
	if !genesis && len(payset) == 0 {
		payset = nil
	}

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
