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

package transactions

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

type (
	// A Payset represents a common, unforgeable, consistent, ordered set of SignedTxn objects.
	//msgp:allocbound Payset 100000
	Payset []SignedTxnInBlock

	// A PaysetDigest contains the corresponding Digests of a block's payset
	//msgp:allocbound PaysetDigest 100000
	PaysetDigest []crypto.Digest
)

// CommitFlat returns a commitment to the Payset, as a flat array.
func (payset Payset) CommitFlat() crypto.Digest {
	return payset.commit(false)
}

// CommitGenesis is like Commit, but with special handling for zero-length
// but non-nil paysets.
func (payset Payset) CommitGenesis() crypto.Digest {
	return payset.commit(true)
}

// commit handles the logic for both Commit and CommitGenesis
func (payset Payset) commit(genesis bool) crypto.Digest {
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

	return crypto.HashObj(payset)
}

// ToBeHashed implements the crypto.Hashable interface
func (payset Payset) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.PaysetFlat, protocol.Encode(payset)
}
