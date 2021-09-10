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

package merklearray

import (
	"hash"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// A Layer of the Merkle tree consists of a dense array of hashes at that
// level of the tree.  Hashes beyond the end of the array (e.g., if the
// number of leaves is not an exact power of 2) are implicitly zero.
//msgp:allocbound Layer -
type Layer []crypto.GenericDigest

// A pair represents an internal node in the Merkle tree.
type pair struct {
	l crypto.GenericDigest
	r crypto.GenericDigest
}

func (p *pair) ToBeHashed() (protocol.HashID, []byte) {
	buf := make([]byte, len(p.l)+len(p.r))
	copy(buf[:], p.l[:])
	copy(buf[len(p.l):], p.r[:])
	return protocol.MerkleArrayNode, buf[:]
}

func (p *pair) Marshal() []byte {

	buf := make([]byte, len(p.l)+len(p.r)+len(protocol.MerkleArrayNode))
	copy(buf[:], protocol.MerkleArrayNode)
	copy(buf[len(protocol.MerkleArrayNode):], p.l[:])
	copy(buf[len(protocol.MerkleArrayNode)+len(p.l):], p.r[:])

	return buf
}

func upWorker(ws *workerState, in Layer, out Layer, h hash.Hash) {
	defer ws.wg.Done()

	ws.started()
	batchSize := uint64(2)

	for {
		off := ws.next(batchSize)
		if off >= ws.maxidx {
			break
		}

		for i := off; i < off+batchSize && i < ws.maxidx; i += 2 {
			var p pair
			p.l = in[i]
			if i+1 < ws.maxidx {
				p.r = in[i+1]
			}

			out[i/2] = crypto.GenereicHashObj(h, &p)
		}

		batchSize += 2
	}
}
