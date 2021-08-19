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
type Layer []Digest

// A pair represents an internal node in the Merkle tree.
type pair struct {
	l Digest
	r Digest
}

func (p *pair) ToBeHashed() (protocol.HashID, []byte) {
	var buf [2 * crypto.DigestSize]byte
	copy(buf[:crypto.DigestSize], p.l[:])
	copy(buf[crypto.DigestSize:], p.r[:])
	return protocol.MerkleArrayNode, buf[:]
}

// Hash implements an optimized version of crypto.HashObj(p).
func (p *pair) Hash() crypto.Digest {
	return crypto.Hash(p.Marshal())
}

func (p *pair) Marshal() []byte {
	var buf [len(protocol.MerkleArrayNode) + 2*crypto.DigestSize]byte
	s := buf[:0]
	s = append(s, protocol.MerkleArrayNode...)
	s = append(s, p.l[:]...)
	return append(s, p.r[:]...)
}

func upWorker(ws *workerState, in Layer, out Layer, h hash.Hash) {
	ws.started()
	batchSize := uint64(2)

	h.Reset()
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

			h.Write(p.Marshal())
			out[i/2] = h.Sum(nil)
			h.Reset()
		}

		batchSize += 2
	}

	ws.done()
}

// up takes a Layer representing some level in the tree,
// and returns the next-higher level in the tree,
// represented as a Layer.
func (t *Tree) up() Layer {
	l := t.topLayer()
	n := len(l)
	res := make(Layer, (uint64(n)+1)/2)

	ws := newWorkerState(uint64(n))
	for ws.nextWorker() {
		// no need to inspect error here -
		// the factory should've been used to generate hash func in the first layer build
		h, _ := t.Hash.NewHash()
		go upWorker(ws, l, res, h)
	}
	ws.wait()

	return res
}
