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

package bookkeeping

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// TxnMerkleTree returns a cryptographic commitment to the transactions in the
// block, along with their ApplyData, as a Merkle tree.  This allows the
// caller to either extract the root hash (for inclusion in the block
// header), or to generate proofs of membership for transactions that are
// in this block.
func (block Block) TxnMerkleTree() (*merklearray.Tree, error) {
	return merklearray.Build(&txnMerkleArray{block: block})
}

// txnMerkleArray is a representation of the transactions in this block,
// along with their ApplyData, as an array for the merklearray package.
type txnMerkleArray struct {
	block Block
}

// Length implements the merklearray.Array interface.
func (tma *txnMerkleArray) Length() uint64 {
	return uint64(len(tma.block.Payset))
}

// Get implements the merklearray.Array interface.
func (tma *txnMerkleArray) GetHash(pos uint64) (crypto.Digest, error) {
	if pos >= uint64(len(tma.block.Payset)) {
		return crypto.Digest{}, fmt.Errorf("txnMerkleArray.Get(%d): out of bounds, payset size %d", pos, len(tma.block.Payset))
	}

	var elem txnMerkleElem
	elem.stib = tma.block.Payset[pos]

	stxn, _, err := tma.block.DecodeSignedTxn(elem.stib)
	if err != nil {
		return crypto.Digest{}, err
	}
	elem.txn = stxn.Txn

	return elem.Hash(), nil
}

// txnMerkleElem represents a leaf in the Merkle tree of all transactions
// in a block.
type txnMerkleElem struct {
	txn  transactions.Transaction
	stib transactions.SignedTxnInBlock
}

// ToBeHashed implements the crypto.Hashable interface.
func (tme *txnMerkleElem) ToBeHashed() (protocol.HashID, []byte) {
	// The leaf contains two hashes: the transaction ID (hash of the
	// transaction itself), and the hash of the entire SignedTxnInBlock.
	txid := tme.txn.ID()
	stib := crypto.HashObj(&tme.stib)

	var buf [2 * crypto.DigestSize]byte
	copy(buf[:crypto.DigestSize], txid[:])
	copy(buf[crypto.DigestSize:], stib[:])

	return protocol.TxnMerkleLeaf, buf[:]
}

// Hash implements an optimized version of crypto.HashObj(tme).
func (tme *txnMerkleElem) Hash() crypto.Digest {
	txid := tme.txn.ID()
	stib := tme.stib.Hash()

	var buf [len(protocol.TxnMerkleLeaf) + 2*crypto.DigestSize]byte
	s := buf[:0]
	s = append(s, protocol.TxnMerkleLeaf...)
	s = append(s, txid[:]...)
	s = append(s, stib[:]...)
	return crypto.Hash(s)
}
