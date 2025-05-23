// Copyright (C) 2019-2025 Algorand, Inc.
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
// block, along with their ApplyData, as a Merkle tree using SHA-512/256.  This allows the
// caller to either extract the root hash (for inclusion in the block
// header), or to generate proofs of membership for transactions that are
// in this block.
func (block Block) TxnMerkleTree() (*merklearray.Tree, error) {
	return merklearray.Build(&txnMerkleArray{block: block, hashType: crypto.Sha512_256}, crypto.HashFactory{HashType: crypto.Sha512_256})
}

// TxnMerkleTreeSHA256 returns a cryptographic commitment to the transactions in the
// block, along with their ApplyData, as a Merkle tree vector commitment, using SHA-256. This allows the
// caller to either extract the root hash (for inclusion in the block
// header), or to generate proofs of membership for transactions that are
// in this block.
func (block Block) TxnMerkleTreeSHA256() (*merklearray.Tree, error) {
	return merklearray.BuildVectorCommitmentTree(&txnMerkleArray{block: block, hashType: crypto.Sha256}, crypto.HashFactory{HashType: crypto.Sha256})
}

// TxnMerkleTreeSHA512 returns a cryptographic commitment to the transactions in the
// block, along with their ApplyData, as a Merkle tree vector commitment, using SHA-512. This allows the
// caller to either extract the root hash (for inclusion in the block
// header), or to generate proofs of membership for transactions that are
// in this block.
func (block Block) TxnMerkleTreeSHA512() (*merklearray.Tree, error) {
	return merklearray.BuildVectorCommitmentTree(&txnMerkleArray{block: block, hashType: crypto.Sha512}, crypto.HashFactory{HashType: crypto.Sha512})
}

// txnMerkleArray is a representation of the transactions in this block,
// along with their ApplyData, as an array for the merklearray package.
type txnMerkleArray struct {
	block    Block
	hashType crypto.HashType
}

// Length implements the merklearray.Array interface.
func (tma *txnMerkleArray) Length() uint64 {
	return uint64(len(tma.block.Payset))
}

// Get implements the merklearray.Array interface.
func (tma *txnMerkleArray) Marshal(pos uint64) (crypto.Hashable, error) {
	if pos >= uint64(len(tma.block.Payset)) {
		return nil, fmt.Errorf("txnMerkleArray.Get(%d): out of bounds, payset size %d", pos, len(tma.block.Payset))
	}

	var elem txnMerkleElem
	elem.hashType = tma.hashType
	elem.stib = tma.block.Payset[pos]

	stxn, _, err := tma.block.DecodeSignedTxn(elem.stib)
	if err != nil {
		return nil, err
	}
	elem.txn = stxn.Txn

	return &elem, nil
}

func txnMerkleToRaw(txid [crypto.DigestSize]byte, stib [crypto.DigestSize]byte) (buf []byte) {
	buf = make([]byte, 2*crypto.DigestSize)
	copy(buf[:], txid[:])
	copy(buf[crypto.DigestSize:], stib[:])
	return
}

// txnMerkleElem represents a leaf in the Merkle tree of all transactions
// in a block.
type txnMerkleElem struct {
	txn      transactions.Transaction
	stib     transactions.SignedTxnInBlock
	hashType crypto.HashType
}

func (tme *txnMerkleElem) RawLeaf() []byte {
	if tme.hashType == crypto.Sha512_256 {
		return txnMerkleToRaw(tme.txn.ID(), tme.stib.Hash())
	}
	// else: hashType == crypto.Sha256
	return txnMerkleToRaw(tme.txn.IDSha256(), tme.stib.HashSHA256())
}

// ToBeHashed implements the crypto.Hashable interface.
func (tme *txnMerkleElem) ToBeHashed() (protocol.HashID, []byte) {
	// The leaf contains two hashes: the transaction ID (hash of the
	// transaction itself), and the hash of the entire SignedTxnInBlock.
	return protocol.TxnMerkleLeaf, tme.RawLeaf()
}

// Hash implements an optimized version of crypto.HashObj(tme).
func (tme *txnMerkleElem) Hash() crypto.Digest {
	return crypto.Hash(tme.HashRepresentation())
}

func (tme *txnMerkleElem) HashRepresentation() []byte {
	var buf [len(protocol.TxnMerkleLeaf) + 2*crypto.DigestSize]byte
	s := buf[:0]
	s = append(s, protocol.TxnMerkleLeaf...)
	s = append(s, tme.RawLeaf()...)
	return s
}
