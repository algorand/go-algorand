// Copyright (C) 2019-2023 Algorand, Inc.
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
	"encoding/binary"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func hashBytes(hash hash.Hash, m []byte) []byte {
	hash.Reset()
	hash.Write(m)
	outhash := hash.Sum(nil)
	return outhash
}

func calculateHashOnKeyLeaf(key *crypto.FalconSigner, round uint64) []byte {
	binaryRound := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryRound, round)

	schemeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(schemeBytes, CryptoPrimitivesID)

	verifyingRawKey := key.GetVerifyingKey().GetFixedLengthHashableRepresentation()
	keyCommitment := make([]byte, 0, len(protocol.KeysInMSS)+len(verifyingRawKey)+len(binaryRound))

	keyCommitment = append(keyCommitment, protocol.KeysInMSS...)
	keyCommitment = append(keyCommitment, schemeBytes...)
	keyCommitment = append(keyCommitment, binaryRound...)
	keyCommitment = append(keyCommitment, verifyingRawKey...)

	factory := crypto.HashFactory{HashType: MerkleSignatureSchemeHashFunction}

	hashValue := hashBytes(factory.NewHash(), keyCommitment)
	return hashValue
}

func calculateHashOnInternalNode(leftNode, rightNode []byte) []byte {
	buf := make([]byte, len(leftNode)+len(rightNode)+len(protocol.MerkleArrayNode))
	copy(buf[:], protocol.MerkleArrayNode)
	copy(buf[len(protocol.MerkleArrayNode):], leftNode[:])
	copy(buf[len(protocol.MerkleArrayNode)+len(leftNode):], rightNode[:])

	factory := crypto.HashFactory{HashType: MerkleSignatureSchemeHashFunction}
	hashValue := hashBytes(factory.NewHash(), buf)
	return hashValue
}

func TestEphemeralPublicKeysCommitmentBinaryFormat(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(1, 9, 2, a)
	a.Equal(4, length(signer, a))

	k0 := signer.GetSigner(2).SigningKey

	k0hash := calculateHashOnKeyLeaf(k0, 2)

	k1 := signer.GetSigner(4).SigningKey
	k1hash := calculateHashOnKeyLeaf(k1, 4)

	k2 := signer.GetSigner(6).SigningKey
	k2hash := calculateHashOnKeyLeaf(k2, 6)

	k3 := signer.GetSigner(8).SigningKey
	k3hash := calculateHashOnKeyLeaf(k3, 8)

	// hash internal node according to the vector commitment indices
	internal1 := calculateHashOnInternalNode(k0hash, k2hash)
	internal2 := calculateHashOnInternalNode(k1hash, k3hash)

	root := calculateHashOnInternalNode(internal1, internal2)
	a.Equal(root, signer.GetVerifier().Commitment[:])
}
