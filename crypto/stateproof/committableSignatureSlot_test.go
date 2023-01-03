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

package stateproof

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestSignatureArrayWithEmptySlot(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	sigs := make([]sigslot, 2)

	key := generateTestSigner(0, uint64(stateProofIntervalForTests)*20+1, stateProofIntervalForTests, a)

	message := testMessage("hello world")
	sig, err := key.GetSigner(uint64(256)).SignBytes(message)
	a.NoError(err)

	sigs[0] = sigslot{
		Weight:        60,
		sigslotCommit: sigslotCommit{Sig: sig, L: 60},
	}

	hfactory := crypto.HashFactory{HashType: HashType}
	tree, err := merklearray.BuildVectorCommitmentTree(committableSignatureSlotArray(sigs), hfactory)

	leftLeafHash := calculateHashOnSigLeaf(t, sig, 60)
	rightLeafHash := hashBytes(hfactory.NewHash(), []byte(protocol.StateProofSig))

	a.Equal([]byte(tree.Root()), calculateHashOnInternalNode(leftLeafHash, rightLeafHash))
}

func calculateHashOnSigLeaf(t *testing.T, sig merklesignature.Signature, lValue uint64) []byte {
	var sigCommitment []byte
	sigCommitment = append(sigCommitment, protocol.StateProofSig...)

	binaryL := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryL, lValue)

	sigCommitment = append(sigCommitment, binaryL...)

	//build the expected binary representation of the merkle signature
	serializedSig, err := sig.Signature.GetFixedLengthHashableRepresentation()
	require.NoError(t, err)

	schemeType := make([]byte, 2)
	binary.LittleEndian.PutUint16(schemeType, merklesignature.CryptoPrimitivesID)

	sigCommitment = append(sigCommitment, schemeType...)
	sigCommitment = append(sigCommitment, serializedSig...)
	sigCommitment = append(sigCommitment, sig.VerifyingKey.GetFixedLengthHashableRepresentation()...)

	treeIdxBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(treeIdxBytes, sig.VectorCommitmentIndex)
	sigCommitment = append(sigCommitment, treeIdxBytes...)

	//build the expected binary representation of the merkle signature proof

	proofLenByte := byte(len(sig.Proof.Path))

	sigCommitment = append(sigCommitment, proofLenByte)

	hash := crypto.HashFactory{HashType: HashType}.NewHash()
	zeroDigest := make([]byte, hash.BlockSize())
	for i := byte(0); i < (merklearray.MaxEncodedTreeDepth - proofLenByte); i++ {
		sigCommitment = append(sigCommitment, zeroDigest...)
	}

	for i := byte(0); i < proofLenByte; i++ {
		sigCommitment = append(sigCommitment, sig.Proof.Path[i]...)
	}

	hashValue := hashBytes(hash, sigCommitment)
	return hashValue
}
