// Copyright (C) 2019-2022 Algorand, Inc.
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

package compactcert

import (
	"encoding/binary"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklekeystore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestSignatureArrayWithEmptySlot(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	sigs := make([]sigslot, 2)

	key, dbAccessor := generateTestSigner(t.Name()+".db", 0, uint64(compactCertRoundsForTests)*20+1, compactCertRoundsForTests, a)
	defer dbAccessor.Close()

	message := testMessage("hello world")
	sig, err := key.Sign(message, uint64(128))
	a.NoError(err)

	sigs[0] = sigslot{
		Weight:        60,
		sigslotCommit: sigslotCommit{Sig: CompactOneTimeSignature{Signature: sig}, L: 60},
	}

	hfactory := crypto.HashFactory{HashType: HashType}
	tree, err := merklearray.Build(committableSignatureSlotArray(sigs), hfactory)

	leftLeafHash := calculateHashOnSigLeaf(t, sig, 60)
	rightLeafHash := crypto.HashBytes(hfactory.NewHash(), []byte(protocol.CompactCertSig))

	a.Equal([]byte(tree.Root()), calculateHashOnInternalNode(leftLeafHash, rightLeafHash))
}

func calculateHashOnSigLeaf(t *testing.T, sig merklekeystore.Signature, lValue uint64) []byte {

	var sigCommitment []byte
	sigCommitment = append(sigCommitment, protocol.CompactCertSig...)

	binaryL := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryL, lValue)

	sigCommitment = append(sigCommitment, binaryL...)

	//build the expected binary representation of the merkle signature
	pK := sig.VerifyingKey.GetVerifier()
	serializedSig, err := pK.GetSignatureFixedLengthHashableRepresentation(sig.ByteSignature)
	require.NoError(t, err)

	schemeType := make([]byte, 2)
	binary.LittleEndian.PutUint16(schemeType, uint16(sig.VerifyingKey.Type))

	sigCommitment = append(sigCommitment, schemeType...)
	sigCommitment = append(sigCommitment, serializedSig...)
	sigCommitment = append(sigCommitment, pK.GetFixedLengthHashableRepresentation()...)

	treeIdxBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(treeIdxBytes, sig.MerkleArrayIndex)
	sigCommitment = append(sigCommitment, treeIdxBytes...)

	//build the expected binary representation of the merkle signature proof

	proofLenByte := byte(len(sig.Proof.Path))

	sigCommitment = append(sigCommitment, proofLenByte)

	i := byte(0)
	for ; i < proofLenByte; i++ {
		sigCommitment = append(sigCommitment, sig.Proof.Path[i]...)
	}

	hash := crypto.HashFactory{HashType: HashType}.NewHash()
	zeroDigest := make([]byte, hash.BlockSize())
	for ; i < merklearray.MaxTreeDepth; i++ {
		sigCommitment = append(sigCommitment, zeroDigest...)
	}

	hashValue := crypto.HashBytes(hash, sigCommitment)
	return hashValue
}
