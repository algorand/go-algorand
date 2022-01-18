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

package merklekeystore

import (
	"crypto/rand"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type TestingHashable struct {
	data []byte
}

func (s TestingHashable) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TestHashable, s.data
}

func TestSignerCreation(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	h := genHashableForTest()
	for i := uint64(1); i < 20; i++ {
		signer := generateTestSigner(crypto.FalconType, i, i+1, 1, a)
		_, err = signer.GetSigner(i).Sign(h)
		a.NoError(err)
	}

	testSignerNumKeysLimits := func(t crypto.AlgorithmType, firstValid uint64, lastValid uint64, interval uint64, expectedLen int) {
		signer := generateTestSigner(t, firstValid, lastValid, interval, a)
		a.Equal(expectedLen, length(signer, a))
	}

	testSignerNumKeysLimits(crypto.FalconType, 0, 0, 1, 0)
	testSignerNumKeysLimits(crypto.FalconType, 0, 1, 1, 1)
	testSignerNumKeysLimits(crypto.FalconType, 2, 2, 2, 1)
	testSignerNumKeysLimits(crypto.FalconType, 8, 21, 10, 2)
	testSignerNumKeysLimits(crypto.FalconType, 8, 20, 10, 2)
	testSignerNumKeysLimits(crypto.FalconType, 10, 21, 10, 2)
	testSignerNumKeysLimits(crypto.FalconType, 10, 20, 10, 2)
	testSignerNumKeysLimits(crypto.FalconType, 11, 20, 10, 1)

	testSignerNumKeysLimits(crypto.Ed25519Type, 0, 0, 1, 0)
	testSignerNumKeysLimits(crypto.Ed25519Type, 0, 1, 1, 1)
	testSignerNumKeysLimits(crypto.Ed25519Type, 2, 2, 2, 1)
	testSignerNumKeysLimits(crypto.Ed25519Type, 8, 21, 10, 2)
	testSignerNumKeysLimits(crypto.Ed25519Type, 8, 20, 10, 2)
	testSignerNumKeysLimits(crypto.Ed25519Type, 10, 21, 10, 2)
	testSignerNumKeysLimits(crypto.Ed25519Type, 10, 20, 10, 2)
	testSignerNumKeysLimits(crypto.Ed25519Type, 11, 20, 10, 1)

	signer := generateTestSigner(crypto.FalconType, 2, 2, 2, a)
	a.Equal(1, length(signer, a))

	sig, err := signer.GetSigner(2).Sign(genHashableForTest())
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(2, genHashableForTest(), sig))

	signer = generateTestSigner(crypto.FalconType, 2, 2, 3, a)
	a.Equal(0, length(signer, a))
	_, err = signer.GetSigner(2).Sign(genHashableForTest())
	a.Error(err)

	signer = generateTestSigner(crypto.FalconType, 11, 19, 10, a)
	a.Equal(0, length(signer, a))
	_, err = signer.GetSigner(2).Sign(genHashableForTest())
	a.Error(err)
}
func TestEmptyVerifier(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(crypto.FalconType, 8, 9, 5, a)
	// even if there are no keys for that period, the root is not empty
	// (part of the vector commitment property).
	a.Equal(signer.GetVerifier().IsEmpty(), false)
}

func TestEmptySigner(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	h := genHashableForTest()
	signer := generateTestSigner(crypto.FalconType, 8, 9, 5, a)
	a.Equal(0, length(signer, a))

	_, err = signer.GetSigner(8).Sign(h)
	a.Error(err)

	_, err = signer.GetSigner(9).Sign(h)
	a.Error(err)
}

func TestDisposableKeysGeneration(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(crypto.FalconType, 0, 100, 1, a)
	for i := uint64(1); i < 100; i++ {
		k := signer.GetKey(i)
		a.NotNil(k)
	}

	k := signer.GetKey(101)
	a.Nil(k)

	signer = generateTestSigner(crypto.FalconType, 1000, 1100, 1, a)
	for i := uint64(1000); i < 1100; i++ {
		k = signer.GetKey(i)
		a.NotNil(k)
	}

	k = signer.GetKey(999)
	a.Nil(k)

	signer = generateTestSigner(crypto.FalconType, 1000, 1100, 101, a)
	intervalRounds := make([]uint64, 0)
	for i := uint64(1000); i <= 1100; i++ {
		if i%101 == 0 {
			intervalRounds = append(intervalRounds, i)
			continue
		}
		k := signer.GetKey(i)
		a.Nil(k)
	}
}

func TestNonEmptyDisposableKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(crypto.FalconType, 0, 100, 1, a)

	s := crypto.GenericSigningKey{}
	for i := uint64(1); i <= 100; i++ {
		key := signer.GetKey(i)
		a.NotNil(key)
		a.NotEqual(s, key)
	}

	signer = generateTestSigner(crypto.Ed25519Type, 0, 100, 1, a)

	s = crypto.GenericSigningKey{}
	for i := uint64(1); i <= 100; i++ {
		key := signer.GetKey(i)
		a.NotNil(key)
		a.NotEqual(s, key)
	}
}

func TestSignatureStructure(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(crypto.FalconType, 50, 100, 1, a)

	hashable := genHashableForTest()
	sig, err := signer.GetSigner(51).Sign(hashable)
	a.NoError(err)

	key := signer.GetKey(51)
	a.NotNil(key)

	a.Equal(sig.VerifyingKey, *key.GetSigner().GetVerifyingKey())

	proof, err := signer.Tree.ProveSingleLeaf(1)
	a.NoError(err)
	a.Equal(*proof, sig.Proof)

	a.NotEqual(nil, sig.ByteSignature)
}

func genHashableForTest() crypto.Hashable {
	hashable := TestingHashable{[]byte("test msg")}

	return hashable
}

func TestSigning(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, end := uint64(50), uint64(100)
	signer := generateTestSigner(crypto.FalconType, start, end, 1, a)

	hashable := genHashableForTest()

	sig, err := signer.GetSigner(start).Sign(hashable)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(start, hashable, sig))

	_, err = signer.GetSigner(start - 1).Sign(hashable)
	a.Error(err)

	_, err = signer.GetSigner(end + 1).Sign(hashable)
	a.Error(err)

	signer = generateTestSigner(crypto.FalconType, start, end, 10, a)

	sig, err = signer.GetSigner(start).Sign(hashable)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(start, hashable, sig))

	sig, err = signer.GetSigner(start + 5).Sign(hashable)
	a.Error(err)
	a.Error(signer.GetVerifier().Verify(start+5, hashable, sig))

	signer = generateTestSigner(crypto.FalconType, 50, 100, 12, a)
	a.Equal(length(signer, a), 4)

	for i := uint64(50); i < 100; i++ {
		if i%12 != 0 {
			_, err = signer.GetSigner(i).Sign(hashable)
			a.Error(err)
		} else {
			sig, err = signer.GetSigner(i).Sign(hashable)
			a.NoError(err)
			a.NoError(signer.GetVerifier().Verify(i, hashable, sig))
		}
	}

	signer = generateTestSigner(crypto.FalconType, 234, 4634, 128, a)
	key := signer.GetKey(256)
	a.NotNil(key)
	key = signer.GetKey(4096)
	a.NotNil(key)
	key = signer.GetKey(234 + 128)
	a.Nil(key)
}

func TestBadRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, _, signer := generateTestSignerAux(a)
	hashable, sig := makeSig(signer, start, a)

	a.Error(signer.GetVerifier().Verify(start+1, hashable, sig))

	hashable, sig = makeSig(signer, start+1, a)
	a.Error(signer.GetVerifier().Verify(start, hashable, sig))
	a.Error(signer.GetVerifier().Verify(start+2, hashable, sig))
}

func TestBadMerkleProofInSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, _, signer := generateTestSignerAux(a)
	hashable, sig := makeSig(signer, start, a)

	sig2 := copySig(sig)
	sig2.Proof.Path = sig2.Proof.Path[:len(sig2.Proof.Path)-1]
	a.Error(signer.GetVerifier().Verify(start, hashable, sig2))

	sig3 := copySig(sig)
	someDigest := crypto.Digest{}
	rand.Read(someDigest[:])
	sig3.Proof.Path[0] = someDigest[:]
	a.Error(signer.GetVerifier().Verify(start, hashable, sig3))
}

func copySig(sig Signature) Signature {
	bsig := make([]byte, len(sig.ByteSignature))
	copy(bsig, sig.ByteSignature)

	return Signature{
		ByteSignature: bsig,
		Proof:         copyProof(sig.Proof),
		VerifyingKey:  sig.VerifyingKey,
	}
}

func TestIncorrectByteSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, _, signer := generateTestSignerAux(a)
	hashable, sig := makeSig(signer, start, a)

	sig2 := sig
	bs := make([]byte, len(sig.ByteSignature))
	copy(bs, sig2.ByteSignature)
	bs[0]++
	sig2.ByteSignature = bs
	a.Error(signer.GetVerifier().Verify(start, hashable, sig2))
}

func TestIncorrectMerkleIndex(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	h := genHashableForTest()
	signer := generateTestSigner(crypto.FalconType, 8, 100, 5, a)
	a.NoError(err)

	sig, err := signer.GetSigner(20).Sign(h)
	a.NoError(err)

	sig.MerkleArrayIndex = 0
	a.Error(signer.GetVerifier().Verify(20, h, sig))

	sig.MerkleArrayIndex = math.MaxUint64
	a.Error(signer.GetVerifier().Verify(20, h, sig))
	a.Error(signer.GetVerifier().Verify(20, h, sig))

}

func TestAttemptToUseDifferentKey(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, _, signer := generateTestSignerAux(a)
	hashable, sig := makeSig(signer, start+1, a)
	// taking signature for specific round and changing the round

	// taking signature and changing the key to match different round
	sig2 := sig
	key := signer.GetKey(start)
	a.NotNil(key)

	sig2.VerifyingKey = *(key.GetSigner().GetVerifyingKey())
	a.Error(signer.GetVerifier().Verify(start+1, hashable, sig2))
}

func TestMarshal(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(crypto.FalconType, 0, 10, 1, a)

	out := protocol.Encode(&signer.SignerContext)
	decodeInto := SignerContext{}
	a.NoError(protocol.Decode(out, &decodeInto))
	a.Equal(signer.SignerContext, decodeInto)

	verifier := signer.GetVerifier()
	bs := protocol.Encode(verifier)
	verifierToDecodeInto := Verifier{}
	protocol.Decode(bs, &verifierToDecodeInto)
	a.Equal(*verifier, verifierToDecodeInto)
}

func TestNumberOfGeneratedKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	interval := uint64(128)
	validPeriod := uint64((1<<8)*interval - 1)

	firstValid := uint64(1000)
	lastValid := validPeriod + 1000
	s, err := New(firstValid, lastValid, interval, crypto.Ed25519Type)
	a.NoError(err)
	a.Equal(1<<8, length(s, a))

	firstValid = uint64(0)
	lastValid = validPeriod
	s, err = New(firstValid, lastValid, interval, crypto.Ed25519Type)
	a.NoError(err)
	a.Equal((1<<8)-1, length(s, a))

	firstValid = uint64(1000)
	lastValid = validPeriod + 1000 - (interval * 50)
	s, err = New(firstValid, lastValid, interval, crypto.Ed25519Type)
	a.NoError(err)

	a.Equal((1<<8)-50, length(s, a))
}

//#region Helper Functions
func makeSig(signer *Keystore, sigRound uint64, a *require.Assertions) (crypto.Hashable, Signature) {
	hashable := genHashableForTest()

	sig, err := signer.GetSigner(sigRound).Sign(hashable)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(sigRound, hashable, sig))
	return hashable, sig
}

func generateTestSignerAux(a *require.Assertions) (uint64, uint64, *Keystore) {
	start, end := uint64(50), uint64(100)
	signer := generateTestSigner(crypto.FalconType, start, end, 1, a)
	return start, end, signer
}

func generateTestSigner(t crypto.AlgorithmType, firstValid, lastValid, interval uint64, a *require.Assertions) *Keystore {
	signer, err := New(firstValid, lastValid, interval, t)
	a.NoError(err)

	return signer
}

func length(s *Keystore, a *require.Assertions) int {
	return len(s.ephemeralKeys)
}

func copyProof(proof merklearray.SingleLeafProof) merklearray.SingleLeafProof {
	path := make([]crypto.GenericDigest, len(proof.Path))
	for i, digest := range proof.Path {
		path[i] = make([]byte, len(digest))
		copy(path[i], digest)
	}
	p := merklearray.Proof{
		Path:        path,
		HashFactory: proof.HashFactory}
	return merklearray.SingleLeafProof{Proof: p}
}

//#endregion
