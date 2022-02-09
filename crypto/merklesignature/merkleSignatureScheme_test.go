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

package merklesignature

import (
	"crypto/rand"
	"errors"
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
		signer := generateTestSigner(i, i+1, 1, a)
		_, err = signer.GetSigner(i).Sign(h)
		a.NoError(err)
	}

	testSignerNumKeysLimits := func(firstValid uint64, lastValid uint64, interval uint64, expectedLen int) {
		signer := generateTestSigner(firstValid, lastValid, interval, a)
		a.Equal(expectedLen, length(signer, a))
	}

	testSignerNumKeysLimits(0, 0, 1, 0)
	testSignerNumKeysLimits(0, 1, 1, 1)
	testSignerNumKeysLimits(2, 2, 2, 1)
	testSignerNumKeysLimits(8, 21, 10, 2)
	testSignerNumKeysLimits(8, 20, 10, 2)
	testSignerNumKeysLimits(10, 21, 10, 2)
	testSignerNumKeysLimits(10, 20, 10, 2)
	testSignerNumKeysLimits(11, 20, 10, 1)

	signer := generateTestSigner(2, 2, 2, a)
	a.Equal(1, length(signer, a))

	sig, err := signer.GetSigner(2).Sign(genHashableForTest())
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(2, genHashableForTest(), sig))

	signer = generateTestSigner(2, 2, 3, a)
	a.Equal(0, length(signer, a))
	_, err = signer.GetSigner(2).Sign(genHashableForTest())
	a.Error(err)
	a.ErrorIs(err, ErrNoStateProofKeyForRound)

	signer = generateTestSigner(11, 19, 10, a)
	a.Equal(0, length(signer, a))
	_, err = signer.GetSigner(2).Sign(genHashableForTest())
	a.Error(err)
	a.ErrorIs(err, ErrNoStateProofKeyForRound)
}

func TestSignerCreationOutOfBounds(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	_, err := New(8, 4, 1)
	a.Error(err)
	a.ErrorIs(err, ErrStartBiggerThanEndRound)

	_, err = New(1, 8, 0)
	a.Error(err)
	a.ErrorIs(err, ErrDivisorIsZero)
}

func TestEmptyVerifier(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(8, 9, 5, a)
	// even if there are no keys for that period, the root is not empty
	// (part of the vector commitment property).
	a.Equal(false, signer.GetVerifier().IsEmpty())
}

func TestEmptySigner(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	h := genHashableForTest()
	signer := generateTestSigner(8, 9, 5, a)
	a.Equal(0, length(signer, a))

	_, err = signer.GetSigner(8).Sign(h)
	a.Error(err)
	a.ErrorIs(err, ErrNoStateProofKeyForRound)

	_, err = signer.GetSigner(9).Sign(h)
	a.Error(err)
	a.ErrorIs(err, ErrNoStateProofKeyForRound)
}

func TestDisposableKeysGeneration(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(0, 100, 1, a)
	for i := uint64(1); i < 100; i++ {
		k := signer.GetKey(i)
		a.NotNil(k)
	}

	k := signer.GetKey(101)
	a.Nil(k)

	signer = generateTestSigner(1000, 1100, 1, a)
	for i := uint64(1000); i < 1100; i++ {
		k = signer.GetKey(i)
		a.NotNil(k)
	}

	k = signer.GetKey(999)
	a.Nil(k)

	signer = generateTestSigner(1000, 1100, 101, a)
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

	signer := generateTestSigner(0, 100, 1, a)

	s := crypto.FalconSigner{}
	for i := uint64(1); i <= 100; i++ {
		key := signer.GetKey(i)
		a.NotNil(key)
		a.NotEqual(s, key)
	}

	signer = generateTestSigner(0, 100, 1, a)

	s = crypto.FalconSigner{}
	for i := uint64(1); i <= 100; i++ {
		key := signer.GetKey(i)
		a.NotNil(key)
		a.NotEqual(s, key)
	}
}

func TestSignatureStructure(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(50, 100, 1, a)

	hashable := genHashableForTest()
	sig, err := signer.GetSigner(51).Sign(hashable)
	a.NoError(err)

	key := signer.GetKey(51)
	a.NotNil(key)

	a.Equal(sig.VerifyingKey, *key.GetVerifyingKey())

	proof, err := signer.Tree.ProveSingleLeaf(1)
	a.NoError(err)
	a.Equal(*proof, sig.Proof)

	a.NotEqual(nil, sig.Signature)
}

func genHashableForTest() crypto.Hashable {
	hashable := TestingHashable{[]byte("test msg")}

	return hashable
}

func TestSigning(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, end := uint64(50), uint64(100)
	signer := generateTestSigner(start, end, 1, a)

	hashable := genHashableForTest()

	sig, err := signer.GetSigner(start).Sign(hashable)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(start, hashable, sig))

	_, err = signer.GetSigner(start - 1).Sign(hashable)
	a.Error(err)
	a.ErrorIs(err, ErrNoStateProofKeyForRound)

	_, err = signer.GetSigner(end + 1).Sign(hashable)
	a.Error(err)
	a.ErrorIs(err, ErrNoStateProofKeyForRound)

	signer = generateTestSigner(start, end, 10, a)

	sig, err = signer.GetSigner(start).Sign(hashable)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(start, hashable, sig))

	sig, err = signer.GetSigner(start + 5).Sign(hashable)
	a.Error(err)

	err = signer.GetVerifier().Verify(start+5, hashable, sig)
	a.Error(err)
	a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)

	signer = generateTestSigner(50, 100, 12, a)
	a.Equal(4, length(signer, a))

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

	signer = generateTestSigner(234, 4634, 256, a)
	key := signer.GetKey(512)
	a.NotNil(key)
	key = signer.GetKey(4096)
	a.NotNil(key)
	key = signer.GetKey(234 + 256)
	a.Nil(key)
}

func TestBadRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, _, signer := generateTestSignerAux(a)
	hashable, sig := makeSig(signer, start, a)

	err := signer.GetVerifier().Verify(start+1, hashable, sig)
	a.Error(err)
  a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)

	hashable, sig = makeSig(signer, start+1, a)
	err = signer.GetVerifier().Verify(start, hashable, sig)
	a.Error(err)
  a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)

	err = signer.GetVerifier().Verify(start+2, hashable, sig)
	a.Error(err)
  a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)
	a.True(errors.Is(err, ErrSignatureSchemeVerificationFailed))
}

func TestBadMerkleProofInSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, _, signer := generateTestSignerAux(a)
	hashable, sig := makeSig(signer, start, a)

	sig2 := copySig(sig)
	sig2.Proof.Path = sig2.Proof.Path[:len(sig2.Proof.Path)-1]
	err := signer.GetVerifier().Verify(start, hashable, sig2)
	a.Error(err)
	a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)

	sig3 := copySig(sig)
	someDigest := crypto.Digest{}
	rand.Read(someDigest[:])
	sig3.Proof.Path[0] = someDigest[:]
	err = signer.GetVerifier().Verify(start, hashable, sig3)
	a.Error(err)
	a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)
}

func copySig(sig Signature) Signature {
	bsig := make([]byte, len(sig.Signature))
	copy(bsig, sig.Signature)

	return Signature{
		Signature:    bsig,
		Proof:        copyProof(sig.Proof),
		VerifyingKey: sig.VerifyingKey,
	}
}

func TestIncorrectByteSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	start, _, signer := generateTestSignerAux(a)
	hashable, sig := makeSig(signer, start, a)

	sig2 := sig
	bs := make([]byte, len(sig.Signature))
	copy(bs, sig2.Signature)
	bs[0]++
	sig2.Signature = bs

	err := signer.GetVerifier().Verify(start, hashable, sig2)
	a.Error(err)
	a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)
}

func TestIncorrectMerkleIndex(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	var err error

	h := genHashableForTest()
	signer := generateTestSigner(8, 100, 5, a)
	a.NoError(err)

	sig, err := signer.GetSigner(20).Sign(h)
	a.NoError(err)

	sig.MerkleArrayIndex = 0
	err = signer.GetVerifier().Verify(20, h, sig)
	a.Error(err)
  a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)

	sig.MerkleArrayIndex = math.MaxUint64
	err = signer.GetVerifier().Verify(20, h, sig)
	a.Error(err)
  a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)

	err = signer.GetVerifier().Verify(20, h, sig)
	a.Error(err)
	a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)
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

	sig2.VerifyingKey = *(key.GetVerifyingKey())

	err := signer.GetVerifier().Verify(start+1, hashable, sig2)
	a.Error(err)
	a.ErrorIs(err, ErrSignatureSchemeVerificationFailed)
}

func TestMarshal(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(0, 10, 1, a)

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
	interval := uint64(256)
	numberOfKeys := uint64(1 << 6)
	validPeriod := numberOfKeys*interval - 1

	firstValid := uint64(1000)
	lastValid := validPeriod + 1000
	s, err := New(firstValid, lastValid, interval)
	a.NoError(err)
	a.Equal(numberOfKeys, uint64(length(s, a)))

	firstValid = uint64(0)
	lastValid = validPeriod
	s, err = New(firstValid, lastValid, interval)
	a.NoError(err)
	a.Equal(numberOfKeys-1, uint64(length(s, a)))

	firstValid = uint64(1000)
	lastValid = validPeriod + 1000 - (interval * 50)
	s, err = New(firstValid, lastValid, interval)
	a.NoError(err)

	a.Equal(numberOfKeys-50, uint64(length(s, a)))
}

func TestGetAllKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	interval := uint64(256)
	numOfKeys := uint64(1 << 8)
	validPeriod := numOfKeys*interval - 1

	firstValid := uint64(1000)
	lastValid := validPeriod + 1000
	s, err := New(firstValid, lastValid, interval)
	a.NoError(err)
	a.Equal(numOfKeys, uint64(len(s.ephemeralKeys)))

	keys := s.GetAllKeys()
	for i := uint64(0); i < uint64(len(s.ephemeralKeys)); i++ {
		a.Equal(s.ephemeralKeys[i], *keys[i].Key)
		a.Equal(indexToRound(firstValid, interval, i), keys[i].Round)
	}

	s, err = New(1, 2, 100)
	a.NoError(err)
	a.Equal(0, length(s, a))

	keys = s.GetAllKeys()
	a.Equal(0, len(keys))
}

//#region Helper Functions
func makeSig(signer *Secrets, sigRound uint64, a *require.Assertions) (crypto.Hashable, Signature) {
	hashable := genHashableForTest()

	sig, err := signer.GetSigner(sigRound).Sign(hashable)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(sigRound, hashable, sig))
	return hashable, sig
}

func generateTestSignerAux(a *require.Assertions) (uint64, uint64, *Secrets) {
	start, end := uint64(50), uint64(100)
	signer := generateTestSigner(start, end, 1, a)
	return start, end, signer
}

func generateTestSigner(firstValid, lastValid, interval uint64, a *require.Assertions) *Secrets {
	signer, err := New(firstValid, lastValid, interval)
	a.NoError(err)

	return signer
}

func length(s *Secrets, a *require.Assertions) int {
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
