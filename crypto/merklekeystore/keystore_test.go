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

package merklekeystore

import (
	"crypto/rand"
	"math"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func TestSignerCreation(t *testing.T) {
	a := require.New(t)

	h := genHashableForTest()
	for i := uint64(1); i < 20; i++ {
		signer, err := New(i, i+1, 1, crypto.PlaceHolderType)
		a.NoError(err)
		_, err = signer.Sign(h, i)
		a.NoError(err)
	}

	_, err := New(1, 0, 1, crypto.PlaceHolderType)
	a.Error(err)

	signer, err := New(2, 2, 2, crypto.PlaceHolderType)
	a.NoError(err)
	sig, err := signer.Sign(genHashableForTest(), 2)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(2, 2, 2, genHashableForTest(), sig))
	a.Equal(1, len(signer.EphemeralKeys.SignatureAlgorithms))

	signer, err = New(2, 2, 3, crypto.PlaceHolderType)
	a.NoError(err)
	_, err = signer.Sign(genHashableForTest(), 2)
	a.Error(err)

	s, err := New(8, 21, 10, crypto.PlaceHolderType)
	a.NoError(err)
	a.Equal(len(s.EphemeralKeys.SignatureAlgorithms), 2)

	s, err = New(10, 21, 10, crypto.PlaceHolderType)
	a.NoError(err)
	a.Equal(len(s.EphemeralKeys.SignatureAlgorithms), 2)

	s, err = New(10, 20, 10, crypto.PlaceHolderType)
	a.NoError(err)
	a.Equal(len(s.EphemeralKeys.SignatureAlgorithms), 2)

	s, err = New(11, 20, 10, crypto.PlaceHolderType)
	a.NoError(err)
	a.Equal(len(s.EphemeralKeys.SignatureAlgorithms), 1)

	s, err = New(11, 19, 10, crypto.PlaceHolderType)
	a.NoError(err)
	a.Equal(0, len(s.EphemeralKeys.SignatureAlgorithms))
	_, err = signer.Sign(genHashableForTest(), 2)
	a.Error(err)
}

func TestDisposableKeyPositions(t *testing.T) {
	a := require.New(t)
	signer, err := New(0, 100, 1, crypto.PlaceHolderType)
	a.NoError(err)

	for i := uint64(1); i < 100; i++ {
		pos, err := signer.getKeyPosition(i)
		a.NoError(err, i)
		a.Equal(i-1, pos)
	}

	_, err = signer.getKeyPosition(101)
	a.Error(err)

	signer, err = New(1000, 1100, 1, crypto.PlaceHolderType)
	a.NoError(err)

	for i := uint64(1000); i < 1100; i++ {
		pos, err := signer.getKeyPosition(i)
		a.NoError(err, i)
		a.Equal(i-1000, pos)
	}

	_, err = signer.getKeyPosition(999)
	a.Error(err)

	signer, err = New(1000, 1100, 101, crypto.PlaceHolderType)
	a.NoError(err)

	indices := make([]uint64, 0)
	for i := uint64(1000); i <= 1100; i++ {
		if i%101 == 0 {
			indices = append(indices, i)
			continue
		}
		_, err := signer.getKeyPosition(i)
		a.Error(err, i)
	}

	for index, round := range indices {
		pos, err := signer.getKeyPosition(round)
		a.NoError(err)
		a.Equal(uint64(index), pos)
	}
}

func TestNonEmptyDisposableKeys(t *testing.T) {
	a := require.New(t)
	signer, err := New(0, 100, 1, crypto.PlaceHolderType)
	a.NoError(err)

	s := crypto.SignatureAlgorithm{}
	for _, key := range signer.EphemeralKeys.SignatureAlgorithms {
		a.NotEqual(s, key)
	}
}

func TestSignatureStructure(t *testing.T) {
	a := require.New(t)
	signer, err := New(50, 100, 1, crypto.PlaceHolderType)
	a.NoError(err)

	hashable := genHashableForTest()
	sig, err := signer.Sign(hashable, 51)
	a.NoError(err)

	pos, err := signer.getKeyPosition(51)
	a.NoError(err)
	a.Equal(uint64(1), pos)

	key := signer.EphemeralKeys.SignatureAlgorithms[pos]
	a.Equal(sig.VerifyingKey, key.GetSigner().GetVerifyingKey())

	proof, err := signer.Tree.Prove([]uint64{1})
	a.NoError(err)
	a.Equal(Proof(proof), sig.Proof)

	a.NotEqual(nil, sig.ByteSignature)
}

func genHashableForTest() crypto.Hashable {
	hashable := crypto.Hashable(&crypto.VerifyingKey{Type: math.MaxUint64}) // just want some crypto.Hashable..
	return hashable
}

func TestSigning(t *testing.T) {
	a := require.New(t)

	start, end := uint64(50), uint64(100)
	signer, err := New(start, end, 1, crypto.PlaceHolderType)
	a.NoError(err)

	hashable := crypto.Hashable(&crypto.VerifyingKey{Type: math.MaxUint64}) // just want some crypto.Hashable..

	sig, err := signer.Sign(hashable, start)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(start, start, 1, hashable, sig))

	_, err = signer.Sign(hashable, start-1)
	a.Error(err)

	_, err = signer.Sign(hashable, end+1)
	a.Error(err)

	signer, err = New(start, end, 10, crypto.PlaceHolderType)
	a.NoError(err)

	sig, err = signer.Sign(hashable, start)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(start, start, 1, hashable, sig))

	sig, err = signer.Sign(hashable, start+5)
	a.Error(err)
	a.Error(signer.GetVerifier().Verify(start, start+5, 1, hashable, sig))

	signer, err = New(50, 100, 12, crypto.PlaceHolderType)
	a.NoError(err)

	for i := uint64(50); i < 100; i++ {
		if i%12 != 0 {
			_, err = signer.Sign(hashable, i)
			a.Error(err)
		} else {
			sig, err = signer.Sign(hashable, i)
			a.NoError(err)
			a.NoError(signer.GetVerifier().Verify(50, i, 12, hashable, sig))
		}
	}
}

func TestBadRound(t *testing.T) {
	a := require.New(t)
	start, _, signer := getSigner(a)

	hashable, sig := makeSig(signer, start, a)

	a.Error(signer.GetVerifier().Verify(0, start, 1, hashable, sig))
	a.Error(signer.GetVerifier().Verify(start, start+1, 1, hashable, sig))

	hashable, sig = makeSig(signer, start+1, a)
	a.Error(signer.GetVerifier().Verify(start, start, 1, hashable, sig))
	a.Error(signer.GetVerifier().Verify(start, start+2, 1, hashable, sig))
}

func TestBadMerkleProofInSignature(t *testing.T) {
	a := require.New(t)
	start, _, signer := getSigner(a)

	hashable, sig := makeSig(signer, start, a)

	sig2 := sig
	sig2.Proof = sig2.Proof[:len(sig2.Proof)-1]
	a.Error(signer.GetVerifier().Verify(start, start, 1, hashable, sig2))

	sig3 := sig2
	someDigest := crypto.Digest{}
	rand.Read(someDigest[:])
	sig3.Proof[0] = someDigest
	a.Error(signer.GetVerifier().Verify(start, start, 1, hashable, sig3))
}

func TestIncorrectByteSignature(t *testing.T) {
	a := require.New(t)
	start, _, signer := getSigner(a)

	hashable, sig := makeSig(signer, start, a)

	sig2 := sig
	bs := make([]byte, len(sig.ByteSignature))
	copy(bs, sig2.ByteSignature)
	bs[0]++
	sig2.ByteSignature = bs
	a.Error(signer.GetVerifier().Verify(start, start, 1, hashable, sig2))
}

func TestAttemptToUseDifferentKey(t *testing.T) {
	a := require.New(t)
	start, _, signer := getSigner(a)

	hashable, sig := makeSig(signer, start+1, a)
	// taking signature for specific round and changing the round

	// taking signature and changing the key to match different round
	sig2 := sig
	sig2.VerifyingKey = signer.EphemeralKeys.SignatureAlgorithms[0].GetSigner().GetVerifyingKey()
	a.Error(signer.GetVerifier().Verify(start, start+1, 1, hashable, sig2))
}

func TestMarshal(t *testing.T) {
	a := require.New(t)
	signer, err := New(0, 10, 1, crypto.PlaceHolderType)
	a.NoError(err)

	out := protocol.Encode(signer)
	decodeInto := &Signer{}
	a.NoError(protocol.Decode(out, decodeInto))
	compareSigners(a, signer, decodeInto)

	// check that after trim the output stays the same.
	cpy, _ := signer.Trim(5)
	a.Equal(protocol.Encode(signer), protocol.Encode(cpy))

	verifier := signer.GetVerifier()
	bs := protocol.Encode(verifier)
	verifierToDecodeInto := Verifier{}
	protocol.Decode(bs, &verifierToDecodeInto)
	a.Equal(*verifier, verifierToDecodeInto)
}

func compareSigners(a *require.Assertions, signer *Signer, cpy *Signer) {
	a.Equal(signer.Tree, cpy.Tree)
	a.Equal(signer.EphemeralKeys.TreeBase, cpy.EphemeralKeys.TreeBase)
	a.Equal(signer.EphemeralKeys.ArrayBase, cpy.EphemeralKeys.ArrayBase)
	a.Equal(signer.EphemeralKeys, cpy.EphemeralKeys)
}

func TestKeySliceAfterSignerTrim(t *testing.T) {
	a := require.New(t)
	signer, err := New(1, 100, 1, crypto.PlaceHolderType)
	a.NoError(err)

	cpy, _ := signer.Trim(1)
	a.Equal(cpy.EphemeralKeys.TreeBase, uint64(1))
	a.Equal(len(cpy.EphemeralKeys.SignatureAlgorithms), 99)

	cpy, _ = signer.Trim(10)
	a.Equal(cpy.EphemeralKeys.TreeBase, uint64(1))
	a.Equal(cpy.EphemeralKeys.ArrayBase, uint64(10))
	a.Equal(len(cpy.EphemeralKeys.SignatureAlgorithms), 90)
	a.Equal(signer.EphemeralKeys.TreeBase, uint64(1))
	a.Equal(len(signer.EphemeralKeys.SignatureAlgorithms), 90)

	cpy, _ = signer.Trim(20)
	a.Equal(cpy.EphemeralKeys.TreeBase, uint64(1))
	a.Equal(cpy.EphemeralKeys.ArrayBase, uint64(20))
	a.Equal(len(cpy.EphemeralKeys.SignatureAlgorithms), 80)
	a.Equal(signer.EphemeralKeys.TreeBase, uint64(1))
	a.Equal(len(signer.EphemeralKeys.SignatureAlgorithms), 80)

	_, err = signer.Trim(101)
	a.Error(err)

	signer, err = New(1, 10, 1, crypto.PlaceHolderType)
	a.NoError(err)

	signer, err = New(1, 100, 11, crypto.PlaceHolderType)
	a.NoError(err)
	a.Equal(9, len(signer.EphemeralKeys.SignatureAlgorithms))

	// Should not trim, removes only keys from before current round
	signer.Trim(11)
	a.Equal(signer.EphemeralKeys.TreeBase, uint64(1))
	a.Equal(8, len(signer.EphemeralKeys.SignatureAlgorithms))

	signer.Trim(22)
	a.Equal(signer.EphemeralKeys.TreeBase, uint64(1))
	a.Equal(7, len(signer.EphemeralKeys.SignatureAlgorithms))

	_, err = signer.Trim(23)
	a.Error(err)

	signer.Trim(99)
	a.Equal(signer.EphemeralKeys.TreeBase, uint64(1))
	a.Equal(len(signer.EphemeralKeys.SignatureAlgorithms), 0)
}

func TestKeyDeletion(t *testing.T) {
	a := require.New(t)
	signer, err := New(1, 60, 1, crypto.PlaceHolderType)
	a.NoError(err)

	signer.Trim(50)
	_, err = signer.Sign(genHashableForTest(), 50)
	a.Error(err)

	for i := uint64(51); i <= 60; i++ {
		sig, err := signer.Sign(genHashableForTest(), i)
		a.NoError(err)

		a.NoError(signer.GetVerifier().Verify(1, i, 1, genHashableForTest(), sig))
	}

	signer, err = New(1, 60, 11, crypto.PlaceHolderType)
	a.NoError(err)

	signer.Trim(50)
	_, err = signer.Sign(genHashableForTest(), 49)
	a.Error(err)

	for i := uint64(50); i <= 60; i++ {
		sig, err := signer.Sign(genHashableForTest(), i)
		if i%11 != 0 {
			a.Error(err)
			continue
		}
		a.NoError(signer.GetVerifier().Verify(1, i, 11, genHashableForTest(), sig))
	}
}

func makeSig(signer *Signer, sigRound uint64, a *require.Assertions) (crypto.Hashable, Signature) {
	hashable := crypto.Hashable(&crypto.VerifyingKey{Type: math.MaxUint64}) // just want some crypto.Hashable..

	sig, err := signer.Sign(hashable, sigRound)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(signer.EphemeralKeys.TreeBase, sigRound, 1, hashable, sig))
	return hashable, sig
}

func getSigner(a *require.Assertions) (uint64, uint64, *Signer) {
	start, end := uint64(50), uint64(100)
	signer, err := New(start, end, 1, crypto.PlaceHolderType)
	a.NoError(err)
	return start, end, signer
}
