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
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestSignerCreation(t *testing.T) {
	a := require.New(t)

	h := genHashableForTest()
	for i := uint64(0); i < 20; i++ {
		signer, err := New(basics.Round(i), basics.Round(i+1), crypto.PlaceHolderType)
		a.NoError(err)
		_, err = signer.Sign(h, basics.Round(i))
		a.NoError(err)
	}

	_, err := New(1, 0, crypto.PlaceHolderType)
	a.Error(err)

	signer, err := New(0, 0, crypto.PlaceHolderType)
	a.NoError(err)
	sig, err := signer.Sign(genHashableForTest(), 0)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(genHashableForTest(), sig))
	a.Equal(1, len(signer.EphemeralKeys))

}
func TestDisposableKeyPositions(t *testing.T) {
	a := require.New(t)
	signer, err := New(0, 100, crypto.PlaceHolderType)
	a.NoError(err)

	for i := 0; i < 100; i++ {
		pos, err := signer.getKeyPosition(basics.Round(i))
		a.NoError(err, i)
		a.Equal(uint64(i), pos)
	}

	_, err = signer.getKeyPosition(101)
	a.Error(err)

	signer, err = New(1000, 1100, crypto.PlaceHolderType)
	a.NoError(err)

	for i := 1000; i < 1100; i++ {
		pos, err := signer.getKeyPosition(basics.Round(i))
		a.NoError(err, i)
		a.Equal(uint64(i-1000), pos)
	}

	_, err = signer.getKeyPosition(999)
	a.Error(err)
}

func TestNonEmptyDisposableKeys(t *testing.T) {
	a := require.New(t)
	signer, err := New(0, 100, crypto.PlaceHolderType)
	a.NoError(err)

	s := crypto.SignatureAlgorithm{}
	for _, key := range signer.EphemeralKeys {
		a.NotEqual(s, key)
	}
}

func TestSignatureStructure(t *testing.T) {
	a := require.New(t)
	signer, err := New(50, 100, crypto.PlaceHolderType)
	a.NoError(err)

	hashable := genHashableForTest()
	sig, err := signer.Sign(hashable, 51)
	a.NoError(err)

	pos, err := signer.getKeyPosition(51)
	a.NoError(err)
	a.Equal(uint64(1), pos)
	a.Equal(sig.Pos, pos)

	key := signer.EphemeralKeys[pos]
	a.Equal(sig.VerifyingKey, key.GetSigner().GetVerifyingKey())

	proof, err := signer.Prove([]uint64{1})
	a.NoError(err)
	a.Equal(Proof(proof), sig.Proof)
}

func genHashableForTest() crypto.Hashable {
	hashable := crypto.Hashable(&crypto.VerifyingKey{Type: math.MaxUint64}) // just want some crypto.Hashable..
	return hashable
}

func TestSigning(t *testing.T) {
	a := require.New(t)

	start, end, signer := getValidSig(a)

	hashable := crypto.Hashable(&crypto.VerifyingKey{Type: math.MaxUint64}) // just want some crypto.Hashable..

	sig, err := signer.Sign(hashable, basics.Round(start+1))
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(hashable, sig))

	_, err = signer.Sign(hashable, basics.Round(start-1))
	a.Error(err)

	_, err = signer.Sign(hashable, basics.Round(end+1))
	a.Error(err)
}

func TestBadLeafPositionInSignature(t *testing.T) {
	a := require.New(t)
	start, end, signer := getValidSig(a)

	hashable, sig := makeSig(signer, start, a)

	sig2 := sig
	sig2.Pos++
	a.Error(signer.GetVerifier().Verify(hashable, sig2))

	sig3 := sig2
	sig3.Pos = uint64(end + 1)
	a.Error(signer.GetVerifier().Verify(hashable, sig3))

	sig4 := sig2
	sig4.Pos = uint64(start - 1)
	a.Error(signer.GetVerifier().Verify(hashable, sig4))
}

func TestBadMerkleProofInSignature(t *testing.T) {
	a := require.New(t)
	start, _, signer := getValidSig(a)

	hashable, sig := makeSig(signer, start, a)

	sig2 := sig
	sig2.Proof = sig2.Proof[:len(sig2.Proof)-1]
	a.Error(signer.GetVerifier().Verify(hashable, sig2))

	sig3 := sig2
	someDigest := crypto.Digest{}
	rand.Read(someDigest[:])
	sig3.Proof[0] = someDigest
	a.Error(signer.GetVerifier().Verify(hashable, sig3))
}

func TestIncorrectByteSignature(t *testing.T) {
	a := require.New(t)
	start, _, signer := getValidSig(a)

	hashable, sig := makeSig(signer, start, a)

	sig2 := sig
	bs := make([]byte, len(sig.ByteSignature))
	copy(bs, sig2.ByteSignature)
	bs[0]++
	sig2.ByteSignature = bs
	a.Error(signer.GetVerifier().Verify(hashable, sig2))
}

func makeSig(signer *Signer, start int, a *require.Assertions) (crypto.Hashable, Signature) {
	hashable := crypto.Hashable(&crypto.VerifyingKey{Type: math.MaxUint64}) // just want some crypto.Hashable..

	sig, err := signer.Sign(hashable, basics.Round(start+1))
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(hashable, sig))
	return hashable, sig
}

func getValidSig(a *require.Assertions) (int, int, *Signer) {
	start, end := 50, 100
	signer, err := New(basics.Round(start), basics.Round(end), crypto.PlaceHolderType)
	a.NoError(err)
	return start, end, signer
}
