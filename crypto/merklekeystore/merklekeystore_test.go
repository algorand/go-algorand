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
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestSignerCreation(t *testing.T) {
	a := require.New(t)

	h := genHashableForTest()
	for i := uint64(0); i < 20; i++ {
		signer, err := New(i, i+1)
		a.NoError(err)
		_, err = signer.Sign(h, int(i))
		a.NoError(err)
	}

	_, err := New(1, 0)
	a.Error(err)

}
func TestDisposableKeyPositions(t *testing.T) {
	a := require.New(t)
	signer, err := New(0, 100)
	a.NoError(err)

	for i := 0; i < 100; i++ {
		pos, err := signer.getKeyPosition(uint64(i))
		a.NoError(err, i)
		a.Equal(uint64(i), pos)
	}

	_, err = signer.getKeyPosition(uint64(100))
	a.Error(err)

	signer, err = New(1000, 1100)
	a.NoError(err)

	for i := 1000; i < 1100; i++ {
		pos, err := signer.getKeyPosition(uint64(i))
		a.NoError(err, i)
		a.Equal(uint64(i-1000), pos)
	}

	_, err = signer.getKeyPosition(uint64(999))
	a.Error(err)
}

func TestNonEmptyDisposableKeys(t *testing.T) {
	a := require.New(t)
	signer, err := New(0, 100)
	a.NoError(err)

	s := crypto.SignatureAlgorithm{}
	for _, key := range signer.disposableKeys {
		a.NotEqual(s, key)
	}
}

func TestSignatureStructure(t *testing.T) {
	a := require.New(t)
	signer, err := New(50, 100)
	a.NoError(err)

	hashable := genHashableForTest()
	sig, err := signer.Sign(hashable, 51)
	a.NoError(err)

	pos, err := signer.getKeyPosition(51)
	a.NoError(err)
	a.Equal(uint64(1), pos)
	a.Equal(sig.pos, pos)

	key := signer.disposableKeys[pos]
	a.Equal(*sig.VerifyingKey, key.GetSigner().GetVerifyingKey())

	proof, err := signer.tree.Prove([]uint64{1})
	a.NoError(err)
	a.Equal(proof, sig.Proof)
}

func genHashableForTest() crypto.Hashable {
	hashable := crypto.Hashable(&crypto.VerifyingKey{Type: math.MaxUint64}) // just want some crypto.Hashable..
	return hashable
}

func TestSigning(t *testing.T) {
	a := require.New(t)

	start, end := 50, 100
	signer, err := New(uint64(start), uint64(end))
	a.NoError(err)

	hashable := crypto.Hashable(&crypto.VerifyingKey{Type: math.MaxUint64}) // just want some crypto.Hashable..

	sig, err := signer.Sign(hashable, start+1)
	a.NoError(err)
	a.NoError(signer.GetVerifier().Verify(hashable, sig))

	_, err = signer.Sign(hashable, start-1)
	a.Error(err)

	_, err = signer.Sign(hashable, end+1)
	a.Error(err)

	t.Run("incorrect byte signature", func(t *testing.T) {
		t.Parallel()
		sig := sig
		bs := make([]byte, len(sig.ByteSignature))
		copy(bs, sig.ByteSignature)
		bs[0]++
		sig.ByteSignature = bs
		a.Error(signer.GetVerifier().Verify(hashable, sig))
	})

	t.Run("incorrect merkle proof", func(t *testing.T) {
		t.Parallel()
		sig := sig
		sig.Proof = sig.Proof[:len(sig.Proof)-1]
		a.Error(signer.GetVerifier().Verify(hashable, sig))

		sig2 := sig
		someDigest := crypto.Digest{}
		rand.Read(someDigest[:])
		sig2.Proof[0] = someDigest
		a.Error(signer.GetVerifier().Verify(hashable, sig))
	})

	t.Run("bad leaf position in signature", func(t *testing.T) {
		t.Parallel()
		sig := sig
		sig.pos++
		a.Error(signer.GetVerifier().Verify(hashable, sig))

		sig2 := sig
		sig2.pos = uint64(end + 1)
		a.Error(signer.GetVerifier().Verify(hashable, sig2))

		sig3 := sig
		sig3.pos = uint64(start - 1)
		a.Error(signer.GetVerifier().Verify(hashable, sig3))
	})

}
