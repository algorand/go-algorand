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

package crypto

import (
	"bytes"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func makeCurve25519Secret() *SignatureSecrets {
	var s Seed
	RandBytes(s[:])
	return GenerateSignatureSecrets(s)
}

func TestSignVerifyEmptyMessage(t *testing.T) {
	partitiontest.PartitionTest(t)
	pk, sk := ed25519GenerateKey()
	sig := ed25519Sign(sk, []byte{})
	if !ed25519Verify(pk, []byte{}, sig) {
		t.Errorf("sig of an empty message failed to verify")
	}
}

func TestVerifyZeros(t *testing.T) {
	partitiontest.PartitionTest(t)
	var pk SignatureVerifier
	var sig Signature
	for x := byte(0); x < 255; x++ {
		if pk.VerifyBytes([]byte{x}, sig) {
			t.Errorf("Zero sig with zero pk successfully verified message %x", x)
		}
	}
}

func TestGenerateSignatureSecrets(t *testing.T) {
	partitiontest.PartitionTest(t)
	var s Seed
	RandBytes(s[:])
	ref := GenerateSignatureSecrets(s)
	for i := 0; i < 10; i++ {
		secrets := GenerateSignatureSecrets(s)
		if bytes.Compare(ref.SignatureVerifier[:], secrets.SignatureVerifier[:]) != 0 {
			t.Errorf("SignatureSecrets.SignatureVerifier is inconsistent; different results generated for the same seed")
			return
		}
		if bytes.Compare(ref.SK[:], secrets.SK[:]) != 0 {
			t.Errorf("SignatureSecrets.SK is inconsistent; different results generated for the same seed")
			return
		}
	}
}

func TestCurve25519SignVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	signVerify(t, makeCurve25519Secret(), makeCurve25519Secret())
}

func TestVRFProveVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	proveVerifyVrf(t, GenerateVRFSecrets(), GenerateVRFSecrets())
}

func BenchmarkSignVerify(b *testing.B) {
	c := makeCurve25519Secret()
	s := randString()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sig := c.Sign(s)
		_ = c.Verify(s, sig)
	}
}

func BenchmarkSign(b *testing.B) {
	c := makeCurve25519Secret()
	s := randString()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = c.Sign(s)
	}
}
func BenchmarkVerify25519(b *testing.B) {
	c := makeCurve25519Secret()
	strs := make([]TestingHashable, b.N)
	sigs := make([]Signature, b.N)
	for i := 0; i < b.N; i++ {
		strs[i] = randString()
		sigs[i] = c.Sign(strs[i])
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = c.Verify(strs[i], sigs[i])
	}
}
