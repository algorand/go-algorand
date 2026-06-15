// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"crypto/ed25519"
	"encoding/hex"
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

func TestIsEdwards25519Point(t *testing.T) {
	partitiontest.PartitionTest(t)

	decodeHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("invalid test vector %q: %v", s, err)
		}
		return b
	}

	// These vectors document the LogicSig rejection-sampling predicate. It is
	// broader than strict Ed25519 public-key validation.
	testCases := []struct {
		name  string
		input []byte
		valid bool
	}{
		{
			name:  "basepoint",
			input: decodeHex("5866666666666666666666666666666666666666666666666666666666666666"),
			valid: true,
		},
		{
			name:  "identity small-order point",
			input: decodeHex("0100000000000000000000000000000000000000000000000000000000000000"),
			valid: true,
		},
		{
			name:  "identity with non-canonical sign bit",
			input: decodeHex("0100000000000000000000000000000000000000000000000000000000000080"),
			valid: true,
		},
		{
			name:  "non-canonical y equals p",
			input: decodeHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
			valid: true,
		},
		{
			name:  "invalid y equals p plus 2",
			input: decodeHex("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
			valid: false,
		},
		{
			name:  "empty input",
			input: nil,
			valid: false,
		},
		{
			name:  "short input",
			input: make([]byte, 31),
			valid: false,
		},
		{
			name:  "long input",
			input: make([]byte, 33),
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsEdwards25519Point(tc.input)
			if got != tc.valid {
				t.Fatalf("IsEdwards25519Point() = %t, expected %t", got, tc.valid)
			}
		})
	}
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
	b.Run("libsodium", func(b *testing.B) {
		benchmarkSign(b, func(sk ed25519PrivateKey, msg []byte) Signature {
			return Signature(ed25519Sign(sk, msg))
		})
	})
	b.Run("ed25519stdlib", func(b *testing.B) {
		benchmarkSign(b, func(sk ed25519PrivateKey, msg []byte) Signature {
			return Signature(ed25519.Sign(ed25519.PrivateKey(sk[:]), msg))
		})
	})
}

func benchmarkSign(b *testing.B, sign func(ed25519PrivateKey, []byte) Signature) {
	c := makeCurve25519Secret()
	s := randString()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = sign(c.SK, HashRep(s))
	}
}

func BenchmarkVerify25519(b *testing.B) {
	b.Run("libsodium", func(b *testing.B) {
		benchmarkVerify25519(b, func(pk SignatureVerifier, msg []byte, sig Signature) bool {
			return ed25519Verify(ed25519PublicKey(pk), msg, ed25519Signature(sig))
		})
	})
	b.Run("ed25519consensus", func(b *testing.B) {
		benchmarkVerify25519(b, func(pk SignatureVerifier, msg []byte, sig Signature) bool {
			return ed25519ConsensusVerifySingle(pk, msg, sig)
		})
	})
}

func benchmarkVerify25519(b *testing.B, verify func(SignatureVerifier, []byte, Signature) bool) {
	c := makeCurve25519Secret()
	strs := make([]TestingHashable, b.N)
	sigs := make([]Signature, b.N)
	for i := 0; i < b.N; i++ {
		strs[i] = randString()
		sigs[i] = c.Sign(strs[i])
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !verify(c.SignatureVerifier, HashRep(strs[i]), sigs[i]) {
			b.Error("BAD: valid signature not valid")
		}
	}
}
