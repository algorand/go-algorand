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

package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBatchVerifierSingle(t *testing.T) {
	// test expected success
	bv := MakeBatchVerifier(1)
	msg := randString()
	var s Seed
	RandBytes(s[:])
	sigSecrets := GenerateSignatureSecrets(s)
	sig := sigSecrets.Sign(msg)
	bv.Enqueue(sigSecrets.SignatureVerifier, msg, sig)
	require.True(t, bv.VerifySlow())
	require.True(t, bv.Verify())

	// test expected failuire
	bv = MakeBatchVerifier(1)
	msg = randString()
	RandBytes(s[:])
	sigSecrets = GenerateSignatureSecrets(s)
	sig = sigSecrets.Sign(msg)
	// break the signature:
	sig[0] = sig[0] + 1
	bv.Enqueue(sigSecrets.SignatureVerifier, msg, sig)
	require.False(t, bv.VerifySlow())
	require.False(t, bv.Verify())
}

func TestBatchVerifierBulk(t *testing.T) {
	n := 149
	bv := MakeBatchVerifier(n)
	var s Seed
	RandBytes(s[:])

	for i := 0; i < n; i++ {
		msg := randString()
		sigSecrets := GenerateSignatureSecrets(s)
		sig := sigSecrets.Sign(msg)
		bv.Enqueue(sigSecrets.SignatureVerifier, msg, sig)
	}
	require.True(t, bv.VerifySlow())
	require.True(t, bv.Verify())
}

func BenchmarkBatchVerifier(b *testing.B) {
	c := makeCurve25519Secret()
	bv := MakeBatchVerifier(1)
	for i := 0; i < b.N; i++ {
		str := randString()
		bv.Enqueue(c.SignatureVerifier, str, c.Sign(str))
	}

	b.ResetTimer()
	require.True(b, bv.Verify())
}
