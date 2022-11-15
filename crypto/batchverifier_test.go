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

package crypto

import (
	"math/rand"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestBatchVerifierSingle(t *testing.T) {
	partitiontest.PartitionTest(t)
	// test expected success
	bv := MakeBatchVerifier()
	msg := randString()
	var s Seed
	RandBytes(s[:])
	sigSecrets := GenerateSignatureSecrets(s)
	sig := sigSecrets.Sign(msg)
	bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
	require.NoError(t, bv.Verify())

	// test expected failure
	bv = MakeBatchVerifier()
	msg = randString()
	RandBytes(s[:])
	sigSecrets = GenerateSignatureSecrets(s)
	sig = sigSecrets.Sign(msg)
	// break the signature:
	sig[0] = sig[0] + 1
	bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
	require.Error(t, bv.Verify())
}

func TestBatchVerifierBulk(t *testing.T) {
	partitiontest.PartitionTest(t)
	for i := 1; i < 64*2+3; i++ {
		n := i
		bv := MakeBatchVerifierWithHint(n)
		var s Seed

		for i := 0; i < n; i++ {
			msg := randString()
			RandBytes(s[:])
			sigSecrets := GenerateSignatureSecrets(s)
			sig := sigSecrets.Sign(msg)
			bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
		}
		require.Equal(t, n, bv.getNumberOfEnqueuedSignatures())
		require.NoError(t, bv.Verify())
	}

}

func TestBatchVerifierBulkWithExpand(t *testing.T) {
	partitiontest.PartitionTest(t)
	n := 64
	bv := MakeBatchVerifier()
	var s Seed
	RandBytes(s[:])

	for i := 0; i < n; i++ {
		msg := randString()
		sigSecrets := GenerateSignatureSecrets(s)
		sig := sigSecrets.Sign(msg)
		bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
	}
	require.NoError(t, bv.Verify())
}

func TestBatchVerifierWithInvalidSiganture(t *testing.T) {
	partitiontest.PartitionTest(t)
	n := 64
	bv := MakeBatchVerifier()
	var s Seed
	RandBytes(s[:])

	for i := 0; i < n-1; i++ {
		msg := randString()
		sigSecrets := GenerateSignatureSecrets(s)
		sig := sigSecrets.Sign(msg)
		bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
	}

	msg := randString()
	sigSecrets := GenerateSignatureSecrets(s)
	sig := sigSecrets.Sign(msg)
	sig[0] = sig[0] + 1
	bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)

	require.Error(t, bv.Verify())
}

func BenchmarkBatchVerifier(b *testing.B) {
	c := makeCurve25519Secret()
	bv := MakeBatchVerifierWithHint(1)
	for i := 0; i < b.N; i++ {
		str := randString()
		bv.EnqueueSignature(c.SignatureVerifier, str, c.Sign(str))
	}

	b.ResetTimer()
	require.NoError(b, bv.Verify())
}

func TestEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	bv := MakeBatchVerifier()
	require.NoError(t, bv.Verify())

	failed, err := bv.VerifyWithFeedback()
	require.NoError(t, err)
	require.Empty(t, failed)
}

// TestBatchVerifierIndividualResults tests that VerifyWithFeedback
// returns the correct failed signature indexes
func TestBatchVerifierIndividualResults(t *testing.T) {
	partitiontest.PartitionTest(t)

	for i := 1; i < 64*2+3; i++ {
		n := i
		bv := MakeBatchVerifierWithHint(n)
		var s Seed
		badSigs := make([]bool, n, n)
		hasBadSig := false
		for i := 0; i < n; i++ {
			msg := randString()
			RandBytes(s[:])
			sigSecrets := GenerateSignatureSecrets(s)
			sig := sigSecrets.Sign(msg)
			if rand.Float32() > 0.5 {
				// make a bad sig
				sig[0] = sig[0] + 1
				badSigs[i] = true
				hasBadSig = true
			}
			bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
		}
		require.Equal(t, n, bv.getNumberOfEnqueuedSignatures())
		failed, err := bv.VerifyWithFeedback()
		if hasBadSig {
			require.ErrorIs(t, err, ErrBatchVerificationFailed)
		} else {
			require.NoError(t, err)
		}
		require.Equal(t, len(badSigs), len(failed))
		for i := range badSigs {
			require.Equal(t, badSigs[i], failed[i])
		}
	}
}

// TestBatchVerifierIndividualResultsAllValid tests that VerifyWithFeedback
// returns the correct failed signature indexes when all are valid
func TestBatchVerifierIndividualResultsAllValid(t *testing.T) {
	partitiontest.PartitionTest(t)

	for i := 1; i < 64*2+3; i++ {
		n := i
		bv := MakeBatchVerifierWithHint(n)
		var s Seed
		for i := 0; i < n; i++ {
			msg := randString()
			RandBytes(s[:])
			sigSecrets := GenerateSignatureSecrets(s)
			sig := sigSecrets.Sign(msg)
			bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
		}
		require.Equal(t, n, bv.getNumberOfEnqueuedSignatures())
		failed, err := bv.VerifyWithFeedback()
		require.NoError(t, err)
		require.Equal(t, bv.getNumberOfEnqueuedSignatures(), len(failed))
		for _, f := range failed {
			require.False(t, f)
		}
	}
}

func TestBatchVerifierGC(t *testing.T) {
	partitiontest.PartitionTest(t)

	const n = 128
	for i := 0; i < 100; i++ {
		t.Run("", func(t *testing.T) {
			t.Parallel()

			bv := MakeBatchVerifierWithHint(n)
			var s Seed

			for i := 0; i < n; i++ {
				msg := randString()
				RandBytes(s[:])
				sigSecrets := GenerateSignatureSecrets(s)
				sig := sigSecrets.Sign(msg)
				bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
			}
			require.NoError(t, bv.Verify())

			runtime.GC()
		})
	}

}
