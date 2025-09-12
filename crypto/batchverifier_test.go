// Copyright (C) 2019-2025 Algorand, Inc.
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
	"fmt"
	"math/rand"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// runnableTB is an interface constraint for types that have both testing.TB methods and Run
type runnableTB[T any] interface {
	testing.TB
	Run(string, func(T)) bool
}

// runBatchVerifierImpls runs testing.{T,B}.Run against 3 batch verifier implementations as subtests.
func runBatchVerifierImpls[T runnableTB[T]](tb T, runFunc func(T, func(int) BatchVerifier)) {
	tb.Run("libsodium_single", func(t T) {
		runFunc(t, func(hint int) BatchVerifier {
			bv := makeLibsodiumBatchVerifier(hint)
			bv.(*cgoBatchVerifier).useSingle = true
			return bv
		})
	})
	tb.Run("libsodium_batch", func(t T) {
		runFunc(t, func(hint int) BatchVerifier {
			bv := makeLibsodiumBatchVerifier(hint)
			bv.(*cgoBatchVerifier).useSingle = false
			return bv
		})
	})
	tb.Run("ed25519consensus", func(t T) {
		runFunc(t, func(hint int) BatchVerifier {
			return makeEd25519ConsensusBatchVerifier(hint)
		})
	})
}

func TestBatchVerifierSingle(t *testing.T) {
	partitiontest.PartitionTest(t)
	runBatchVerifierImpls(t, testBatchVerifierSingle)
}
func testBatchVerifierSingle(t *testing.T, makeBV func(int) BatchVerifier) {
	// test expected success
	bv := makeBV(0)
	msg := randString()
	var s Seed
	RandBytes(s[:])
	sigSecrets := GenerateSignatureSecrets(s)
	sig := sigSecrets.Sign(msg)
	bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
	require.NoError(t, bv.Verify())

	// test expected failure
	bv = makeBV(0)
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
	runBatchVerifierImpls(t, testBatchVerifierBulk)
}
func testBatchVerifierBulk(t *testing.T, makeBV func(int) BatchVerifier) {
	for i := 1; i < 64*2+3; i++ {
		n := i
		bv := makeBV(n)
		var s Seed

		for i := 0; i < n; i++ {
			msg := randString()
			RandBytes(s[:])
			sigSecrets := GenerateSignatureSecrets(s)
			sig := sigSecrets.Sign(msg)
			bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
		}
		require.Equal(t, n, bv.GetNumberOfEnqueuedSignatures())
		require.NoError(t, bv.Verify())
	}
}

func TestBatchVerifierBulkWithExpand(t *testing.T) {
	partitiontest.PartitionTest(t)
	runBatchVerifierImpls(t, testBatchVerifierBulkWithExpand)
}
func testBatchVerifierBulkWithExpand(t *testing.T, makeBV func(int) BatchVerifier) {
	n := 64
	bv := makeBV(0) // Start with no hint to test expansion
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
	runBatchVerifierImpls(t, testBatchVerifierWithInvalidSignature)
}
func testBatchVerifierWithInvalidSignature(t *testing.T, makeBV func(int) BatchVerifier) {
	n := 64
	bv := makeBV(0)
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
	runBatchVerifierImpls(b, benchmarkBatchVerifier)
}
func benchmarkBatchVerifier(b *testing.B, makeBV func(int) BatchVerifier) {
	c := makeCurve25519Secret()
	bv := makeBV(1)
	for i := 0; i < b.N; i++ {
		str := randString()
		bv.EnqueueSignature(c.SignatureVerifier, str, c.Sign(str))
	}

	b.ResetTimer()
	require.NoError(b, bv.Verify())
}

// BenchmarkBatchVerifierBig with b.N over 1000 will report the expected performance
// gain as the batchsize increases. All sigs are valid.
func BenchmarkBatchVerifierBig(b *testing.B) {
	runBatchVerifierImpls(b, benchmarkBatchVerifierBig)
}
func benchmarkBatchVerifierBig(b *testing.B, makeBV func(int) BatchVerifier) {
	c := makeCurve25519Secret()
	for batchSize := 1; batchSize <= 96; batchSize++ {
		bv := makeBV(batchSize)
		for i := 0; i < batchSize; i++ {
			str := randString()
			bv.EnqueueSignature(c.SignatureVerifier, str, c.Sign(str))
		}
		b.Run(fmt.Sprintf("running batchsize %d", batchSize), func(b *testing.B) {
			totalTransactions := b.N
			count := totalTransactions / batchSize
			if count*batchSize < totalTransactions {
				count++
			}
			for x := 0; x < count; x++ {
				require.NoError(b, bv.Verify())
			}
		})
	}
}

// BenchmarkBatchVerifierBigWithInvalid builds over BenchmarkBatchVerifierBig by introducing
// invalid sigs to even numbered batch sizes. This shows the impact of invalid sigs on the
// performance. Basically, all the gains from batching disappear.
func BenchmarkBatchVerifierBigWithInvalid(b *testing.B) {
	runBatchVerifierImpls(b, benchmarkBatchVerifierBigWithInvalid)
}
func benchmarkBatchVerifierBigWithInvalid(b *testing.B, makeBV func(int) BatchVerifier) {
	c := makeCurve25519Secret()
	badSig := Signature{}
	for batchSize := 1; batchSize <= 96; batchSize++ {
		bv := makeBV(batchSize)
		sigs := make([]Signature, batchSize)
		for i := 0; i < batchSize; i++ {
			str := randString()
			if batchSize%2 == 0 && (i == 0 || rand.Float32() < 0.1) {
				bv.EnqueueSignature(c.SignatureVerifier, str, badSig)
				sigs[i] = badSig
			} else {
				sig := c.Sign(str)
				bv.EnqueueSignature(c.SignatureVerifier, str, sig)
				sigs[i] = sig
			}
		}
		b.Run(fmt.Sprintf("running batchsize %d", batchSize), func(b *testing.B) {
			totalTransactions := b.N
			count := totalTransactions / batchSize
			if count*batchSize < totalTransactions {
				count++
			}
			for x := 0; x < count; x++ {
				failed, err := bv.VerifyWithFeedback()
				if err != nil {
					require.Len(b, failed, batchSize)
					for i, f := range failed {
						if sigs[i] == badSig {
							require.True(b, f)
						} else {
							require.False(b, f)
						}
					}
				} else {
					require.Nil(b, failed)
				}
			}
		})
	}
}

func TestEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	runBatchVerifierImpls(t, testEmpty)
}
func testEmpty(t *testing.T, makeBV func(int) BatchVerifier) {
	bv := makeBV(0)
	require.NoError(t, bv.Verify())

	failed, err := bv.VerifyWithFeedback()
	require.NoError(t, err)
	require.Nil(t, failed)
}

// TestBatchVerifierIndividualResults tests that VerifyWithFeedback
// returns the correct failed signature indexes
func TestBatchVerifierIndividualResults(t *testing.T) {
	partitiontest.PartitionTest(t)
	runBatchVerifierImpls(t, testBatchVerifierIndividualResults)
}
func testBatchVerifierIndividualResults(t *testing.T, makeBV func(int) BatchVerifier) {
	for i := 1; i < 64*2+3; i++ {
		n := i
		bv := makeBV(n)
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
		require.Equal(t, n, bv.GetNumberOfEnqueuedSignatures())
		failed, err := bv.VerifyWithFeedback()
		if hasBadSig {
			require.ErrorIs(t, err, ErrBatchHasFailedSigs)
			require.Equal(t, len(badSigs), len(failed))
			for i := range badSigs {
				require.Equal(t, badSigs[i], failed[i])
			}
		} else {
			require.NoError(t, err)
			require.Nil(t, failed)
		}
	}
}

// TestBatchVerifierIndividualResultsAllValid tests that VerifyWithFeedback
// returns the correct failed signature indexes when all are valid
func TestBatchVerifierIndividualResultsAllValid(t *testing.T) {
	partitiontest.PartitionTest(t)
	runBatchVerifierImpls(t, testBatchVerifierIndividualResultsAllValid)
}
func testBatchVerifierIndividualResultsAllValid(t *testing.T, makeBV func(int) BatchVerifier) {
	for i := 1; i < 64*2+3; i++ {
		n := i
		bv := makeBV(n)
		var s Seed
		for i := 0; i < n; i++ {
			msg := randString()
			RandBytes(s[:])
			sigSecrets := GenerateSignatureSecrets(s)
			sig := sigSecrets.Sign(msg)
			bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
		}
		require.Equal(t, n, bv.GetNumberOfEnqueuedSignatures())
		failed, err := bv.VerifyWithFeedback()
		require.NoError(t, err)
		require.Nil(t, failed)
	}
}

func TestBatchVerifierGC(t *testing.T) {
	partitiontest.PartitionTest(t)

	const n = 128
	for i := 0; i < 100; i++ {
		t.Run("", func(t *testing.T) {
			t.Parallel()

			bv := makeLibsodiumBatchVerifier(n)
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
