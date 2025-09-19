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
	cryptorand "crypto/rand"
	"io"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func randSignedMsg(t testing.TB, r io.Reader) (SignatureVerifier, Hashable, Signature) {
	mlen := 100
	msg := TestingHashable{data: make([]byte, mlen)}
	n, err := r.Read(msg.data)
	require.NoError(t, err)
	require.Equal(t, n, mlen)
	var s Seed
	n, err = r.Read(s[:])
	require.NoError(t, err)
	require.Equal(t, 32, n)
	secrets := GenerateSignatureSecrets(s)
	return secrets.SignatureVerifier, msg, secrets.Sign(msg)
}

// BenchmarkBatchVerifierImpls benchmarks different batch verification implementations
// with realistic batch sizes (100 batches of 64 signatures each)
func BenchmarkBatchVerifierImpls(b *testing.B) {
	partitiontest.PartitionTest(b)

	numBatches := 100
	batchSize := 64
	msgs := make([][]Hashable, numBatches)
	pks := make([][]SignatureVerifier, numBatches)
	sigs := make([][]Signature, numBatches)
	r := cryptorand.Reader
	for i := 0; i < numBatches; i++ {
		for j := 0; j < batchSize; j++ {
			pk, msg, sig := randSignedMsg(b, r)
			msgs[i] = append(msgs[i], msg)
			pks[i] = append(pks[i], pk)
			sigs[i] = append(sigs[i], sig)
		}
	}

	b.Log("running with", b.N, "iterations using", len(msgs), "batches of", batchSize, "signatures")
	runImpl := func(b *testing.B, bv BatchVerifier,
		msgs [][]Hashable, pks [][]SignatureVerifier, sigs [][]Signature) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			batchIdx := i % numBatches
			for j := range msgs[batchIdx] {
				bv.EnqueueSignature(pks[batchIdx][j], msgs[batchIdx][j], sigs[batchIdx][j])
			}
			require.NoError(b, bv.Verify())
		}
	}

	b.Run("libsodium_single", func(b *testing.B) {
		bv := makeLibsodiumBatchVerifier(batchSize)
		bv.(*cgoBatchVerifier).useSingle = true
		runImpl(b, bv, msgs, pks, sigs)
	})
	b.Run("libsodium_batch", func(b *testing.B) {
		bv := makeLibsodiumBatchVerifier(batchSize)
		bv.(*cgoBatchVerifier).useSingle = false
		runImpl(b, bv, msgs, pks, sigs)
	})
	b.Run("ed25519consensus", func(b *testing.B) {
		bv := makeEd25519ConsensusBatchVerifier(batchSize)
		runImpl(b, bv, msgs, pks, sigs)
	})
}

func BenchmarkCanonicalityCheck(b *testing.B) {
	partitiontest.PartitionTest(b)

	const maxN = 10000
	pubkeys := make([]SignatureVerifier, maxN)
	sigs := make([]Signature, maxN)
	for i := 0; i < maxN; i++ {
		var s Seed
		RandBytes(s[:])
		sigSecrets := GenerateSignatureSecrets(s)
		pubkeys[i] = sigSecrets.SignatureVerifier
		msg := randString()
		sigs[i] = sigSecrets.Sign(msg)
	}

	b.Run("pubkey_check", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = isCanonicalPoint(pubkeys[i%maxN])
		}
	})

	b.Run("signature_R_check", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = isCanonicalPoint([32]byte(sigs[i%maxN][:32]))
		}
	})

	b.Run("both_checks", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = !isCanonicalPoint(pubkeys[i%maxN]) || !isCanonicalPoint([32]byte(sigs[i%maxN][:32]))
		}
	})
}
