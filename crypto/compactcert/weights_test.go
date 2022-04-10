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

package compactcert

import (
	"math"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestMaxNumberOfRevealsInVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(10)
	provenWeight := uint64(10)
	lnProvenWt, err := lnIntApproximation(provenWeight, precisionBits)
	a.NoError(err)

	err = verifyWeights(signedWeight, lnProvenWt, MaxReveals+1, compactCertSecKQForTests)
	a.ErrorIs(err, ErrTooManyReveals)
}

func TestMaxNumberOfReveals(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1<<10 + 1)
	provenWeight := uint64(1 << 10)
	lnProvenWt, err := lnIntApproximation(provenWeight, precisionBits)
	a.NoError(err)

	_, err = numReveals(signedWeight, lnProvenWt, compactCertSecKQForTests)
	a.ErrorIs(err, ErrTooManyReveals)
}

func TestVerifyImpliedProvenWeightThreshold(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1 << 11)
	provenWeight := uint64(1 << 10)
	lnProvenWt, err := lnIntApproximation(provenWeight, precisionBits)
	a.NoError(err)

	numOfReveals, err := numReveals(signedWeight, lnProvenWt, compactCertSecKQForTests)
	a.NoError(err)

	err = verifyWeights(signedWeight, lnProvenWt, numOfReveals, compactCertSecKQForTests)
	a.NoError(err)

	err = verifyWeights(signedWeight, lnProvenWt, numOfReveals-1, compactCertSecKQForTests)
	a.ErrorIs(err, ErrInsufficientImpliedProvenWeight)
}

func TestVerifyZeroNumberOfRevealsEquation(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1<<15 + 1)
	provenWeight := uint64(1 << 15)
	lnProvenWt, err := lnIntApproximation(provenWeight, precisionBits)
	a.NoError(err)

	_, err = numReveals(signedWeight, lnProvenWt, compactCertSecKQForTests)
	a.ErrorIs(err, ErrNegativeNumOfRevealsEquation)
}

func TestLnWithPrecision(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	for i := 1; i < 32; i++ {
		exp := 1 << i
		val, err := lnIntApproximation(2, uint64(exp))
		a.NoError(err)

		a.GreaterOrEqual(float64(val)/float64(exp), math.Log(2))
		a.Greater(math.Log(2), float64(val-1)/float64(exp))
	}

	ln2, err := lnIntApproximation(2, precisionBits)
	a.NoError(err)
	a.Equal(ln2IntApproximation, ln2)
}

func TestVerifyLimits(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(0)
	provenWeight := uint64(1<<10 - 1)
	lnProvenWt, err := lnIntApproximation(provenWeight, precisionBits)
	a.NoError(err)

	err = verifyWeights(signedWeight, lnProvenWt, MaxReveals-1, compactCertSecKQForTests)
	a.ErrorIs(err, ErrZeroSignedWeight)
}

func TestNumRevealsApproxBound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	for j := 0; j < 10; j++ {
		sigWt := uint64(1<<(40-j) - 1)
		for i := 0; i < 10; i++ {
			provenWt := uint64(float64(sigWt) / (2 - (float64(i) / 10)))
			lnProvenWt, err := lnIntApproximation(provenWt, precisionBits)
			a.NoError(err)

			numOfReveals, err := numReveals(sigWt, lnProvenWt, compactCertSecKQForTests)
			a.NoError(err)

			log2Sig := math.Log(float64(sigWt)) / math.Log(2)
			log2Prov := math.Log(float64(provenWt)) / math.Log(2)
			nr := float64(compactCertSecKQForTests) / (log2Sig - log2Prov)
			a.Greater(1.01, float64(numOfReveals)/nr,
				"Approximated number of reveals exceeds limit. "+
					"limit %v, signedWeight: %v provenWeight %v, "+
					"appox numberOfReveals: %v, real numberOfReveals %v", 1.01, sigWt, provenWt, numOfReveals, nr)

		}
	}
}

func TestNumReveals(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	billion := uint64(1000 * 1000 * 1000)
	microalgo := uint64(1000 * 1000)
	provenWeight := 2 * billion * microalgo
	secKQ := uint64(compactCertSecKQForTests)
	bound := uint64(1000)
	lnProvenWt, err := lnIntApproximation(provenWeight, precisionBits)
	a.NoError(err)

	for i := uint64(3); i < 10; i++ {
		signedWeight := i * billion * microalgo
		n, err := numReveals(signedWeight, lnProvenWt, secKQ)
		a.NoError(err)
		n2, err := old(signedWeight, provenWeight, secKQ, bound)
		t.Logf("%f", float64(n2)/float64(n))
		t.Logf("old %d", n2)
		t.Logf("new %d ", n)
		if n < 50 || n > 300 {
			t.Errorf("numReveals(%d, %d, %d) = %d looks suspect",
				signedWeight, provenWeight, secKQ, n)
		}

		err = verifyWeights(signedWeight, lnProvenWt, n, compactCertSecKQForTests)
		a.NoError(err)
	}
}

func BenchmarkVerifyWeights(b *testing.B) {
	billion := uint64(1000 * 1000 * 1000)
	microalgo := uint64(1000 * 1000)
	provenWeight := 100 * billion * microalgo
	signedWeight := 110 * billion * microalgo
	secKQ := uint64(compactCertSecKQForTests)

	lnProvenWt, err := lnIntApproximation(provenWeight, precisionBits)
	require.NoError(b, err)

	nr, err := numReveals(signedWeight, lnProvenWt, secKQ)
	if nr < 900 {
		b.Errorf("numReveals(%d, %d, %d) = %d < 900", signedWeight, provenWeight, secKQ, nr)
	}
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		verifyWeights(signedWeight, lnProvenWt, nr, secKQ)
	}
}

func BenchmarkNumReveals(b *testing.B) {
	billion := uint64(1000 * 1000 * 1000)
	microalgo := uint64(1000 * 1000)
	provenWeight := 100 * billion * microalgo
	signedWeight := 110 * billion * microalgo
	secKQ := uint64(compactCertSecKQForTests)
	lnProvenWt, err := lnIntApproximation(provenWeight, precisionBits)
	require.NoError(b, err)

	nr, err := numReveals(signedWeight, lnProvenWt, secKQ)
	if nr < 900 {
		b.Errorf("numReveals(%d, %d, %d) = %d < 900", signedWeight, provenWeight, secKQ, nr)
	}
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		numReveals(signedWeight, lnProvenWt, secKQ)
	}
}
