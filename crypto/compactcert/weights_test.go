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

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func numRevealsForTests(signedWeight uint64, provenWeight uint64, secKQ uint64) (uint64, error) {
	p := Params{SecKQ: secKQ, ProvenWeightThreshold: provenWeight}
	lnProvenWt := lnIntApproximation(provenWeight, precisionBits)
	b := &Builder{
		Params:                  p,
		signedWeight:            signedWeight,
		lnProvenWeightThreshold: lnProvenWt,
	}
	return b.numReveals()
}

func TestVerifyMaxNumberOfRevealsInVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(10)
	provenWeight := uint64(10)

	param := Params{SecKQ: 128, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})
	err := verifier.verifyWeights(signedWeight, MaxReveals+1)
	a.ErrorIs(err, ErrTooManyReveals)
}

func TestVerifyMaxNumberOfReveals(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1<<10 + 1)
	provenWeight := uint64(1 << 10)

	_, err := numRevealsForTests(signedWeight, provenWeight, compactCertSecKQForTests)
	a.ErrorIs(err, ErrTooManyReveals)
}

func TestVerifySignedWeightLessThanProvenWeight(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1 << 10)
	provenWeight := uint64(1<<10 + 1)

	param := Params{SecKQ: compactCertSecKQForTests, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})
	err := verifier.verifyWeights(signedWeight, compactCertSecKQForTests)
	a.ErrorIs(err, ErrSignedWeightLessThanProvenWeight)
}

func TestVerifyImpliedProvenGreaterThanThreshold(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1<<10 + 93)
	provenWeight := uint64(1 << 10)

	numOfReveals, err := numRevealsForTests(signedWeight, provenWeight, compactCertSecKQForTests)

	param := Params{SecKQ: compactCertSecKQForTests, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})
	err = verifier.verifyWeights(signedWeight, numOfReveals)
	a.NoError(err)

	signedWeight = uint64(1<<10 + 92)
	provenWeight = uint64(1 << 10)

	numOfReveals, err = numRevealsForTests(signedWeight, provenWeight, compactCertSecKQForTests)

	param = Params{SecKQ: compactCertSecKQForTests, ProvenWeightThreshold: provenWeight}
	verifier = MkVerifier(param, crypto.GenericDigest{})
	err = verifier.verifyWeights(signedWeight, numOfReveals)
	a.ErrorIs(err, ErrInsufficientImpliedProvenWeight)
}

func TestVerifyZeroNumberOfRevealsEquation(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1<<15 + 1)
	provenWeight := uint64(1 << 15)

	_, err := numRevealsForTests(signedWeight, provenWeight, compactCertSecKQForTests)
	a.ErrorIs(err, ErrNegativeNumOfRevealsEquation)
}

func TestLnWithPrecision(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	for i := 1; i < 32; i++ {
		exp := 1 << i
		val := lnIntApproximation(2, uint64(exp))
		a.GreaterOrEqual(float64(val)/float64(exp), math.Log(2))
		a.Greater(math.Log(2), float64(val-1)/float64(exp))
	}

	a.Equal(ln2IntApproximation, lnIntApproximation(2, precisionBits))
}

func TestVerifyLimits(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(0)
	provenWeight := uint64(1<<10 - 1)

	param := Params{SecKQ: compactCertSecKQForTests, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})
	err := verifier.verifyWeights(signedWeight, 130)
	a.ErrorIs(err, ErrZeroSignedWeight)

	signedWeight = 101
	provenWeight = 0

	param = Params{SecKQ: compactCertSecKQForTests, ProvenWeightThreshold: provenWeight}
	verifier = MkVerifier(param, crypto.GenericDigest{})
	err = verifier.verifyWeights(signedWeight, 0)
	a.ErrorIs(err, ErrZeroProvenWeightThreshold)
}

func TestNumReveals(t *testing.T) {
	partitiontest.PartitionTest(t)

	billion := uint64(1000 * 1000 * 1000)
	microalgo := uint64(1000 * 1000)
	provenWeight := 2 * billion * microalgo
	secKQ := uint64(compactCertSecKQForTests)
	bound := uint64(1000)

	for i := uint64(3); i < 10; i++ {
		signedWeight := i * billion * microalgo
		n, err := numRevealsForTests(signedWeight, provenWeight, secKQ)
		require.NoError(t, err)
		n2, err := old(signedWeight, provenWeight, secKQ, bound)
		t.Logf("%f", float64(n2)/float64(n))
		t.Logf("old %d", n2)
		t.Logf("new %d ", n)
		if n < 50 || n > 300 {
			t.Errorf("numReveals(%d, %d, %d) = %d looks suspect",
				signedWeight, provenWeight, secKQ, n)
		}

		param := Params{SecKQ: compactCertSecKQForTests, ProvenWeightThreshold: provenWeight}
		verifier := MkVerifier(param, crypto.GenericDigest{})
		err = verifier.verifyWeights(signedWeight, n)
		require.NoError(t, err)
	}
}

func BenchmarkVerifyWeights(b *testing.B) {
	billion := uint64(1000 * 1000 * 1000)
	microalgo := uint64(1000 * 1000)
	provenWeight := 100 * billion * microalgo
	signedWeight := 110 * billion * microalgo
	secKQ := uint64(compactCertSecKQForTests)

	nr, err := numRevealsForTests(signedWeight, provenWeight, secKQ)
	if nr < 900 {
		b.Errorf("numReveals(%d, %d, %d) = %d < 900", signedWeight, provenWeight, secKQ, nr)
	}
	require.NoError(b, err)

	param := Params{SecKQ: secKQ, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})

	for i := 0; i < b.N; i++ {
		verifier.verifyWeights(signedWeight, nr)
	}
}

func BenchmarkNumReveals(b *testing.B) {
	billion := uint64(1000 * 1000 * 1000)
	microalgo := uint64(1000 * 1000)
	provenWeight := 100 * billion * microalgo
	signedWeight := 110 * billion * microalgo
	secKQ := uint64(compactCertSecKQForTests)

	nr, err := numRevealsForTests(signedWeight, provenWeight, secKQ)
	if nr < 900 {
		b.Errorf("numReveals(%d, %d, %d) = %d < 900", signedWeight, provenWeight, secKQ, nr)
	}
	require.NoError(b, err)

	p := Params{SecKQ: secKQ, ProvenWeightThreshold: provenWeight}
	lnProvenWt := lnIntApproximation(provenWeight, precisionBits)
	builder := &Builder{
		Params:                  p,
		signedWeight:            signedWeight,
		lnProvenWeightThreshold: lnProvenWt,
	}

	for i := 0; i < b.N; i++ {
		builder.numReveals()
	}
}
