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

package stateproof

import (
	"fmt"
	"math"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestMaxNumberOfRevealsInVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(10)
	provenWeight := uint64(10)
	lnProvenWt, err := LnIntApproximation(provenWeight)
	a.NoError(err)

	err = verifyWeights(signedWeight, lnProvenWt, MaxReveals+1, stateProofStrengthTargetForTests)
	a.ErrorIs(err, ErrTooManyReveals)
}

func TestMaxNumberOfReveals(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1<<10 + 1)
	provenWeight := uint64(1 << 10)
	lnProvenWt, err := LnIntApproximation(provenWeight)
	a.NoError(err)

	_, err = numReveals(signedWeight, lnProvenWt, stateProofStrengthTargetForTests)
	a.ErrorIs(err, ErrTooManyReveals)
}

func TestVerifyProvenWeight(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1 << 11)
	provenWeight := uint64(1 << 10)
	lnProvenWt, err := LnIntApproximation(provenWeight)
	a.NoError(err)

	numOfReveals, err := numReveals(signedWeight, lnProvenWt, stateProofStrengthTargetForTests)
	a.NoError(err)

	err = verifyWeights(signedWeight, lnProvenWt, numOfReveals, stateProofStrengthTargetForTests)
	a.NoError(err)

	err = verifyWeights(signedWeight, lnProvenWt, numOfReveals-1, stateProofStrengthTargetForTests)
	a.ErrorIs(err, ErrInsufficientSignedWeight)
}

func TestVerifyZeroNumberOfRevealsEquation(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1<<15 + 1)
	provenWeight := uint64(1 << 15)
	lnProvenWt, err := LnIntApproximation(provenWeight)
	a.NoError(err)

	_, err = numReveals(signedWeight, lnProvenWt, stateProofStrengthTargetForTests)
	a.ErrorIs(err, ErrNegativeNumOfRevealsEquation)
}

func TestLnWithPrecision(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	val, err := LnIntApproximation(2)
	a.NoError(err)

	// check that precisionBits will not overflow
	exp := 1 << precisionBits
	a.Less(precisionBits, uint8(64))

	a.GreaterOrEqual(float64(val)/float64(exp), math.Log(2))
	a.Greater(math.Log(2), float64(val-1)/float64(exp))

	ln2, err := LnIntApproximation(2)
	a.NoError(err)
	a.Equal(ln2IntApproximation, ln2)
}

func TestVerifyLimits(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(0)
	provenWeight := uint64(1<<10 - 1)
	lnProvenWt, err := LnIntApproximation(provenWeight)
	a.NoError(err)

	err = verifyWeights(signedWeight, lnProvenWt, MaxReveals-1, stateProofStrengthTargetForTests)
	a.ErrorIs(err, ErrZeroSignedWeight)
}

func TestNumRevealsApproxBound(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	// In order to create a valid state proof we need to be bound to a MaxNumberOfReveals.
	// according to SNARK-friendly weight-verification formula there would be a ratio signedWt/provenWt > 1
	// that we would not be able to generate proof since the MaxReveals would be too high.
	// This test points out on the minimal ratio signedWt/provenWt we would ever prdouce.

	for j := 0; j < 10; j++ {
		sigWt := uint64(1<<(40-j) - 1)
		// we check the ratios = signedWt/provenWt {3, 2.99, 2.98...1}
		// ratio = 1.33 (i==167) would give 625 would be the lower bound we can expect
		for i := 0; i < 168; i++ {
			a.NoError(checkRatio(i, sigWt, stateProofStrengthTargetForTests))
		}
		a.ErrorIs(checkRatio(168, sigWt, stateProofStrengthTargetForTests), ErrTooManyReveals)
	}
}

func checkRatio(i int, sigWt uint64, secParam uint64) error {
	provenWtRatio := 3 - (float64(i) / 100)
	provenWt := uint64(float64(sigWt) / (provenWtRatio))
	lnProvenWt, err := LnIntApproximation(provenWt)
	if err != nil {
		return err
	}

	numOfReveals, err := numReveals(sigWt, lnProvenWt, secParam)
	if err != nil {
		return fmt.Errorf("failed on sigWt %v provenWt %d ratio is %v i %v err: %w", sigWt, provenWt, provenWtRatio, i, err)
	}

	log2Sig := math.Log(float64(sigWt)) / math.Log(2)
	log2Prov := math.Log(float64(provenWt)) / math.Log(2)
	nr := float64(secParam) / (log2Sig - log2Prov)
	if 1.01 < float64(numOfReveals)/nr {
		return fmt.Errorf("approximated number of reveals exceeds limit "+
			"limit %v, signedWeight: %v provenWeight %v, "+
			"appox numberOfReveals: %v, real numberOfReveals %v ratio is %v", 1.01, sigWt, provenWt, numOfReveals, nr, provenWtRatio)
	}
	return nil
}

func TestNumReveals(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	billion := uint64(1000 * 1000 * 1000)
	microalgo := uint64(1000 * 1000)
	provenWeight := 2 * billion * microalgo
	strengthTarget := uint64(stateProofStrengthTargetForTests)
	lnProvenWt, err := LnIntApproximation(provenWeight)
	a.NoError(err)

	for i := uint64(3); i < 10; i++ {
		signedWeight := i * billion * microalgo
		n, err := numReveals(signedWeight, lnProvenWt, strengthTarget)
		a.NoError(err)
		if n < 50 || n > 500 {
			t.Errorf("numReveals(%d, %d, %d) = %d looks suspect",
				signedWeight, provenWeight, strengthTarget, n)
		}

		err = verifyWeights(signedWeight, lnProvenWt, n, stateProofStrengthTargetForTests)
		a.NoError(err)
	}
}

func TestSigPartProofMaxSize(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// Ensures that the SigPartProofMaxSize constant used for maxtotalbytes for StateProof.(Sig|Part)Proof(s) is
	// correct. It should be logically bound by the maximum number of StateProofTopVoters. It is scaled by 1/2
	// see merkelarray.Proof comment for explanation of the size calculation.
	require.Equal(t, SigPartProofMaxSize, merklearray.ProofMaxSizeByElements(config.StateProofTopVoters/2))
}

func BenchmarkVerifyWeights(b *testing.B) {
	billion := uint64(1000 * 1000 * 1000)
	microalgo := uint64(1000 * 1000)
	provenWeight := 100 * billion * microalgo
	signedWeight := 110 * billion * microalgo
	strengthTarget := uint64(stateProofStrengthTargetForTests)

	lnProvenWt, err := LnIntApproximation(provenWeight)
	require.NoError(b, err)

	nr, err := numReveals(signedWeight, lnProvenWt, strengthTarget)
	if nr < 900 {
		b.Errorf("numReveals(%d, %d, %d) = %d < 900", signedWeight, provenWeight, strengthTarget, nr)
	}
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		verifyWeights(signedWeight, lnProvenWt, nr, strengthTarget)
	}
}

func BenchmarkNumReveals(b *testing.B) {
	billion := uint64(1000 * 1000 * 1000)
	microalgo := uint64(1000 * 1000)
	provenWeight := 100 * billion * microalgo
	signedWeight := 110 * billion * microalgo
	strengthTarget := uint64(stateProofStrengthTargetForTests)
	lnProvenWt, err := LnIntApproximation(provenWeight)
	require.NoError(b, err)

	nr, err := numReveals(signedWeight, lnProvenWt, strengthTarget)
	if nr < 900 {
		b.Errorf("numReveals(%d, %d, %d) = %d < 900", signedWeight, provenWeight, strengthTarget, nr)
	}
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		numReveals(signedWeight, lnProvenWt, strengthTarget)
	}
}
