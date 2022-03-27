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
	"fmt"
	"math"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerifyRevelForEachPosition(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	cert, param, partCom, numPart := generateCertForTesting(a)

	verifier := MkVerifier(param, partCom)
	err := verifier.Verify(cert)
	a.NoError(err)

	for i := uint64(0); i < numPart; i++ {
		_, ok := cert.Reveals[i]
		if !ok {
			cert.PositionsToReveal[0] = i
			break
		}
	}

	verifier = MkVerifier(param, partCom)
	err = verifier.Verify(cert)
	a.ErrorIs(err, ErrNoRevealInPos)

}

func TestVerifyWrongCoinSlot(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	cert, param, partCom, _ := generateCertForTesting(a)

	verifier := MkVerifier(param, partCom)
	err := verifier.Verify(cert)
	a.NoError(err)

	swap := cert.PositionsToReveal[1]
	cert.PositionsToReveal[1] = cert.PositionsToReveal[0]
	cert.PositionsToReveal[0] = swap

	verifier = MkVerifier(param, partCom)
	err = verifier.Verify(cert)
	a.ErrorIs(err, ErrCoinNotInRange)
}

func TestVerifyBadSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	cert, param, partCom, _ := generateCertForTesting(a)

	verifier := MkVerifier(param, partCom)
	err := verifier.Verify(cert)
	a.NoError(err)

	rev := cert.Reveals[cert.PositionsToReveal[0]]
	rev.SigSlot.Sig.Signature[10]++

	verifier = MkVerifier(param, partCom)
	err = verifier.Verify(cert)
	a.ErrorIs(err, merklesignature.ErrSignatureSchemeVerificationFailed)
}

func TestVerifyMaxNumberOfReveals(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(10)
	provenWeight := uint64(10)

	param := Params{SecKQ: 128, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})
	err := verifier.verifyWeights(signedWeight, MaxReveals+1)
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

func TestVerifyImpliedProvenBiggerThanThreshold(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1 << 11)
	provenWeight := uint64(1<<10 - 1)

	numOfReveals, err := numReveals(signedWeight, provenWeight, compactCertSecKQForTests, MaxReveals)
	fmt.Println(numOfReveals)

	param := Params{SecKQ: compactCertSecKQForTests, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})
	err = verifier.verifyWeights(signedWeight, numOfReveals)
	a.NoError(err)
}

func TestVerifyImpliedProvenBiggerThanThresholdApproximationError(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1 << 11)
	provenWeight := uint64(1 << 10)

	numOfReveals, err := numReveals(signedWeight, provenWeight, compactCertSecKQForTests, MaxReveals)
	fmt.Println(numOfReveals)

	param := Params{SecKQ: compactCertSecKQForTests, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})
	err = verifier.verifyWeights(signedWeight, numOfReveals)
	a.ErrorIs(err, ErrInsufficientImpliedProvenWeight)
}

func TestLnWithPrecision(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	for i := 1; i < 32; i++ {
		exp := 1 << i
		val := lnWithPrecision(2, uint64(exp))
		a.GreaterOrEqual(float64(val)/float64(exp), math.Log(2))
		a.Greater(math.Log(2), float64(val-1)/float64(exp))
	}

	a.Equal(ln2AsInteger, lnWithPrecision(2, precisionBits))
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
		n, err := numReveals(signedWeight, provenWeight, secKQ, bound)
		require.NoError(t, err)
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
