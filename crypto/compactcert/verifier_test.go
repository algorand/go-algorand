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

	signedWeight := uint64(9)
	provenWeight := uint64(10)

	param := Params{SecKQ: 128, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})
	err := verifier.verifyWeights(signedWeight, 128)
	a.ErrorIs(err, ErrSignedWeightLessThanProvenWeight)
}

func TestVerifyImpliedProvenBiggerThanThreshold(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	// those would need to result in 128 reveals
	signedWeight := uint64(1 << 11)
	provenWeight := uint64(1 << 10)

	param := Params{SecKQ: 128, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})
	err := verifier.verifyWeights(signedWeight, 130)
	a.NoError(err)
}

func TestVerifyImpliedProvend(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signedWeight := uint64(1<<11 - 1)
	provenWeight := uint64(1<<10 + 3)

	numOfReveals, err := numReveals(signedWeight, provenWeight, 128, MaxReveals)
	fmt.Println(numOfReveals)

	param := Params{SecKQ: 128, ProvenWeightThreshold: provenWeight}
	verifier := MkVerifier(param, crypto.GenericDigest{})
	err = verifier.verifyWeights(signedWeight, numOfReveals)
	a.NoError(err)
}
