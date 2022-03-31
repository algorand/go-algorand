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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/test/partitiontest"
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
