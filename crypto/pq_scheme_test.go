// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestPQVerifierEd25519(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	verifier := PQEd25519{}

	msg := TestingHashable{data: []byte("pq verifier round trip")}
	signer := GenerateSignatureSecrets(Seed{1})
	sig := signer.Sign(msg)

	require.NoError(t, verifier.Verify(msg, signer.SignatureVerifier[:], sig[:]))
	require.ErrorIs(t, verifier.Verify(msg, signer.SignatureVerifier[:len(signer.SignatureVerifier)-1], sig[:]), ErrSigInvalid)
	require.ErrorIs(t, verifier.Verify(msg, signer.SignatureVerifier[:], sig[:len(sig)-1]), ErrSigInvalid)
	require.ErrorIs(t, verifier.Verify(TestingHashable{data: []byte("wrong message")}, signer.SignatureVerifier[:], sig[:]), ErrSigInvalid)

	otherSigner := GenerateSignatureSecrets(Seed{2})
	require.ErrorIs(t, verifier.Verify(msg, otherSigner.SignatureVerifier[:], sig[:]), ErrSigInvalid)
}

// TestPQVerifierFalconRoundTrip exercises the interface wiring; the
// underlying verification is covered by the VerifyFalcon1024/512 tests.
func TestPQVerifierFalconRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	v1 := PQFalcon1024{}
	v5 := PQFalcon512{}

	msg := TestingHashable{data: []byte("pq verifier round trip")}
	var seed FalconSeed
	seed[0] = 1

	signer1, err := GenerateFalcon1024Signer(seed)
	require.NoError(t, err)
	sig1, err := signer1.Sign(msg)
	require.NoError(t, err)

	require.NoError(t, v1.Verify(msg, signer1.PublicKey[:], sig1))
	require.Error(t, v1.Verify(msg, signer1.PublicKey[:], nil))

	signer5, err := GenerateFalcon512Signer(seed)
	require.NoError(t, err)
	sig5, err := signer5.Sign(msg)
	require.NoError(t, err)

	require.NoError(t, v5.Verify(msg, signer5.PublicKey[:], sig5))
	require.Error(t, v5.Verify(msg, signer5.PublicKey[:], nil))
}
