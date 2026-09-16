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

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestLookupPQScheme(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	v, ok := LookupPQScheme(protocol.PQSchemeEd25519)
	require.True(t, ok)
	require.NotNil(t, v)

	v, ok = LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)
	require.NotNil(t, v)

	v, ok = LookupPQScheme(protocol.PQSchemeFalcon512)
	require.True(t, ok)
	require.NotNil(t, v)

	_, ok = LookupPQScheme(protocol.PQScheme{'x', '1'})
	require.False(t, ok)
}

// TestPQBoundsCoverSchemes guards against MaxPQ*Size being smaller than a
// real public key or signature from any supported scheme.
func TestPQBoundsCoverSchemes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	msg := TestingHashable{data: []byte("pq bounds")}
	edSigner := GenerateSignatureSecrets(Seed{1})
	edSig := edSigner.Sign(msg)
	require.LessOrEqual(t, uint64(len(edSigner.SignatureVerifier)), uint64(MaxPQPublicKeySize))
	require.LessOrEqual(t, uint64(len(edSig)), uint64(MaxPQSignatureSize))

	var seed FalconSeed
	seed[0] = 1
	signer1024, err := GenerateFalcon1024Signer(seed)
	require.NoError(t, err)
	require.LessOrEqual(t, uint64(len(signer1024.PublicKey)), uint64(MaxPQPublicKeySize))
	signer512, err := GenerateFalcon512Signer(seed)
	require.NoError(t, err)
	require.LessOrEqual(t, uint64(len(signer512.PublicKey)), uint64(MaxPQPublicKeySize))

	sig1, err := signer1024.Sign(msg)
	require.NoError(t, err)
	require.LessOrEqual(t, uint64(len(sig1)), uint64(MaxPQSignatureSize))
	sig5, err := signer512.Sign(msg)
	require.NoError(t, err)
	require.LessOrEqual(t, uint64(len(sig5)), uint64(MaxPQSignatureSize))
}

func TestPQVerifierEd25519(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	verifier, ok := LookupPQScheme(protocol.PQSchemeEd25519)
	require.True(t, ok)

	msg := TestingHashable{data: []byte("pq verifier round trip")}
	signer := GenerateSignatureSecrets(Seed{1})
	sig := signer.Sign(msg)

	require.NoError(t, verifier.Verify(msg, signer.SignatureVerifier[:], sig[:]))
	require.ErrorIs(t, verifier.Verify(msg, signer.SignatureVerifier[:len(signer.SignatureVerifier)-1], sig[:]), ErrPQEd25519SigInvalid)
	require.ErrorIs(t, verifier.Verify(msg, signer.SignatureVerifier[:], sig[:len(sig)-1]), ErrPQEd25519SigInvalid)
	require.ErrorIs(t, verifier.Verify(TestingHashable{data: []byte("wrong message")}, signer.SignatureVerifier[:], sig[:]), ErrPQEd25519SigInvalid)

	otherSigner := GenerateSignatureSecrets(Seed{2})
	require.ErrorIs(t, verifier.Verify(msg, otherSigner.SignatureVerifier[:], sig[:]), ErrPQEd25519SigInvalid)
}

// TestPQVerifierFalconRoundTrip exercises the interface wiring; the
// underlying verification is covered by the VerifyFalcon1024/512 tests.
func TestPQVerifierFalconRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	v1, ok := LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)
	v5, ok := LookupPQScheme(protocol.PQSchemeFalcon512)
	require.True(t, ok)

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
