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

	v, ok := LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)
	require.NotNil(t, v)

	v, ok = LookupPQScheme(protocol.PQSchemeFalcon512)
	require.True(t, ok)
	require.NotNil(t, v)

	_, ok = LookupPQScheme(protocol.PQScheme{'x', '1'})
	require.False(t, ok)
}

// TestPQBoundsCoverFalcon guards against MaxPQ*Size being smaller than a
// real Falcon-1024/512 public key or signature.
func TestPQBoundsCoverFalcon(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var seed FalconSeed
	seed[0] = 1
	signer1024, err := GenerateFalcon1024Signer(seed)
	require.NoError(t, err)
	require.LessOrEqual(t, uint64(len(signer1024.PublicKey)), uint64(MaxPQPublicKeySize))
	signer512, err := GenerateFalcon512Signer(seed)
	require.NoError(t, err)
	require.LessOrEqual(t, uint64(len(signer512.PublicKey)), uint64(MaxPQPublicKeySize))

	sig1, err := signer1024.Sign(TestingHashable{data: []byte("pq bounds")})
	require.NoError(t, err)
	require.LessOrEqual(t, uint64(len(sig1)), uint64(MaxPQSignatureSize))
	sig5, err := signer512.Sign(TestingHashable{data: []byte("pq bounds")})
	require.NoError(t, err)
	require.LessOrEqual(t, uint64(len(sig5)), uint64(MaxPQSignatureSize))
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
