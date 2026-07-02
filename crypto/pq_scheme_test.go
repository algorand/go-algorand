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
	require.Equal(t, uint64(FalconPublicKeySize), v.PublicKeySize())
	require.Equal(t, uint64(FalconMaxSignatureSize), v.SignatureSize())

	_, ok = LookupPQScheme(protocol.PQScheme{'x', '1'})
	require.False(t, ok)
}

// TestPQVerifierFalcon1024RoundTrip exercises the interface wiring; the
// underlying verification is covered by the VerifyFalcon1024 tests.
func TestPQVerifierFalcon1024RoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	v, ok := LookupPQScheme(protocol.PQSchemeFalcon1024)
	require.True(t, ok)

	msg := TestingHashable{data: []byte("pq verifier round trip")}
	var seed FalconSeed
	seed[0] = 1
	signer, err := GenerateFalconSigner(seed)
	require.NoError(t, err)
	sig, err := signer.Sign(msg)
	require.NoError(t, err)

	require.NoError(t, v.Verify(msg, signer.PublicKey[:], sig))
	require.Error(t, v.Verify(msg, signer.PublicKey[:], nil))
}
