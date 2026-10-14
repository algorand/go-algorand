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

package transactions

import (
	"testing"

	"github.com/stretchr/testify/require"

	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestPQSchemesMatchTestSchemes keeps the scheme table and the schemes that
// tests exercise in step, so that every scheme gets tested.
func TestPQSchemesMatchTestSchemes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.Len(t, pqSchemes, len(basics_testing.PQTestSchemes))
	for _, ts := range basics_testing.PQTestSchemes {
		require.True(t, PQSchemeSupported(ts.Scheme), ts.Name)
	}
	for tag, s := range pqSchemes {
		require.NotNil(t, s.verifier, tag)
		require.NotNil(t, s.enabled, tag)
		require.NotNil(t, s.maxPublicKeySize, tag)
		require.NotNil(t, s.maxSignatureSize, tag)
	}
	require.False(t, PQSchemeSupported(protocol.PQScheme{'x', '1'}))
}

// TestPQBoundsCoverSchemes guards against a scheme's size bounds being smaller
// than a real public key or signature from it.
func TestPQBoundsCoverSchemes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var msg Transaction
	for _, ts := range basics_testing.PQTestSchemes {
		acct := basics_testing.MakePQTestAccount(t, 1, ts.Scheme)
		sig, err := acct.Signer.Sign(msg)
		require.NoError(t, err)

		scheme := pqSchemes[ts.Scheme]
		require.LessOrEqual(t, len(acct.PublicKey), scheme.maxPublicKeySize(), ts.Name)
		require.LessOrEqual(t, len(sig), scheme.maxSignatureSize(), ts.Name)
	}
}
