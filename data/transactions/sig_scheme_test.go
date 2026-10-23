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

	"github.com/algorand/go-algorand/config"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestSigSchemesMatchTestSchemes keeps the scheme table and the schemes that
// tests exercise in step, so that every scheme gets tested.
func TestSigSchemesMatchTestSchemes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// SigSchemeTests holds the signing schemes, so it lacks only ls.
	require.Len(t, sigSchemes, len(basics_testing.SigSchemeTests)+1)
	for _, ts := range basics_testing.SigSchemeTests {
		require.True(t, SigSchemeSupported(ts.Scheme), ts.Name)
	}
	require.True(t, SigSchemeSupported(protocol.SigSchemeLogicSig))
	for tag, s := range sigSchemes {
		if tag == protocol.SigSchemeLogicSig {
			require.Nil(t, s.verifier)
		} else {
			require.NotNil(t, s.verifier, tag)
		}
		require.NotNil(t, s.enabled, tag)
		require.NotNil(t, s.maxPublicKeySize, tag)
		require.NotNil(t, s.maxSignatureSize, tag)
	}
	require.False(t, SigSchemeSupported(protocol.SigScheme{'x', '1'}))
}

// TestSigSchemeBoundsCoverSchemes guards against a scheme's size bounds being smaller
// than a real public key or signature from it.
func TestSigSchemeBoundsCoverSchemes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var msg Transaction
	for _, ts := range basics_testing.SigSchemeTests {
		acct := basics_testing.MakeHashedKeySigTestAccount(t, 1, ts.Scheme)
		sig, err := acct.Signer.Sign(msg)
		require.NoError(t, err)

		scheme := sigSchemes[ts.Scheme]
		require.LessOrEqual(t, len(acct.PublicKey), scheme.maxPublicKeySize(), ts.Name)
		require.LessOrEqual(t, len(sig), scheme.maxSignatureSize(), ts.Name)
	}
}

// TestSigSchemeLogicSigFee pins the ls scheme's lack of a surcharge. An ls
// account costs a hash plus AVM execution, both of which are priced or
// constrained anyway. Charging a Falcon-style surcharge would make the
// off-curve form more expensive than the on-curve SignedTxn.Lsig form it exists
// to replace.
func TestSigSchemeLogicSigFee(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for proto, params := range config.Consensus {
		require.Zero(t, SigSchemeFeeContribution(params, protocol.SigSchemeLogicSig), proto)
	}
}
