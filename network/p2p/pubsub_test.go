// Copyright (C) 2019-2026 Algorand, Inc.
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

package p2p

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestPubsub_GossipSubParamsBasic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// expected values for n from 5 (calculated) to 12 (max default)
	// n, D, Dlo, Dscore, Dout, Dhi, Dlazy
	expected := []struct {
		n, D, Dlo, Dscore, Dout, Dhi, Dlazy int
	}{
		{5, 4, 3, 3, 1, 5, 5},
		{6, 4, 3, 3, 1, 6, 6},
		{7, 5, 3, 3, 1, 7, 7},
		{8, 6, 4, 4, 2, 8, 8},
		{9, 6, 4, 4, 2, 9, 9},
		{10, 7, 5, 5, 2, 10, 10},
		{11, 8, 6, 6, 3, 11, 11},
		{12, 8, 6, 6, 3, 12, 12},
	}

	for _, e := range expected {
		p := deriveAlgorandGossipSubParams(e.n)
		require.Equal(t, e.D, p.D, "n=%d D", e.n)
		require.Equal(t, e.Dlo, p.Dlo, "n=%d Dlo", e.n)
		require.Equal(t, e.Dscore, p.Dscore, "n=%d Dscore", e.n)
		require.Equal(t, e.Dout, p.Dout, "n=%d Dout", e.n)
		require.Equal(t, e.Dhi, p.Dhi, "n=%d Dhi", e.n)
		require.Equal(t, e.Dlazy, p.Dlazy, "n=%d Dlazy", e.n)
	}
}

// Verify libp2p gossipsub validate() constraints
// 1. Dlo <= D <= Dhi
// 2. Dscore <= Dhi
// 3. Dout < Dlo (strict)
// 4. Dout < D/2 (strict, integer division)
func TestPubsub_GossipSubParamsValidateConstraints(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for n := 1; n <= 20; n++ {
		p := deriveAlgorandGossipSubParams(n)
		require.LessOrEqual(t, p.Dlo, p.D, "n=%d: Dlo <= D", n)
		require.LessOrEqual(t, p.D, p.Dhi, "n=%d: D <= Dhi", n)
		require.LessOrEqual(t, p.Dscore, p.Dhi, "n=%d: Dscore <= Dhi", n)
		require.Less(t, p.Dout, p.Dlo, "n=%d: Dout < Dlo", n)
		require.Less(t, p.Dout, p.D/2, "n=%d: Dout < D/2", n)
	}
}

func TestPubsub_GossipSubParamsEdgeCases(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// n = 0: all zeros
	p := deriveAlgorandGossipSubParams(0)
	require.Equal(t, 0, p.D)
	require.Equal(t, 0, p.Dlo)
	require.Equal(t, 0, p.Dscore)
	require.Equal(t, 0, p.Dout)
	require.Equal(t, 0, p.Dhi)
	require.Equal(t, 0, p.Dlazy)

	// n = 1..4: low bound
	for n := 1; n <= 4; n++ {
		p = deriveAlgorandGossipSubParams(n)
		require.Equal(t, 4, p.D)
		require.Equal(t, 2, p.Dlo)
		require.Equal(t, 1, p.Dscore)
		require.Equal(t, 1, p.Dout)
		require.Equal(t, 4, p.Dhi)
		require.Equal(t, 4, p.Dlazy)
	}

	// n >= 12: capped to defaults
	for n := 12; n <= 20; n++ {
		p = deriveAlgorandGossipSubParams(20)
		require.Equal(t, 8, p.D)
		require.Equal(t, 6, p.Dlo)
		require.Equal(t, 6, p.Dscore)
		require.Equal(t, 3, p.Dout)
		require.Equal(t, 12, p.Dhi)
		require.Equal(t, 12, p.Dlazy)
	}
}
