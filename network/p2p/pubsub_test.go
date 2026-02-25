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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestPubsub_GossipSubParamsBasic(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := config.GetDefaultLocal()

	for _, fanout := range []int{4, 8} {
		cfg.GossipFanout = fanout

		params := deriveAlgorandGossipSubParams(cfg.GossipFanout)

		require.Equal(t, fanout, params.D)
		require.Equal(t, fanout-1, params.Dlo)
		require.Equal(t, fanout*2/3, params.Dscore)
		require.Equal(t, fanout*1/3, params.Dout)
	}
}

func TestPubsub_GossipSubParamsEdgeCases(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := config.GetDefaultLocal()
	cfg.GossipFanout = 1
	p := deriveAlgorandGossipSubParams(cfg.GossipFanout)
	require.Equal(t, 3, p.D)
	require.Equal(t, 0, p.Dlo)
	require.Equal(t, 1, p.Dscore)
	require.Equal(t, 1, p.Dout)

	// D = 0 => keep Dlo = D (0) instead of negative
	cfg = config.GetDefaultLocal()
	cfg.GossipFanout = 0
	p = deriveAlgorandGossipSubParams(cfg.GossipFanout)
	require.Equal(t, 0, p.D)
	require.Equal(t, 0, p.Dlo)
	require.Equal(t, 0, p.Dscore)
	require.Equal(t, 0, p.Dout)
}
