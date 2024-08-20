// Copyright (C) 2019-2024 Algorand, Inc.
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

package network

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestMetrics_TagList ensures p2p.TracedNetworkMessageTags and tagStringListP2P are disjoint
func TestMetrics_TagList(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	p2pTags := make(map[string]bool, len(p2p.TracedNetworkMessageTags))
	metricTags := make(map[string]bool, len(tagStringListP2P))

	for _, tag := range p2p.TracedNetworkMessageTags {
		p2pTags[string(tag)] = true
	}

	for _, tag := range tagStringListP2P {
		metricTags[string(tag)] = true
	}

	require.Equal(t, len(protocol.TagMap), len(p2pTags)+len(metricTags))
	for tag := range protocol.TagMap {
		require.True(t, p2pTags[string(tag)] || metricTags[string(tag)])
		require.False(t, p2pTags[string(tag)] && metricTags[string(tag)])
	}
}
