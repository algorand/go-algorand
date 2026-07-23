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

package v2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type testPeerConnInfo struct {
	addr        string
	networkType network.PeerNetworkType
}

func (p testPeerConnInfo) GetAddress() string                      { return p.addr }
func (p testPeerConnInfo) GetNetworkType() network.PeerNetworkType { return p.networkType }

func TestPeerStatuses(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	peers := []network.Peer{
		testPeerConnInfo{addr: "/ip4/10.0.0.2/tcp/4160", networkType: network.PeerNetworkTypeLibP2P},
		testPeerConnInfo{addr: "192.168.1.5:4160", networkType: network.PeerNetworkTypeWebsocket},
		// a p2p gossip peer is reported both as a wsPeer and as its underlying
		// libp2p connection with the same address; it must be deduplicated
		testPeerConnInfo{addr: "/ip4/10.0.0.2/tcp/4160", networkType: network.PeerNetworkTypeLibP2P},
		// peers that cannot report connection info are skipped
		struct{}{},
	}

	statuses := peerStatuses(peers, model.PeerStatusConnectionTypeInbound)
	require.Equal(t, []model.PeerStatus{
		{
			ConnectionType: model.PeerStatusConnectionTypeInbound,
			NetworkAddress: "/ip4/10.0.0.2/tcp/4160",
			NetworkType:    model.PeerStatusNetworkTypeP2p,
		},
		{
			ConnectionType: model.PeerStatusConnectionTypeInbound,
			NetworkAddress: "192.168.1.5:4160",
			NetworkType:    model.PeerStatusNetworkTypeWs,
		},
	}, statuses)

	// every status must use a value declared in the API enum
	for _, status := range statuses {
		require.Contains(t, []model.PeerStatusNetworkType{
			model.PeerStatusNetworkTypeWs,
			model.PeerStatusNetworkTypeP2p,
		}, status.NetworkType)
	}

	require.Empty(t, peerStatuses(nil, model.PeerStatusConnectionTypeOutbound))
}
