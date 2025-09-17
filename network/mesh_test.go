// Copyright (C) 2019-2025 Algorand, Inc.
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
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/limitcaller"
	p2piface "github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

// mockP2PService implements p2p.Service and counts DialPeersUntilTargetCount invocations.
// It relies on p2p's meshThreadInner's defer of DialPeersUntilTargetCount to detect invocation.
type mockP2PService struct{ dialCount atomic.Int32 }

func (m *mockP2PService) Start() error                              { return nil }
func (m *mockP2PService) Close() error                              { return nil }
func (m *mockP2PService) ID() peer.ID                               { return "" }
func (m *mockP2PService) IDSigner() *p2piface.PeerIDChallengeSigner { return nil }
func (m *mockP2PService) AddrInfo() peer.AddrInfo                   { return peer.AddrInfo{} }
func (m *mockP2PService) NetworkNotify(network.Notifiee)            {}
func (m *mockP2PService) NetworkStopNotify(network.Notifiee)        {}
func (m *mockP2PService) DialPeersUntilTargetCount(int) bool        { m.dialCount.Add(1); return true }
func (m *mockP2PService) ClosePeer(peer.ID) error                   { return nil }
func (m *mockP2PService) Conns() []network.Conn                     { return nil }
func (m *mockP2PService) ListPeersForTopic(string) []peer.ID        { return nil }
func (m *mockP2PService) Subscribe(string, pubsub.ValidatorEx) (p2piface.SubNextCancellable, error) {
	return nil, nil
}
func (m *mockP2PService) Publish(context.Context, string, []byte) error { return nil }
func (m *mockP2PService) GetHTTPClient(*peer.AddrInfo, limitcaller.ConnectionTimeStore, time.Duration) (*http.Client, error) {
	return &http.Client{}, nil
}

// TestMesh_HybridRelayP2PInnerCall ensures the wsConnections <= targetConnCount condition
// in the hybridRelayMeshCreator mesh function in order to make sure P2PNetwork.meshThreadInner is invoked
func TestMesh_HybridRelayP2PInnerCall(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := config.GetDefaultLocal()
	cfg.GossipFanout = 0
	cfg.DNSBootstrapID = ""
	cfg.EnableP2PHybridMode = true
	cfg.PublicAddress = "public-address"
	cfg.NetAddress = "127.0.0.1:0"
	cfg.P2PHybridNetAddress = "127.0.0.1:0"

	log := logging.TestingLog(t)
	genesisInfo := GenesisInfo{GenesisID: "test-genesis", NetworkID: protocol.NetworkID("test-network")}
	net, err := NewHybridP2PNetwork(log, cfg, "", nil, genesisInfo, &nopeNodeInfo{}, nil)
	require.NoError(t, err)

	mockSvc := &mockP2PService{}
	net.p2pNetwork.service = mockSvc
	net.p2pNetwork.relayMessages = false // prevent pubsub startup

	err = net.Start()
	require.NoError(t, err)
	defer net.Stop()

	net.RequestConnectOutgoing(false, nil)
	require.Eventually(t, func() bool {
		// RequestConnectOutgoing queues mesh update request so we have to wait a bit
		return mockSvc.dialCount.Load() > 0
	}, 3*time.Second, 50*time.Millisecond, "expected DialPeersUntilTargetCount to be called")
}
