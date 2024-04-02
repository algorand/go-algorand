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

package p2p

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// Tests the helper function netAddressToListenAddress which converts
// a config value netAddress to a multiaddress usable by libp2p.
func TestNetAddressToListenAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tests := []struct {
		input  string
		output string
		err    bool
	}{
		{
			input:  "192.168.1.1:8080",
			output: "/ip4/192.168.1.1/tcp/8080",
			err:    false,
		},
		{
			input:  ":8080",
			output: "/ip4/0.0.0.0/tcp/8080",
			err:    false,
		},
		{
			input:  "192.168.1.1:",
			output: "",
			err:    true,
		},
		{
			input:  "192.168.1.1",
			output: "",
			err:    true,
		},
		{
			input:  "192.168.1.1:8080:9090",
			output: "",
			err:    true,
		},
	}

	for _, test := range tests { //nolint:paralleltest
		t.Run(fmt.Sprintf("input: %s", test.input), func(t *testing.T) {
			res, err := netAddressToListenAddress(test.input)
			if test.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.output, res)
			}
		})
	}
}

func TestP2PStreamingHost(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	dir := t.TempDir()
	pstore, err := peerstore.NewPeerStore(nil, "")
	require.NoError(t, err)
	h, la, err := MakeHost(cfg, dir, pstore)
	require.NoError(t, err)

	var h1calls atomic.Int64
	h1 := func(network.Stream) {
		h1calls.Add(1)
	}
	var h2calls atomic.Int64
	h2 := func(network.Stream) {
		h2calls.Add(1)
	}

	ma, err := multiaddr.NewMultiaddr(la)
	require.NoError(t, err)
	h.Network().Listen(ma)
	defer h.Close()

	h.SetStreamHandler(AlgorandWsProtocol, h1)
	h.SetStreamHandler(AlgorandWsProtocol, h2)

	addrInfo := peer.AddrInfo{
		ID:    h.ID(),
		Addrs: h.Addrs(),
	}
	cpstore, err := peerstore.NewPeerStore([]*peer.AddrInfo{&addrInfo}, "")
	require.NoError(t, err)
	c, _, err := MakeHost(cfg, dir, cpstore)
	require.NoError(t, err)
	defer c.Close()

	s1, err := c.NewStream(context.Background(), h.ID(), AlgorandWsProtocol)
	require.NoError(t, err)
	s1.Write([]byte("hello"))
	defer s1.Close()

	require.Eventually(t, func() bool {
		return h1calls.Load() == 1 && h2calls.Load() == 1
	}, 5*time.Second, 100*time.Millisecond)

	// ensure a single handler also works as expected
	h1calls.Store(0)
	h.SetStreamHandler(algorandP2pHTTPProtocol, h1)

	s2, err := c.NewStream(context.Background(), h.ID(), algorandP2pHTTPProtocol)
	require.NoError(t, err)
	s2.Write([]byte("hello"))
	defer s2.Close()

	require.Eventually(t, func() bool {
		return h1calls.Load() == 1
	}, 5*time.Second, 100*time.Millisecond)

}

// TestP2PGetPeerTelemetryInfo tests the GetPeerTelemetryInfo function
func TestP2PGetPeerTelemetryInfo(t *testing.T) {
	partitiontest.PartitionTest(t)

	testCases := []struct {
		name                      string
		peerProtocols             []protocol.ID
		expectedTelemetryID       string
		expectedTelemetryInstance string
	}{
		{
			name:                      "Valid Telemetry Info",
			peerProtocols:             []protocol.ID{protocol.ID(formatPeerTelemetryInfoProtocolName("telemetryID", "telemetryInstance"))},
			expectedTelemetryID:       "telemetryID",
			expectedTelemetryInstance: "telemetryInstance",
		},
		{
			name:                      "Partial Telemetry Info 1",
			peerProtocols:             []protocol.ID{protocol.ID(formatPeerTelemetryInfoProtocolName("telemetryID", ""))},
			expectedTelemetryID:       "telemetryID",
			expectedTelemetryInstance: "",
		},
		{
			name:                      "Partial Telemetry Info 2",
			peerProtocols:             []protocol.ID{protocol.ID(formatPeerTelemetryInfoProtocolName("", "telemetryInstance"))},
			expectedTelemetryID:       "",
			expectedTelemetryInstance: "telemetryInstance",
		},
		{
			name:                      "No Telemetry Info",
			peerProtocols:             []protocol.ID{protocol.ID("/some-other-protocol/1.0.0/otherID/otherInstance")},
			expectedTelemetryID:       "",
			expectedTelemetryInstance: "",
		},
		{
			name:                      "Invalid Telemetry Info Format",
			peerProtocols:             []protocol.ID{protocol.ID("/algorand-telemetry/1.0.0/invalidFormat")},
			expectedTelemetryID:       "",
			expectedTelemetryInstance: "",
		},
		{
			name:                      "Special Characters Telemetry Info Format",
			peerProtocols:             []protocol.ID{protocol.ID(formatPeerTelemetryInfoProtocolName("telemetry/ID", "123-//11-33"))},
			expectedTelemetryID:       "telemetry/ID",
			expectedTelemetryInstance: "123-//11-33",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			telemetryID, telemetryInstance := GetPeerTelemetryInfo(tc.peerProtocols)
			if telemetryID != tc.expectedTelemetryID || telemetryInstance != tc.expectedTelemetryInstance {
				t.Errorf("Expected telemetry ID: %s, telemetry instance: %s, but got telemetry ID: %s, telemetry instance: %s",
					tc.expectedTelemetryID, tc.expectedTelemetryInstance, telemetryID, telemetryInstance)
			}
		})
	}
}

func TestP2PProtocolAsMeta(t *testing.T) {
	partitiontest.PartitionTest(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer h1.Close()

	h1TID := "telemetryID1"
	h1Inst := "telemetryInstance2"
	telemetryProtoInfo := formatPeerTelemetryInfoProtocolName(h1TID, h1Inst)
	h1.SetStreamHandler(protocol.ID(telemetryProtoInfo), func(s network.Stream) { s.Close() })

	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer h2.Close()

	err = h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()})
	require.NoError(t, err)

	protos, err := h2.Peerstore().GetProtocols(h1.ID())
	require.NoError(t, err)

	tid, inst := GetPeerTelemetryInfo(protos)
	require.Equal(t, h1TID, tid)
	require.Equal(t, h1Inst, inst)
}
