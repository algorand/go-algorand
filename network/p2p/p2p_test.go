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
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"

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
