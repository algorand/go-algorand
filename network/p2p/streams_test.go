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

package p2p

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
	"github.com/algorand/go-algorand/test/partitiontest"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

// TestConnectedLogsNonDialedOutgoingConnection tests that the Connected function
// exits early for non-dialed outgoing connections by checking the log output
func TestStreamNonDialedOutgoingConnection(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	logBuffer := &strings.Builder{}
	logger := logging.NewLogger()
	logger.SetOutput(logBuffer)
	logger.SetLevel(logging.Debug)

	cfg := config.GetDefaultLocal()
	cfg.NetAddress = ":1"
	cfg.EnableP2PHybridMode = true
	cfg.P2PHybridNetAddress = ":2"

	pstore1, err := peerstore.NewPeerStore(nil, "test1")
	require.NoError(t, err)
	pstore2, err := peerstore.NewPeerStore(nil, "test2")
	require.NoError(t, err)

	var dialerHost, listenerHost host.Host
	var dialerSM, listenerSM *streamManager

	host1, _, err := MakeHost(cfg, t.TempDir(), pstore1)
	require.NoError(t, err)
	defer host1.Close()

	host2, _, err := MakeHost(cfg, t.TempDir(), pstore2)
	require.NoError(t, err)
	defer host2.Close()

	if host1.ID() < host2.ID() {
		dialerHost = host1
		listenerHost = host2
	} else {
		dialerHost = host2
		listenerHost = host1
	}

	// Make listenerHost listen on a port so we can connect to it
	listenAddr, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	require.NoError(t, err)
	err = listenerHost.Network().Listen(listenAddr)
	require.NoError(t, err)

	ctx := context.Background()
	handlers := StreamHandlers{}
	dialerSM = makeStreamManager(ctx, logger, cfg, dialerHost, handlers, false)
	listenerSM = makeStreamManager(ctx, logger, cfg, listenerHost, handlers, false)

	// Setup Connected notification
	dialerHost.Network().Notify(dialerSM)
	listenerHost.Network().Notify(listenerSM)

	logBuffer.Reset()

	listenerAddrs := listenerHost.Network().ListenAddresses()
	require.NotEmpty(t, listenerAddrs, "listenerHost should have listening addresses")
	dialerHost.Peerstore().AddAddrs(listenerHost.ID(), listenerAddrs, 1)

	// Connect dialerHost to listenerHost directly, not through dialNode
	err = dialerHost.Connect(ctx, peer.AddrInfo{
		ID:    listenerHost.ID(),
		Addrs: listenerAddrs,
	})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return len(dialerHost.Network().ConnsToPeer(listenerHost.ID())) > 0
	}, 5*time.Second, 50*time.Millisecond)

	conns := dialerHost.Network().ConnsToPeer(listenerHost.ID())
	require.Len(t, conns, 1)
	require.Equal(t, network.DirOutbound, conns[0].Stat().Direction)

	// Check that the log contains the expected message for non-dialed outgoing connection
	logOutput := logBuffer.String()
	expectedMsg := "ignoring non-dialed outgoing peer ID"
	require.Contains(t, logOutput, expectedMsg)
	require.Contains(t, logOutput, listenerHost.ID().String())
}
