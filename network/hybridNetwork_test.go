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
	"net/url"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

// TestHybridNetwork_DuplicateConn checks the same nodes do not connect over ws and p2p.
// Scenario:
// 1. Create a hybrid network: relay and two nodes
// 2. Let them connect to the relay
// 3. Ensure relay has only two connections
// 4. Ensure extra connection attempts were rejected by nodes rather than relay
func TestHybridNetwork_DuplicateConn(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.EnableP2PHybridMode = true
	log := logging.TestingLog(t)
	const p2pKeyDir = ""

	identDiscValue := int(networkPeerIdentityDisconnect.GetUint64Value())

	relayCfg := cfg
	relayCfg.ForceRelayMessages = true
	netA, err := NewHybridP2PNetwork(log.With("node", "netA"), relayCfg, p2pKeyDir, nil, genesisID, "net", &nopeNodeInfo{})
	require.NoError(t, err)

	err = netA.Start()
	require.NoError(t, err)

	// collect ws address
	addr, portListen := netA.wsNetwork.Address()
	require.True(t, portListen)
	require.NotZero(t, addr)
	parsed, err := url.Parse(addr)
	require.NoError(t, err)
	addr = parsed.Host
	netA.Stop()

	// make it net address and restart the node
	relayCfg.NetAddress = addr
	relayCfg.PublicAddress = addr
	netA, err = NewHybridP2PNetwork(log.With("node", "netA"), relayCfg, p2pKeyDir, nil, genesisID, "net", &nopeNodeInfo{})
	require.NoError(t, err)

	err = netA.Start()
	require.NoError(t, err)
	defer netA.Stop()

	// collect relay address and prepare nodes phonebook
	peerInfoA := netA.p2pNetwork.service.AddrInfo()
	addrsAp2p, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsAp2p[0])
	multiAddrStr := addrsAp2p[0].String()

	fullAddr, portListen := netA.wsNetwork.Address()
	require.True(t, portListen)
	require.NotZero(t, addr)
	require.Contains(t, fullAddr, addr)

	phoneBookAddresses := []string{multiAddrStr, addr}

	netB, err := NewHybridP2PNetwork(log.With("node", "netB"), cfg, "", phoneBookAddresses, genesisID, "net", &nopeNodeInfo{})
	require.NoError(t, err)
	// for netB start the p2p network first
	err = netB.p2pNetwork.Start()
	require.NoError(t, err)
	defer netB.Stop()

	netC, err := NewHybridP2PNetwork(log.With("node", "netC"), cfg, "", phoneBookAddresses, genesisID, "net", &nopeNodeInfo{})
	require.NoError(t, err)
	// for netC start the ws network first
	err = netC.wsNetwork.Start()
	require.NoError(t, err)
	defer netC.Stop()

	// ensure initial connections are done
	require.Eventually(t, func() bool {
		return len(netA.GetPeers(PeersConnectedIn)) == 2+identDiscValue
	}, 3*time.Second, 50*time.Millisecond)

	// start the second half of the hybrid net
	err = netB.wsNetwork.Start()
	require.NoError(t, err)
	err = netC.p2pNetwork.Start()
	require.NoError(t, err)

	// wait for connection attempts. nodes need some time to make connections,
	// and instead of `time.Sleep(1 * time.Second)` the networkPeerIdentityDisconnect net identity counter is used.
	// Since this test is not parallel the networkPeerIdentityDisconnect should not be modified from outside.
	require.Eventually(t, func() bool {
		return networkPeerIdentityDisconnect.GetUint64Value() == 2
	}, 2*time.Second, 50*time.Millisecond)

	// now count connections
	// netA should have 2 connections, not 4
	// netB should have 1 connection (via p2p)
	// netC should have 1 connection (via ws)

	require.Eventually(t, func() bool {
		return len(netB.GetPeers(PeersConnectedOut)) == 1
	}, time.Second, 50*time.Millisecond)

	require.Eventually(t, func() bool {
		return len(netC.GetPeers(PeersConnectedOut)) == 1
	}, time.Second, 50*time.Millisecond)

	require.Eventually(t, func() bool {
		return len(netA.GetPeers(PeersConnectedIn)) == 2
	}, 3*time.Second, 50*time.Millisecond)
}
