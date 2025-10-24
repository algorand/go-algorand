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
	cfg.DNSBootstrapID = ""
	log := logging.TestingLog(t)
	const p2pKeyDir = ""

	identDiscValue := networkPeerIdentityDisconnect.GetUint64Value()
	genesisInfo := GenesisInfo{genesisID, "net"}

	relayCfg := cfg
	relayCfg.ForceRelayMessages = true
	netA, err := NewHybridP2PNetwork(log.With("node", "netA"), relayCfg, p2pKeyDir, nil, genesisInfo, &nopeNodeInfo{}, &baseMeshCreator{})
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
	relayCfg.P2PHybridNetAddress = "127.0.0.1:0"
	netA, err = NewHybridP2PNetwork(log.With("node", "netA"), relayCfg, p2pKeyDir, nil, genesisInfo, &nopeNodeInfo{}, &baseMeshCreator{})
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

	netB, err := NewHybridP2PNetwork(log.With("node", "netB"), cfg, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, &baseMeshCreator{})
	require.NoError(t, err)
	// for netB start the p2p network first
	err = netB.p2pNetwork.Start()
	require.NoError(t, err)
	defer netB.Stop()

	netC, err := NewHybridP2PNetwork(log.With("node", "netC"), cfg, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, &baseMeshCreator{})
	require.NoError(t, err)
	// for netC start the ws network first
	err = netC.wsNetwork.Start()
	require.NoError(t, err)
	defer netC.Stop()

	// ensure initial connections are done
	require.Eventually(t, func() bool {
		return len(netA.GetPeers(PeersConnectedIn)) == 2
	}, 3*time.Second, 50*time.Millisecond)

	// start the second half of the hybrid net
	err = netB.wsNetwork.Start()
	require.NoError(t, err)
	err = netC.p2pNetwork.Start()
	require.NoError(t, err)

	// wait for connection attempts. nodes need some time to make connections,
	// and instead of `time.Sleep(1 * time.Second)` the networkPeerIdentityDisconnect net identity counter is used.
	// Since this test is not parallel the networkPeerIdentityDisconnect should not be modified from outside.
	// Both netB and netC are attempting to connect but netA could also open an outgoing stream in netB or netC connection.
	// So, the counter should be at least 2+identDiscValue.
	const waitFor = 3 * time.Second
	const checkEvery = 50 * time.Millisecond
	const maxTicks = int(waitFor / checkEvery)
	const debugThreshold = maxTicks - maxTicks/20 // log last 5% of ticks
	require.Greater(t, debugThreshold, 1)
	require.Less(t, debugThreshold, maxTicks)
	tickCounter := 0
	require.Eventually(t, func() bool {
		if tickCounter >= debugThreshold {
			log.Infof("networkPeerIdentityDisconnect: %d\n", networkPeerIdentityDisconnect.GetUint64Value())
		}
		tickCounter++
		return networkPeerIdentityDisconnect.GetUint64Value() >= 2+identDiscValue
	}, waitFor, checkEvery)

	// now count connections
	// netA should have 2 connections, not 4
	// netB should have 1 connection (via p2p)
	// netC should have 1 connection (via ws)

	tickCounter = 0
	require.Eventually(t, func() bool {
		if tickCounter >= debugThreshold {
			netAIn := len(netA.GetPeers(PeersConnectedIn))
			netAOut := len(netA.GetPeers(PeersConnectedOut))
			netBIn := len(netB.GetPeers(PeersConnectedIn))
			netBOut := len(netB.GetPeers(PeersConnectedOut))
			netCIn := len(netC.GetPeers(PeersConnectedIn))
			netCOut := len(netC.GetPeers(PeersConnectedOut))
			log.Infof("netA in/out: %d/%d, netB in/out: %d/%d, netC in/out: %d/%d\n", netAIn, netAOut, netBIn, netBOut, netCIn, netCOut)
		}
		tickCounter++
		return len(netB.GetPeers(PeersConnectedOut)) == 1
	}, waitFor, checkEvery)

	tickCounter = 0
	require.Eventually(t, func() bool {
		if tickCounter >= debugThreshold {
			netAIn := len(netA.GetPeers(PeersConnectedIn))
			netAOut := len(netA.GetPeers(PeersConnectedOut))
			netBIn := len(netB.GetPeers(PeersConnectedIn))
			netBOut := len(netB.GetPeers(PeersConnectedOut))
			netCIn := len(netC.GetPeers(PeersConnectedIn))
			netCOut := len(netC.GetPeers(PeersConnectedOut))
			log.Infof("netA in/out: %d/%d, netB in/out: %d/%d, netC in/out: %d/%d\n", netAIn, netAOut, netBIn, netBOut, netCIn, netCOut)
		}
		tickCounter++
		return len(netC.GetPeers(PeersConnectedOut)) == 1
	}, waitFor, checkEvery)

	tickCounter = 0
	require.Eventually(t, func() bool {
		if tickCounter >= debugThreshold {
			netAIn := len(netA.GetPeers(PeersConnectedIn))
			netAOut := len(netA.GetPeers(PeersConnectedOut))
			netBIn := len(netB.GetPeers(PeersConnectedIn))
			netBOut := len(netB.GetPeers(PeersConnectedOut))
			netCIn := len(netC.GetPeers(PeersConnectedIn))
			netCOut := len(netC.GetPeers(PeersConnectedOut))
			log.Infof("netA in/out: %d/%d, netB in/out: %d/%d, netC in/out: %d/%d\n", netAIn, netAOut, netBIn, netBOut, netCIn, netCOut)
		}
		tickCounter++
		return len(netA.GetPeers(PeersConnectedIn)) == 2
	}, 3*time.Second, 50*time.Millisecond)
}

func TestHybridNetwork_ValidateConfig(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := config.GetDefaultLocal()
	cfg.EnableP2PHybridMode = true
	cfg.NetAddress = ":0"
	cfg.P2PHybridNetAddress = ""
	genesisInfo := GenesisInfo{genesisID, "net"}

	_, err := NewHybridP2PNetwork(logging.TestingLog(t), cfg, "", nil, genesisInfo, &nopeNodeInfo{}, &baseMeshCreator{})
	require.ErrorContains(t, err, "both NetAddress and P2PHybridNetAddress")

	cfg.NetAddress = ""
	cfg.P2PHybridNetAddress = ":0"
	_, err = NewHybridP2PNetwork(logging.TestingLog(t), cfg, "", nil, genesisInfo, &nopeNodeInfo{}, &baseMeshCreator{})
	require.ErrorContains(t, err, "both NetAddress and P2PHybridNetAddress")
}

func TestHybridNetwork_HybridRelayStrategy(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := config.GetDefaultLocal()
	cfg.EnableP2PHybridMode = true
	cfg.DNSBootstrapID = ""
	log := logging.TestingLog(t)

	genesisInfo := GenesisInfo{genesisID, "net"}

	startNewRelayNode := func(name string, phonebook []string) (*HybridP2PNetwork, []string) {
		relayCfg := cfg
		relayCfg.ForceRelayMessages = true
		// no phonebook addresses since we start and stop it to collect the ws address
		net, err := NewHybridP2PNetwork(log.With("node", name), relayCfg, "", nil, genesisInfo, &nopeNodeInfo{}, nil)
		require.NoError(t, err)

		err = net.Start()
		require.NoError(t, err)

		// collect ws address
		addr, portListen := net.wsNetwork.Address()
		require.True(t, portListen)
		require.NotZero(t, addr)
		parsed, err := url.Parse(addr)
		require.NoError(t, err)
		addr = parsed.Host
		net.Stop()

		// make it net address and restart the node
		relayCfg.NetAddress = addr
		relayCfg.PublicAddress = addr
		relayCfg.P2PHybridNetAddress = "127.0.0.1:0"
		net, err = NewHybridP2PNetwork(log.With("node", name), relayCfg, "", phonebook, genesisInfo, &nopeNodeInfo{}, nil)
		require.NoError(t, err)

		err = net.Start()
		require.NoError(t, err)

		// collect relay address and prepare nodes phonebook
		peerInfo := net.p2pNetwork.service.AddrInfo()
		addrsP2P, err := peer.AddrInfoToP2pAddrs(&peerInfo)
		require.NoError(t, err)
		require.NotZero(t, addrsP2P[0])
		multiAddrStr := addrsP2P[0].String()

		fullAddr, portListen := net.wsNetwork.Address()
		require.True(t, portListen)
		require.NotZero(t, addr)
		require.Contains(t, fullAddr, addr)

		return net, []string{multiAddrStr, addr}
	}

	netA, netAddrs := startNewRelayNode("netA", nil)
	defer netA.Stop()

	phoneBookAddresses := append([]string{}, netAddrs...)

	netB, netAddrs := startNewRelayNode("netB", phoneBookAddresses)
	defer netB.Stop()

	phoneBookAddresses = append(phoneBookAddresses, netAddrs...)

	netC, _ := startNewRelayNode("netC", phoneBookAddresses)
	defer netC.Stop()

	// ensure initial connections are done
	require.Eventually(t, func() bool {
		return len(netA.GetPeers(PeersConnectedIn, PeersConnectedOut)) == 2 &&
			len(netB.GetPeers(PeersConnectedIn, PeersConnectedOut)) == 2
	}, 3*time.Second, 100*time.Millisecond)

	// make sure all are connected via ws net
	wsPeersA := netA.wsNetwork.GetPeers(PeersConnectedIn, PeersConnectedOut)
	wsPeersB := netB.wsNetwork.GetPeers(PeersConnectedIn, PeersConnectedOut)
	require.Len(t, wsPeersA, 2)
	require.Len(t, wsPeersB, 2)
}
