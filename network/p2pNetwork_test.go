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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	algocrypto "github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/limitcaller"
	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/network/p2p/dnsaddr"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
	"github.com/algorand/go-algorand/network/phonebook"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/uuid"
	"github.com/algorand/go-deadlock"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func (n *P2PNetwork) hasPeers() bool {
	n.wsPeersLock.RLock()
	defer n.wsPeersLock.RUnlock()
	return len(n.wsPeers) > 0
}

func (n *P2PNetwork) hasPeer(peerID peer.ID) bool {
	n.wsPeersLock.RLock()
	defer n.wsPeersLock.RUnlock()
	_, ok := n.wsPeers[peerID]
	return ok
}

func TestP2PSubmitTX(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.ForceFetchTransactions = true
	cfg.NetAddress = "127.0.0.1:0"
	cfg.DNSBootstrapID = ""
	log := logging.TestingLog(t)
	genesisInfo := GenesisInfo{genesisID, config.Devtestnet}
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	netA.Start()
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}
	netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	netB.Start()
	defer netB.Stop()

	netC, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	netC.Start()
	defer netC.Stop()

	require.Eventually(
		t,
		func() bool {
			return len(netA.service.ListPeersForTopic(p2p.TXTopicName)) == 2 &&
				len(netB.service.ListPeersForTopic(p2p.TXTopicName)) == 1 &&
				len(netC.service.ListPeersForTopic(p2p.TXTopicName)) == 1
		},
		2*time.Second,
		50*time.Millisecond,
	)
	require.Eventually(t, func() bool {
		return netA.hasPeers() && netB.hasPeers() && netC.hasPeers()
	}, 5*time.Second, 50*time.Millisecond)

	// for some reason the above check is not enough in race builds on CI
	time.Sleep(time.Second) // give time for peers to connect.

	// now we should be connected in a line: B <-> A <-> C where both B and C are connected to A but not each other

	// Since we aren't using the transaction handler in this test, we need to register a pass-through handler
	passThroughHandler := []TaggedMessageValidatorHandler{
		{
			Tag: protocol.TxnTag,
			MessageHandler: struct {
				ValidateHandleFunc
			}{
				ValidateHandleFunc(func(msg IncomingMessage) OutgoingMessage {
					return OutgoingMessage{Action: Accept, Tag: msg.Tag}
				}),
			},
		},
	}

	netA.RegisterValidatorHandlers(passThroughHandler)
	netB.RegisterValidatorHandlers(passThroughHandler)
	netC.RegisterValidatorHandlers(passThroughHandler)

	// send messages from B and confirm that they get received by C (via A)
	for i := 0; i < 10; i++ {
		err = netB.Broadcast(context.Background(), protocol.TxnTag, []byte(fmt.Sprintf("hello %d", i)), false, nil)
		require.NoError(t, err)
	}

	require.Eventually(
		t,
		func() bool {
			netC.peerStatsMu.Lock()
			netCpeerStatsA, ok := netC.peerStats[netA.service.ID()]
			netC.peerStatsMu.Unlock()
			if !ok {
				return false
			}
			return netCpeerStatsA.txReceived.Load() == 10
		},
		1*time.Second,
		50*time.Millisecond,
	)
}

// TestP2PSubmitTXNoGossip tests nodes without gossip enabled cannot receive transactions
func TestP2PSubmitTXNoGossip(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.ForceFetchTransactions = true
	cfg.NetAddress = "127.0.0.1:0"
	cfg.DNSBootstrapID = ""
	log := logging.TestingLog(t)
	genesisInfo := GenesisInfo{genesisID, config.Devtestnet}
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	netA.Start()
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}
	netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	netB.Start()
	defer netB.Stop()

	require.Eventually(
		t,
		func() bool {
			return len(netA.service.ListPeersForTopic(p2p.TXTopicName)) == 1 &&
				len(netB.service.ListPeersForTopic(p2p.TXTopicName)) == 1
		},
		2*time.Second,
		50*time.Millisecond,
	)

	// run netC in NPN mode (no relay => no gossip sup => no TX receiving)
	cfg.ForceFetchTransactions = false
	// Have to unset NetAddress to get IsGossipServer to return false
	cfg.NetAddress = ""
	netC, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	netC.Start()
	defer netC.Stop()

	require.Eventually(t, func() bool {
		return netA.hasPeers() && netB.hasPeers() && netC.hasPeers()
	}, 5*time.Second, 50*time.Millisecond)

	time.Sleep(time.Second) // give time for peers to connect.

	// ensure netC cannot receive messages

	passThroughHandler := []TaggedMessageValidatorHandler{
		{
			Tag: protocol.TxnTag,
			MessageHandler: struct {
				ValidateHandleFunc
			}{
				ValidateHandleFunc(func(msg IncomingMessage) OutgoingMessage {
					return OutgoingMessage{Action: Accept, Tag: msg.Tag}
				}),
			},
		},
	}

	netB.RegisterValidatorHandlers(passThroughHandler)
	netC.RegisterValidatorHandlers(passThroughHandler)
	for i := 0; i < 10; i++ {
		err = netA.Broadcast(context.Background(), protocol.TxnTag, []byte(fmt.Sprintf("test %d", i)), false, nil)
		require.NoError(t, err)
	}

	// check netB received the messages
	require.Eventually(
		t,
		func() bool {
			netB.peerStatsMu.Lock()
			netBpeerStatsA, ok := netB.peerStats[netA.service.ID()]
			netB.peerStatsMu.Unlock()
			if !ok {
				return false
			}
			return netBpeerStatsA.txReceived.Load() == 10
		},
		1*time.Second,
		50*time.Millisecond,
	)

	// check netC did not receive the messages
	netC.peerStatsMu.Lock()
	_, ok := netC.peerStats[netA.service.ID()]
	netC.peerStatsMu.Unlock()
	require.False(t, ok)
}

func TestP2PSubmitWS(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.NetAddress = "127.0.0.1:0"
	cfg.DNSBootstrapID = ""
	log := logging.TestingLog(t)
	genesisInfo := GenesisInfo{genesisID, config.Devtestnet}
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)

	err = netA.Start()
	require.NoError(t, err)
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}
	netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	err = netB.Start()
	require.NoError(t, err)
	defer netB.Stop()

	netC, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	err = netC.Start()
	require.NoError(t, err)
	defer netC.Stop()

	require.Eventually(t, func() bool {
		return netA.hasPeers() && netB.hasPeers() && netC.hasPeers()
	}, 5*time.Second, 50*time.Millisecond)

	time.Sleep(time.Second) // give time for peers to connect.

	// now we should be connected in a line: B <-> A <-> C where both B and C are connected to A but not each other

	testTag := protocol.AgreementVoteTag
	var handlerCount atomic.Uint32

	// Since we aren't using the transaction handler in this test, we need to register a pass-through handler
	passThroughHandler := []TaggedMessageHandler{
		{Tag: testTag, MessageHandler: HandlerFunc(func(msg IncomingMessage) OutgoingMessage {
			handlerCount.Add(1)
			return OutgoingMessage{Action: Broadcast}
		})},
	}

	netA.RegisterHandlers(passThroughHandler)
	netB.RegisterHandlers(passThroughHandler)
	netC.RegisterHandlers(passThroughHandler)

	// send messages from B and confirm that they get received by C (via A)
	for i := 0; i < 10; i++ {
		err = netB.Broadcast(context.Background(), testTag, []byte(fmt.Sprintf("hello %d", i)), false, nil)
		require.NoError(t, err)
	}

	require.Eventually(
		t,
		func() bool {
			return handlerCount.Load() == 20
		},
		1*time.Second,
		50*time.Millisecond,
	)
}

type mockService struct {
	id    peer.ID
	addrs []ma.Multiaddr
	peers map[peer.ID]peer.AddrInfo
}

func (s *mockService) Start() error {
	return nil
}

func (s *mockService) Close() error {
	return nil
}

func (s *mockService) ID() peer.ID {
	return s.id
}

func (s *mockService) IDSigner() *p2p.PeerIDChallengeSigner {
	panic("not implemented")
}

func (s *mockService) AddrInfo() peer.AddrInfo {
	return peer.AddrInfo{
		ID:    s.id,
		Addrs: s.addrs,
	}
}

func (s *mockService) DialPeersUntilTargetCount(targetConnCount int) bool {
	return false
}

func (s *mockService) ClosePeer(peer peer.ID) error {
	delete(s.peers, peer)
	return nil
}

func (s *mockService) Conns() []network.Conn {
	return nil
}

func (s *mockService) ListPeersForTopic(topic string) []peer.ID {
	return nil
}

func (s *mockService) Subscribe(topic string, val pubsub.ValidatorEx) (p2p.SubNextCancellable, error) {
	return nil, nil
}
func (s *mockService) Publish(ctx context.Context, topic string, data []byte) error {
	return nil
}

func (s *mockService) GetHTTPClient(addrInfo *peer.AddrInfo, connTimeStore limitcaller.ConnectionTimeStore, queueingTimeout time.Duration) (*http.Client, error) {
	return nil, nil
}

func (s *mockService) NetworkNotify(notifiee network.Notifiee) {
}

func (s *mockService) NetworkStopNotify(notifiee network.Notifiee) {
}

func makeMockService(id peer.ID, addrs []ma.Multiaddr) *mockService {
	return &mockService{
		id:    id,
		addrs: addrs,
	}
}

func TestP2PNetworkAddress(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	log := logging.TestingLog(t)
	netA, err := NewP2PNetwork(log, cfg, "", nil, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	defer netA.Stop()
	addrInfo := netA.service.AddrInfo()
	// close the real service since we will substitute a mock one
	netA.service.Close()

	// define some multiaddrs we will use in the test
	loopbackAddr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1234")
	require.NoError(t, err)
	unspecifiedAddr, err := ma.NewMultiaddr("/ip4/0.0.0.0/tcp/0")
	require.NoError(t, err)
	publicAddr, err := ma.NewMultiaddr("/ip4/12.86.192.5/tcp/5678")
	require.NoError(t, err)
	publicAddr2, err := ma.NewMultiaddr("/ip4/23.97.191.6/tcp/1564")
	require.NoError(t, err)

	// first two are invalid so third one should be returned as the first public address
	addrsA := []ma.Multiaddr{
		loopbackAddr,
		unspecifiedAddr,
		publicAddr,
		publicAddr2,
	}
	mockService := makeMockService(addrInfo.ID, addrsA)
	netA.service = mockService

	retAddr, ok := netA.Address()
	require.True(t, ok)
	// using Contains since the return of Address also includes the public peerID
	require.Contains(t, retAddr, publicAddr.String())

	// don't have a public address so return the first one
	addrsB := []ma.Multiaddr{
		loopbackAddr,
		unspecifiedAddr,
	}
	mockService.addrs = addrsB
	retAddr, ok = netA.Address()
	require.True(t, ok)
	require.Contains(t, retAddr, loopbackAddr.String())

	// confirm that we don't return an address if none is supplied
	mockService.addrs = nil
	retAddr, ok = netA.Address()
	require.False(t, ok)
	require.Empty(t, retAddr)

	mockService.addrs = addrsA         // these are still valid addresses
	mockService.id = "invalid peer ID" // this won't parse and encode properly
	retAddr, ok = netA.Address()
	require.False(t, ok)
	require.Empty(t, retAddr)
}

type nilResolveController struct{}

func (c *nilResolveController) Resolver() dnsaddr.Resolver {
	return nil
}

func (c *nilResolveController) NextResolver() dnsaddr.Resolver {
	return nil
}

type mockResolveController struct {
	nilResolveController
}

func (c *mockResolveController) Resolver() dnsaddr.Resolver {
	return &mockResolver{}
}

type mockResolver struct{}

func (r *mockResolver) Resolve(ctx context.Context, _ ma.Multiaddr) ([]ma.Multiaddr, error) {
	// return random stuff each time
	_, publicKey, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		panic(err)
	}
	peerID, err := peer.IDFromPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	maddr, err := ma.NewMultiaddr("/ip4/127.0.0.1/p2p/" + peerID.String())
	return []ma.Multiaddr{maddr}, err
}

func TestP2PBootstrapFunc(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	b := bootstrapper{}
	require.Nil(t, b.BootstrapFunc())

	b.started.Store(true)
	p := peer.AddrInfo{ID: "test"}
	b.phonebookPeers = []*peer.AddrInfo{&p}
	require.Equal(t, []peer.AddrInfo{p}, b.BootstrapFunc())

	b.phonebookPeers = nil

	b.cfg = config.GetDefaultLocal()
	b.cfg.DNSBootstrapID = "<network>.algodev.network"
	b.cfg.DNSSecurityFlags = 0
	b.networkID = "devnet"
	b.resolveController = &mockResolveController{}

	addrs := b.BootstrapFunc()

	require.GreaterOrEqual(t, len(addrs), 1)
	addr := addrs[0]
	require.Equal(t, len(addr.Addrs), 1)
	require.GreaterOrEqual(t, len(addr.Addrs), 1)
}

func TestP2PdnsLookupBootstrapPeersErr(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.DNSSecurityFlags = 0
	cfg.DNSBootstrapID = "non-existent.algodev.network"

	controller := nilResolveController{}
	addrs := dnsLookupBootstrapPeers(logging.TestingLog(t), cfg, "test", &controller)

	require.Equal(t, 0, len(addrs))
}

func TestP2PdnsLookupBootstrapPeersInvalidAddr(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.DNSSecurityFlags = 0
	cfg.DNSBootstrapID = "<network>.algodev.network"

	controller := nilResolveController{}
	addrs := dnsLookupBootstrapPeers(logging.TestingLog(t), cfg, "testInvalidAddr", &controller)

	require.Equal(t, 0, len(addrs))
}

func TestP2PdnsLookupBootstrapPeersWithBackup(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.DNSSecurityFlags = 0
	cfg.DNSBootstrapID = "<network>.algodev.network"

	controller := &mockResolveController{}
	addrs := dnsLookupBootstrapPeers(logging.TestingLog(t), cfg, "test", controller)
	require.GreaterOrEqual(t, len(addrs), 1)

	cfg.DNSBootstrapID = "<network>.algodev.network?backup=<network>.backup.algodev.network"
	addrs = dnsLookupBootstrapPeers(logging.TestingLog(t), cfg, "test", controller)
	require.GreaterOrEqual(t, len(addrs), 2)

}

type capNodeInfo struct {
	nopeNodeInfo
	cap p2p.Capability
}

func (ni *capNodeInfo) Capabilities() []p2p.Capability {
	return []p2p.Capability{ni.cap}
}

func waitForRouting(t *testing.T, disc *p2p.CapabilitiesDiscovery) {
	refreshCtx, refCancel := context.WithTimeout(context.Background(), time.Second*5)
	for {
		select {
		case <-refreshCtx.Done():
			refCancel()
			require.Fail(t, "failed to populate routing table before timeout")
		default:
			if disc.RoutingTable().Size() > 0 {
				refCancel()
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestP2PNetworkDHTCapabilities runs nodes with capabilities and ensures that connected nodes
// can discover itself. The other nodes receive the first node in bootstrap list before starting.
// There is two variations of the test: only netA advertises capabilities, and all nodes advertise.
func TestP2PNetworkDHTCapabilities(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.NetAddress = "127.0.0.1:0"
	cfg.EnableDHTProviders = true
	cfg.DNSBootstrapID = ""
	log := logging.TestingLog(t)
	genesisInfo := GenesisInfo{genesisID, config.Devtestnet}

	cap := p2p.Archival
	tests := []struct {
		name        string
		nis         []NodeInfo
		numCapPeers int
	}{
		{"cap=all", []NodeInfo{&capNodeInfo{cap: cap}, &capNodeInfo{cap: cap}, &capNodeInfo{cap: cap}}, 2}, // each has 2 peers with capabilities
		{"cap=netA", []NodeInfo{&capNodeInfo{cap: cap}, &nopeNodeInfo{}, &nopeNodeInfo{}}, 1},              // each has 1 peer with capabilities
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			netA, err := NewP2PNetwork(log.With("name", "netA"), cfg, "", nil, genesisInfo, test.nis[0], nil, nil)
			require.NoError(t, err)

			err = netA.Start()
			require.NoError(t, err)
			defer netA.Stop()

			peerInfoA := netA.service.AddrInfo()
			addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
			require.NoError(t, err)
			require.NotZero(t, addrsA[0])

			multiAddrStr := addrsA[0].String()
			phoneBookAddresses := []string{multiAddrStr}
			netB, err := NewP2PNetwork(log.With("name", "netB"), cfg, "", phoneBookAddresses, genesisInfo, test.nis[1], nil, nil)
			require.NoError(t, err)
			err = netB.Start()
			require.NoError(t, err)
			defer netB.Stop()

			netC, err := NewP2PNetwork(log.With("name", "netC"), cfg, "", phoneBookAddresses, genesisInfo, test.nis[2], nil, nil)
			require.NoError(t, err)
			err = netC.Start()
			require.NoError(t, err)
			defer netC.Stop()

			require.Eventually(t, func() bool {
				return netA.hasPeers() && netB.hasPeers() && netC.hasPeers()
			}, 2*time.Second, 50*time.Millisecond)

			t.Logf("peers connected")

			nets := []*P2PNetwork{netA, netB, netC}
			discs := []*p2p.CapabilitiesDiscovery{netA.capabilitiesDiscovery, netB.capabilitiesDiscovery, netC.capabilitiesDiscovery}

			var wg sync.WaitGroup
			wg.Add(len(discs))
			for _, disc := range discs {
				if disc == nil {
					wg.Done()
					continue
				}
				go func(disc *p2p.CapabilitiesDiscovery) {
					defer wg.Done()
					waitForRouting(t, disc)
				}(disc)
			}
			wg.Wait()

			t.Logf("DHT is ready")

			// ensure all peers are connected - wait for connectivity as needed
			for _, disc := range discs {
				go func(disc *p2p.CapabilitiesDiscovery) {
					require.Eventuallyf(t, func() bool {
						return len(disc.Host().Network().Peers()) == 2
					}, time.Minute, time.Second, "Not all peers were found")
				}(disc)
			}

			wg.Add(len(discs))
			for i := range discs {
				go func(idx int) {
					disc := discs[idx]
					defer wg.Done()
					// skip netA since it is special for the test cap=netA
					if test.name == "cap=netA" && disc == netA.capabilitiesDiscovery {
						return
					}
					require.Eventuallyf(t,
						func() bool {
							peers, err := disc.PeersForCapability(cap, test.numCapPeers)
							if err == nil && len(peers) == test.numCapPeers {
								return true
							}
							return false
						},
						time.Minute,
						time.Second,
						fmt.Sprintf("Not all expected %s cap peers were found", cap),
					)
					// ensure GetPeers gets PeersPhonebookArchivalNodes peers
					// it appears there are artificial peers because of listening on localhost and on a real network interface
					// so filter out and save only unique peers by their IDs
					net := nets[idx]
					net.meshThreadInner(cfg.GossipFanout) // update peerstore with DHT peers
					peers := net.GetPeers(PeersPhonebookArchivalNodes)
					uniquePeerIDs := make(map[peer.ID]struct{})
					for _, p := range peers {
						wsPeer := p.(*wsPeerCore)
						pi, err := peer.AddrInfoFromString(wsPeer.GetAddress())
						require.NoError(t, err)
						uniquePeerIDs[pi.ID] = struct{}{}
					}
					require.Equal(t, test.numCapPeers, len(uniquePeerIDs))
				}(i)
			}
			wg.Wait()
		})
	}
}

// TestMultiaddrConversionToFrom ensures Multiaddr can be serialized back to an address without losing information
func TestP2PMultiaddrConversionToFrom(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const a = "/ip4/192.168.1.1/tcp/8180/p2p/Qmewz5ZHN1AAGTarRbMupNPbZRfg3p5jUGoJ3JYEatJVVk"
	ma, err := ma.NewMultiaddr(a)
	require.NoError(t, err)
	require.Equal(t, a, ma.String())

	// this conversion drops the p2p proto part
	pi, err := peer.AddrInfoFromP2pAddr(ma)
	require.NoError(t, err)
	require.NotEqual(t, a, pi.Addrs[0].String())
	require.Len(t, pi.Addrs, 1)

	mas, err := peer.AddrInfoToP2pAddrs(pi)
	require.NoError(t, err)
	require.Len(t, mas, 1)
	require.Equal(t, a, mas[0].String())
}

type p2phttpHandler struct {
	tb      testing.TB
	retData string
	net     GossipNode
}

func (h *p2phttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h.retData))
	if r.URL.Path == "/check-conn" {
		rc := http.NewResponseController(w)
		err := rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		require.NoError(h.tb, err)
	}
}

func TestP2PHTTPHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := config.GetDefaultLocal()
	cfg.EnableDHTProviders = true
	cfg.GossipFanout = 1
	cfg.NetAddress = "127.0.0.1:0"
	log := logging.TestingLog(t)

	netA, err := NewP2PNetwork(log, cfg, "", nil, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)

	h := &p2phttpHandler{t, "hello", nil}
	netA.RegisterHTTPHandler("/test", h)

	h2 := &p2phttpHandler{t, "world", netA}
	netA.RegisterHTTPHandler("/check-conn", h2)

	netA.Start()
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	httpClient, err := p2p.MakeTestHTTPClient(&peerInfoA)
	require.NoError(t, err)
	resp, err := httpClient.Get("/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(body))

	// check another endpoint that also access the underlying connection/stream
	httpClient, err = p2p.MakeTestHTTPClient(&peerInfoA)
	require.NoError(t, err)
	resp, err = httpClient.Get("/check-conn")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "world", string(body))

	// check rate limiting client:
	// zero clients allowed, rate limiting window (10s) is greater than queue deadline (1s)
	netB, err := NewP2PNetwork(log, cfg, "", nil, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	defer netB.Stop() // even though netB.Start is not called, NewP2PNetwork creates goroutines to stop

	pstore, err := peerstore.MakePhonebook(0, 10*time.Second)
	require.NoError(t, err)
	pstore.AddPersistentPeers([]*peer.AddrInfo{&peerInfoA}, "net", phonebook.RelayRole)
	httpClient, err = netB.service.GetHTTPClient(&peerInfoA, pstore, 1*time.Second)
	require.NoError(t, err)
	_, err = httpClient.Get("/test")
	require.ErrorIs(t, err, limitcaller.ErrConnectionQueueingTimeout)
}

// TestP2PHTTPHandlerAllInterfaces makes sure HTTP server runs even if NetAddress is set to a non-routable address
func TestP2PHTTPHandlerAllInterfaces(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := config.GetDefaultLocal()
	cfg.EnableDHTProviders = false
	cfg.GossipFanout = 1
	cfg.NetAddress = ":0"
	log := logging.TestingLog(t)

	netA, err := NewP2PNetwork(log, cfg, "", nil, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)

	h := &p2phttpHandler{t, "hello", nil}
	netA.RegisterHTTPHandler("/test", h)

	netA.Start()
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	t.Logf("peerInfoA: %s", peerInfoA)
	httpClient, err := p2p.MakeTestHTTPClient(&peerInfoA)
	require.NoError(t, err)
	resp, err := httpClient.Get("/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(body))

}

// TestP2PRelay checks p2p nodes can properly relay messages:
// netA and netB are started with ForceFetchTransactions so it subscribes to the txn topic,
// both of them are connected and do not relay messages.
// Later, netB is forced to relay messages and netC is started with a listening address set
// so that it relays messages as well.
// The test checks messages from both netB and netC are received by netA.
func TestP2PRelay(t *testing.T) {
	partitiontest.PartitionTest(t)

	if strings.ToUpper(os.Getenv("CIRCLECI")) == "TRUE" {
		t.Skip("Flaky on CIRCLECI")
	}

	cfg := config.GetDefaultLocal()
	cfg.DNSBootstrapID = "" // disable DNS lookups since the test uses phonebook addresses
	cfg.ForceFetchTransactions = true
	cfg.BaseLoggerDebugLevel = 5
	cfg.NetAddress = "127.0.0.1:0"
	log := logging.TestingLog(t)
	genesisInfo := GenesisInfo{genesisID, config.Devtestnet}
	log.Debugln("Starting netA")
	netA, err := NewP2PNetwork(log.With("net", "netA"), cfg, "", nil, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)

	err = netA.Start()
	require.NoError(t, err)
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}

	// Explicitly unset NetAddress for netB
	cfg.NetAddress = ""
	log.Debugf("Starting netB with phonebook addresses %v", phoneBookAddresses)
	netB, err := NewP2PNetwork(log.With("net", "netB"), cfg, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	err = netB.Start()
	require.NoError(t, err)
	defer netB.Stop()

	require.Eventually(
		t,
		func() bool {
			return len(netA.service.ListPeersForTopic(p2p.TXTopicName)) > 0 &&
				len(netB.service.ListPeersForTopic(p2p.TXTopicName)) > 0
		},
		2*time.Second,
		50*time.Millisecond,
	)

	require.Eventually(t, func() bool {
		return netA.hasPeers() && netB.hasPeers()
	}, 2*time.Second, 50*time.Millisecond)

	type logMessages struct {
		msgs [][]byte
		mu   deadlock.Mutex
	}
	makeCounterHandler := func(numExpected int, counter *atomic.Uint32, msgSink *logMessages) ([]TaggedMessageValidatorHandler, chan struct{}) {
		counterDone := make(chan struct{})
		counterHandler := []TaggedMessageValidatorHandler{
			{
				Tag: protocol.TxnTag,
				MessageHandler: struct {
					ValidateHandleFunc
				}{
					ValidateHandleFunc(func(msg IncomingMessage) OutgoingMessage {
						if msgSink != nil {
							msgSink.mu.Lock()
							msgSink.msgs = append(msgSink.msgs, msg.Data)
							msgSink.mu.Unlock()
						}
						if count := counter.Add(1); int(count) >= numExpected {
							close(counterDone)
						}
						return OutgoingMessage{Action: Accept, Tag: msg.Tag}
					}),
				},
			},
		}
		return counterHandler, counterDone
	}
	var counter atomic.Uint32
	counterHandler, counterDone := makeCounterHandler(1, &counter, nil)
	netA.RegisterValidatorHandlers(counterHandler)

	// send 5 messages from netB to netA
	// since relaying is disabled on net B => no messages should be received by net A
	for i := 0; i < 5; i++ {
		err := netB.Relay(context.Background(), protocol.TxnTag, []byte{1, 2, 3, byte(i)}, true, nil)
		require.NoError(t, err)
	}

	select {
	case <-counterDone:
		require.Fail(t, "No messages should have been received")
	case <-time.After(1 * time.Second):
	}

	// add a netC with listening address set and enable relaying on netB
	// ensure all messages from netB and netC are received by netA
	cfg.NetAddress = "127.0.0.1:0"
	log.Debugf("Starting netC with phonebook addresses %v", phoneBookAddresses)
	netC, err := NewP2PNetwork(log.With("net", "netC"), cfg, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	require.True(t, netC.relayMessages)
	err = netC.Start()
	require.NoError(t, err)
	defer netC.Stop()

	netB.relayMessages = true

	require.Eventually(
		t,
		func() bool {
			netAtopicPeers := netA.service.ListPeersForTopic(p2p.TXTopicName)
			netBtopicPeers := netB.service.ListPeersForTopic(p2p.TXTopicName)
			netCtopicPeers := netC.service.ListPeersForTopic(p2p.TXTopicName)
			netBConnected := slices.Contains(netAtopicPeers, netB.service.ID())
			netCConnected := slices.Contains(netAtopicPeers, netC.service.ID())
			return len(netAtopicPeers) >= 2 &&
				len(netBtopicPeers) > 0 &&
				len(netCtopicPeers) > 0 &&
				netBConnected && netCConnected
		},
		10*time.Second, // wait until netC node gets actually connected to netA after starting
		50*time.Millisecond,
	)

	require.Eventually(t, func() bool {
		return netA.hasPeers() && netB.hasPeers() && netC.hasPeers() &&
			netA.hasPeer(netB.service.ID()) && netA.hasPeer(netC.service.ID())
	}, 2*time.Second, 50*time.Millisecond)

	const expectedMsgs = 10
	counter.Store(0)
	var msgsSink logMessages
	counterHandler, counterDone = makeCounterHandler(expectedMsgs, &counter, &msgsSink)
	netA.ClearValidatorHandlers()
	netA.RegisterValidatorHandlers(counterHandler)

	for i := 0; i < expectedMsgs/2; i++ {
		err := netB.Relay(context.Background(), protocol.TxnTag, []byte{5, 6, 7, byte(i)}, true, nil)
		require.NoError(t, err)
		err = netC.Relay(context.Background(), protocol.TxnTag, []byte{11, 12, 10 + byte(i), 14}, true, nil)
		require.NoError(t, err)
	}
	// send some duplicate messages, they should be dropped
	for i := 0; i < expectedMsgs/2; i++ {
		err := netB.Relay(context.Background(), protocol.TxnTag, []byte{5, 6, 7, byte(i)}, true, nil)
		require.NoError(t, err)
	}

	select {
	case <-counterDone:
	case <-time.After(3 * time.Second):
		if c := counter.Load(); c < expectedMsgs {
			t.Logf("Logged messages: %v", msgsSink.msgs)
			require.Failf(t, "One or more messages failed to reach destination network", "%d > %d", expectedMsgs, c)
		} else if c > expectedMsgs {
			t.Logf("Logged messages: %v", msgsSink.msgs)
			require.Failf(t, "One or more messages that were expected to be dropped, reached destination network", "%d < %d", expectedMsgs, c)
		}
	}
}

type mockSubPService struct {
	mockService
	count          atomic.Int64
	otherPeerID    peer.ID
	shouldNextFail bool
}

type mockSubscription struct {
	peerID         peer.ID
	shouldNextFail bool
}

func (m *mockSubscription) Next(ctx context.Context) (*pubsub.Message, error) {
	if m.shouldNextFail {
		return nil, errors.New("mockSubscription error")
	}
	return &pubsub.Message{ReceivedFrom: m.peerID}, nil
}
func (m *mockSubscription) Cancel() {}

func (m *mockSubPService) Subscribe(topic string, val pubsub.ValidatorEx) (p2p.SubNextCancellable, error) {
	m.count.Add(1)
	otherPeerID := m.otherPeerID
	if otherPeerID == "" {
		otherPeerID = "mockSubPServicePeerID"
	}
	return &mockSubscription{peerID: otherPeerID, shouldNextFail: m.shouldNextFail}, nil
}

// TestP2PWantTXGossip checks txTopicHandleLoop runs as expected on wantTXGossip changes
func TestP2PWantTXGossip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// cancelled context to trigger subscription.Next to return
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	peerID := peer.ID("myPeerID")
	mockService := &mockSubPService{mockService: mockService{id: peerID}, shouldNextFail: true}
	net := &P2PNetwork{
		service:         mockService,
		log:             logging.TestingLog(t),
		ctx:             ctx,
		nodeInfo:        &nopeNodeInfo{},
		connPerfMonitor: makeConnectionPerformanceMonitor([]Tag{protocol.AgreementVoteTag, protocol.TxnTag}),
	}
	net.outgoingConnsCloser = makeOutgoingConnsCloser(logging.TestingLog(t), net, net.connPerfMonitor, cliqueResolveInterval)

	// ensure wantTXGossip from false to false is noop
	net.wantTXGossip.Store(false)
	net.OnNetworkAdvance()
	require.Eventually(t, func() bool { net.wg.Wait(); return true }, 1*time.Second, 50*time.Millisecond)
	require.Equal(t, int64(0), mockService.count.Load())
	require.False(t, net.wantTXGossip.Load())

	// ensure wantTXGossip from true (wantTXGossip) to false (nopeNodeInfo) is noop
	net.wantTXGossip.Store(true)
	net.OnNetworkAdvance()
	require.Eventually(t, func() bool { net.wg.Wait(); return true }, 1*time.Second, 50*time.Millisecond)
	require.Equal(t, int64(0), mockService.count.Load())
	require.False(t, net.wantTXGossip.Load())

	// check false to true change triggers subscription
	net.wantTXGossip.Store(false)
	net.nodeInfo = &participatingNodeInfo{}
	net.OnNetworkAdvance()
	require.Eventually(t, func() bool { return mockService.count.Load() == 1 }, 1*time.Second, 50*time.Millisecond)
	require.True(t, net.wantTXGossip.Load())

	// check IsParticipating changes wantTXGossip
	net.wantTXGossip.Store(true)
	net.nodeInfo = &nopeNodeInfo{}
	net.config.ForceFetchTransactions = false
	net.config.NetAddress = ""
	net.relayMessages = false
	net.OnNetworkAdvance()
	require.Eventually(t, func() bool { net.wg.Wait(); return true }, 1*time.Second, 50*time.Millisecond)
	require.False(t, net.wantTXGossip.Load())

	// check ForceFetchTransactions and relayMessages also take effect
	net.wantTXGossip.Store(false)
	net.nodeInfo = &nopeNodeInfo{}
	net.config.ForceFetchTransactions = true
	net.relayMessages = false
	net.OnNetworkAdvance()
	require.Eventually(t, func() bool { return mockService.count.Load() == 2 }, 1*time.Second, 50*time.Millisecond)
	require.True(t, net.wantTXGossip.Load())

	net.wantTXGossip.Store(false)
	net.nodeInfo = &nopeNodeInfo{}
	net.config.ForceFetchTransactions = false
	net.config.NetAddress = ""
	net.relayMessages = true
	net.OnNetworkAdvance()
	require.Eventually(t, func() bool { return mockService.count.Load() == 3 }, 1*time.Second, 50*time.Millisecond)
	require.True(t, net.wantTXGossip.Load())

	// ensure empty nodeInfo prevents changing the value
	net.wantTXGossip.Store(false)
	net.nodeInfo = nil
	net.config.ForceFetchTransactions = true
	net.relayMessages = true
	net.OnNetworkAdvance()
	require.Eventually(t, func() bool { net.wg.Wait(); return true }, 1*time.Second, 50*time.Millisecond)
	require.False(t, net.wantTXGossip.Load())

	// check true to true change is noop
	net.wantTXGossip.Store(true)
	net.nodeInfo = &participatingNodeInfo{}
	net.OnNetworkAdvance()
	require.Eventually(t, func() bool { return mockService.count.Load() == 3 }, 1*time.Second, 50*time.Millisecond)
	require.True(t, net.wantTXGossip.Load())
}

func TestP2PMergeAddrInfoResolvedAddresses(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	m1, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN")
	require.NoError(t, err)
	m2, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/4001/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb")
	require.NoError(t, err)
	m3, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/4001/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
	require.NoError(t, err)
	m4, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/4001")
	require.NoError(t, err)

	var tests = []struct {
		name       string
		primary    []ma.Multiaddr
		backup     []ma.Multiaddr
		expected   int
		hasInvalid bool
	}{
		{"no overlap", []ma.Multiaddr{m1}, []ma.Multiaddr{m2}, 2, false},
		{"complete overlap", []ma.Multiaddr{m1}, []ma.Multiaddr{m1}, 1, false},
		{"partial overlap", []ma.Multiaddr{m1, m2}, []ma.Multiaddr{m1, m3}, 3, false},
		{"empty slices", []ma.Multiaddr{}, []ma.Multiaddr{}, 0, false},
		{"nil slices", nil, nil, 0, false},
		{"invalid p2p", []ma.Multiaddr{m1, m4}, []ma.Multiaddr{m2, m4}, 2, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r1 := mergeP2PMultiaddrResolvedAddresses(tt.primary, tt.backup)
			if len(r1) != tt.expected {
				t.Errorf("Expected  %d addresses, got %d", tt.expected, len(r1))
			}

			var info1 []peer.AddrInfo
			var info2 []peer.AddrInfo
			for _, addr := range tt.primary {
				info, err0 := peer.AddrInfoFromP2pAddr(addr)
				if tt.hasInvalid {
					if err0 == nil {
						info1 = append(info1, *info)
					}
				} else {
					require.NoError(t, err0)
					info1 = append(info1, *info)
				}
			}
			for _, addr := range tt.backup {
				info, err0 := peer.AddrInfoFromP2pAddr(addr)
				if tt.hasInvalid {
					if err0 == nil {
						info2 = append(info2, *info)
					}
				} else {
					require.NoError(t, err0)
					info2 = append(info2, *info)
				}
			}
			if info1 == nil && tt.primary != nil {
				info1 = []peer.AddrInfo{}
			}
			if info2 == nil && tt.backup != nil {
				info1 = []peer.AddrInfo{}
			}

			r2 := mergeP2PAddrInfoResolvedAddresses(info1, info2)
			if len(r2) != tt.expected {
				t.Errorf("Expected  %d addresses, got %d", tt.expected, len(r2))
			}
		})
	}
}

// TestP2PwsStreamHandlerDedup checks that the wsStreamHandler detects duplicate connections
// and does not add a new wePeer for it.
func TestP2PwsStreamHandlerDedup(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.DNSBootstrapID = "" // disable DNS lookups since the test uses phonebook addresses
	cfg.NetAddress = "127.0.0.1:0"
	log := logging.TestingLog(t)
	netA, err := NewP2PNetwork(log, cfg, "", nil, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, &identityOpts{tracker: NewIdentityTracker()}, nil)
	require.NoError(t, err)
	err = netA.Start()
	require.NoError(t, err)
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}
	netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, &identityOpts{tracker: NewIdentityTracker()}, nil)
	require.NoError(t, err)

	// now say netA's identity tracker knows about netB's peerID
	var netIdentPeerID algocrypto.PublicKey
	p2pPeerPubKey, err := netB.service.ID().ExtractPublicKey()
	require.NoError(t, err)

	b, err := p2pPeerPubKey.Raw()
	require.NoError(t, err)
	netIdentPeerID = algocrypto.PublicKey(b)
	wsp := &wsPeer{
		identity: netIdentPeerID,
	}
	netA.identityTracker.setIdentity(wsp)
	networkPeerIdentityDisconnectInitial := networkPeerIdentityDisconnect.GetUint64Value()

	// start network and ensure dedup happens
	err = netB.Start()
	require.NoError(t, err)
	defer netB.Stop()

	require.Eventually(t, func() bool {
		return networkPeerIdentityDisconnect.GetUint64Value() > networkPeerIdentityDisconnectInitial
	}, 2*time.Second, 50*time.Millisecond)

	// now allow the peer made outgoing connection to handle conn closing initiated by the other side
	require.Eventually(t, func() bool {
		return !netA.hasPeers() && !netB.hasPeers()
	}, 2*time.Second, 50*time.Millisecond)
}

// TestP2PEnableGossipService_NodeDisable ensures that a node with EnableGossipService=false
// still can participate in the network by sending and receiving messages.
func TestP2PEnableGossipService_NodeDisable(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)

	// prepare configs
	cfg := config.GetDefaultLocal()
	cfg.DNSBootstrapID = "" // disable DNS lookups since the test uses phonebook addresses

	relayCfg := cfg
	relayCfg.NetAddress = "127.0.0.1:0"

	nodeCfg := cfg
	nodeCfg.EnableGossipService = false
	nodeCfg2 := nodeCfg
	nodeCfg2.NetAddress = "127.0.0.1:0"

	tests := []struct {
		name     string
		relayCfg config.Local
		nodeCfg  config.Local
	}{
		{"non-listening-node", relayCfg, nodeCfg},
		{"listening-node", relayCfg, nodeCfg2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			relayCfg := test.relayCfg
			netA, err := NewP2PNetwork(log, relayCfg, "", nil, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
			require.NoError(t, err)
			netA.Start()
			defer netA.Stop()

			peerInfoA := netA.service.AddrInfo()
			addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
			require.NoError(t, err)
			require.NotZero(t, addrsA[0])
			multiAddrStr := addrsA[0].String()
			phoneBookAddresses := []string{multiAddrStr}

			// start netB with gossip service disabled
			nodeCfg := test.nodeCfg
			netB, err := NewP2PNetwork(log, nodeCfg, "", phoneBookAddresses, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
			require.NoError(t, err)
			netB.Start()
			defer netB.Stop()

			require.Eventually(t, func() bool {
				return netA.hasPeers() && netB.hasPeers()
			}, 1*time.Second, 50*time.Millisecond)

			testTag := protocol.AgreementVoteTag

			var handlerCountA atomic.Uint32
			passThroughHandlerA := []TaggedMessageHandler{
				{Tag: testTag, MessageHandler: HandlerFunc(func(msg IncomingMessage) OutgoingMessage {
					handlerCountA.Add(1)
					return OutgoingMessage{Action: Broadcast}
				})},
			}
			var handlerCountB atomic.Uint32
			passThroughHandlerB := []TaggedMessageHandler{
				{Tag: testTag, MessageHandler: HandlerFunc(func(msg IncomingMessage) OutgoingMessage {
					handlerCountB.Add(1)
					return OutgoingMessage{Action: Broadcast}
				})},
			}
			netA.RegisterHandlers(passThroughHandlerA)
			netB.RegisterHandlers(passThroughHandlerB)

			// send messages from both nodes to each other and confirm they are received.
			for i := 0; i < 10; i++ {
				err = netA.Broadcast(context.Background(), testTag, []byte(fmt.Sprintf("hello from A %d", i)), false, nil)
				require.NoError(t, err)
				err = netB.Broadcast(context.Background(), testTag, []byte(fmt.Sprintf("hello from B %d", i)), false, nil)
				require.NoError(t, err)
			}

			require.Eventually(
				t,
				func() bool {
					return handlerCountA.Load() == 10 && handlerCountB.Load() == 10
				},
				2*time.Second,
				50*time.Millisecond,
			)
		})
	}
}

// TestP2PEnableGossipService_BothDisable checks if both relay and node have EnableGossipService=false
// they do not gossip to each other.
//
// Note, this test checks a configuration where node A (relay) does not know about node B,
// and node B is configured to connect to A, and this scenario rejecting logic is guaranteed to work.
func TestP2PEnableGossipService_BothDisable(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)

	// prepare configs
	cfg := config.GetDefaultLocal()
	cfg.DNSBootstrapID = ""         // disable DNS lookups since the test uses phonebook addresses
	cfg.EnableGossipService = false // disable gossip service by default

	relayCfg := cfg
	relayCfg.NetAddress = "127.0.0.1:0"

	var netAConnected atomic.Bool
	var netBConnected atomic.Bool
	notifiee1 := &network.NotifyBundle{
		ConnectedF: func(n network.Network, c network.Conn) {
			netAConnected.Store(true)
		},
	}
	notifiee2 := &network.NotifyBundle{
		ConnectedF: func(n network.Network, c network.Conn) {
			netBConnected.Store(true)
		},
	}

	netA, err := NewP2PNetwork(log.With("net", "netA"), relayCfg, "", nil, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	netA.service.NetworkNotify(notifiee1)
	defer netA.service.NetworkStopNotify(notifiee1)
	netA.Start()
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])
	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}

	nodeCfg := cfg
	nodeCfg.NetAddress = ""

	netB, err := NewP2PNetwork(log.With("net", "netB"), nodeCfg, "", phoneBookAddresses, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	netB.service.NetworkNotify(notifiee2)
	defer netB.service.NetworkStopNotify(notifiee2)
	netB.Start()
	defer netB.Stop()

	require.Eventually(t, func() bool {
		return netAConnected.Load() && netBConnected.Load()
	}, 1*time.Second, 50*time.Millisecond)

	require.False(t, netA.hasPeers())
	require.False(t, netB.hasPeers())
}

// TestP2PTxTopicValidator_NoWsPeer checks txTopicValidator does not call tx handler with empty Sender
func TestP2PTxTopicValidator_NoWsPeer(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)

	// prepare configs
	cfg := config.GetDefaultLocal()
	cfg.DNSBootstrapID = "" // disable DNS lookups since the test uses phonebook addresses

	net, err := NewP2PNetwork(log, cfg, "", nil, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	defer net.Stop()

	peerID := peer.ID("12345678") // must be 8+ in size
	msg := pubsub.Message{Message: &pb.Message{}, ID: string(peerID)}
	validateIncomingTxMessage := func(rawmsg IncomingMessage) OutgoingMessage {
		require.NotEmpty(t, rawmsg.Sender)
		require.Implements(t, (*DisconnectableAddressablePeer)(nil), rawmsg.Sender)
		return OutgoingMessage{Action: Accept}
	}
	net.handler.RegisterValidatorHandlers([]TaggedMessageValidatorHandler{
		{Tag: protocol.TxnTag, MessageHandler: ValidateHandleFunc(validateIncomingTxMessage)},
	})

	ctx := context.Background()
	require.NotContains(t, net.wsPeers, peerID)
	res := net.txTopicValidator(ctx, peerID, &msg)
	require.Equal(t, pubsub.ValidationAccept, res)
}

// TestGetPeersFiltersSelf checks that GetPeers does not return the node's own peer ID.
// The test adds a self peer to the peerstore and another peer to the peerstore and verifies that
// the self peer is not in the returned list.
func TestGetPeersFiltersSelf(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)
	cfg := config.GetDefaultLocal()

	net, err := NewP2PNetwork(log, cfg, t.TempDir(), []string{}, GenesisInfo{"test-genesis", "test-network"}, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	defer net.Stop()
	selfID := net.service.ID()

	// Create and add self
	selfAddr, err := ma.NewMultiaddr("/ip4/127.0.0.1/p2p/" + selfID.String())
	require.NoError(t, err)
	selfInfo := &peer.AddrInfo{
		ID:    selfID,
		Addrs: []multiaddr.Multiaddr{selfAddr},
	}
	net.pstore.AddPersistentPeers([]*peer.AddrInfo{selfInfo}, "test-network", phonebook.RelayRole)

	// Create and add another peer
	otherID, err := peer.Decode("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")
	require.NoError(t, err)
	addr, err := ma.NewMultiaddr("/ip4/127.0.0.1/p2p/" + otherID.String())
	require.NoError(t, err)
	otherInfo := &peer.AddrInfo{
		ID:    otherID,
		Addrs: []multiaddr.Multiaddr{addr},
	}
	net.pstore.AddPersistentPeers([]*peer.AddrInfo{otherInfo}, "test-network", phonebook.RelayRole)

	peers := net.GetPeers(PeersPhonebookRelays)

	// Verify that self peer is not in the returned list
	for _, p := range peers {
		switch peer := p.(type) {
		case *wsPeerCore:
			require.NotEqual(t, selfAddr.String(), peer.GetAddress(), "GetPeers should not return the node's own peer ID")
		default:
			t.Fatalf("unexpected peer type: %T", peer)
		}
	}
}

// TestP2PMetainfoExchange checks that the metainfo exchange works correctly
func TestP2PMetainfoExchange(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.DNSBootstrapID = "" // disable DNS lookups since the test uses phonebook addresses
	cfg.NetAddress = "127.0.0.1:0"
	cfg.EnableVoteCompression = true
	log := logging.TestingLog(t)
	err := log.EnableTelemetryContext(context.Background(), logging.TelemetryConfig{Enable: true, SendToLog: true, GUID: uuid.New()})
	require.NoError(t, err)
	netA, err := NewP2PNetwork(log, cfg, "", nil, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	err = netA.Start()
	require.NoError(t, err)
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	cfg2 := cfg
	cfg2.EnableVoteCompression = false
	cfg.NetAddress = ""
	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}
	netB, err := NewP2PNetwork(log, cfg2, "", phoneBookAddresses, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	err = netB.Start()
	require.NoError(t, err)
	defer netB.Stop()

	require.Eventually(t, func() bool {
		return len(netA.service.Conns()) > 0 && len(netB.service.Conns()) > 0
	}, 2*time.Second, 50*time.Millisecond)

	var peers []Peer
	require.Eventually(t, func() bool {
		peers = netA.GetPeers(PeersConnectedIn)
		return len(peers) > 0
	}, 2*time.Second, 50*time.Millisecond)

	require.Len(t, peers, 1)
	peer := peers[0].(*wsPeer)
	require.True(t, peer.features&pfCompressedProposal != 0)
	require.False(t, peer.vpackVoteCompressionSupported())

	peers = netB.GetPeers(PeersConnectedOut)
	require.Len(t, peers, 1)
	peer = peers[0].(*wsPeer)
	require.True(t, peer.features&pfCompressedProposal != 0)
	require.True(t, peer.vpackVoteCompressionSupported())
}

// TestP2PMetainfoV1vsV22 checks v1 and v22 nodes works together.
// It is done with setting disableV22Protocol=true for the second node,
// and it renders EnableVoteCompression options to have no effect.
func TestP2PMetainfoV1vsV22(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.DNSBootstrapID = "" // disable DNS lookups since the test uses phonebook addresses
	cfg.NetAddress = "127.0.0.1:0"
	cfg.EnableVoteCompression = true
	log := logging.TestingLog(t)
	genesisInfo := GenesisInfo{genesisID, config.Devtestnet}
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	err = netA.Start()
	require.NoError(t, err)
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	cfg2 := cfg
	cfg2.EnableVoteCompression = true
	cfg.NetAddress = ""
	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}
	disableV22Protocol = true
	defer func() {
		disableV22Protocol = false
	}()
	netB, err := NewP2PNetwork(log, cfg2, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	err = netB.Start()
	require.NoError(t, err)
	defer netB.Stop()

	require.Eventually(t, func() bool {
		return len(netA.service.Conns()) > 0 && len(netB.service.Conns()) > 0
	}, 2*time.Second, 50*time.Millisecond)

	var peers []Peer
	require.Eventually(t, func() bool {
		peers = netA.GetPeers(PeersConnectedIn)
		return len(peers) > 0
	}, 2*time.Second, 50*time.Millisecond)
	require.Len(t, peers, 1)
	peer := peers[0].(*wsPeer)
	require.False(t, peer.features&pfCompressedProposal != 0)
	require.False(t, peer.vpackVoteCompressionSupported())

	peers = netB.GetPeers(PeersConnectedOut)
	require.Len(t, peers, 1)
	peer = peers[0].(*wsPeer)
	require.False(t, peer.features&pfCompressedProposal != 0)
	require.False(t, peer.vpackVoteCompressionSupported())
}

// TestP2PVoteCompression tests vote compression feature in P2P network
func TestP2PVoteCompression(t *testing.T) {
	partitiontest.PartitionTest(t)

	type testDef struct {
		netAEnableCompression, netBEnableCompression bool
	}

	var tests []testDef = []testDef{
		{true, true},   // both nodes with compression enabled
		{true, false},  // node A with compression, node B without
		{false, true},  // node A without compression, node B with compression
		{false, false}, // both nodes with compression disabled
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("A_compression_%v+B_compression_%v", test.netAEnableCompression, test.netBEnableCompression), func(t *testing.T) {
			cfg := config.GetDefaultLocal()
			cfg.DNSBootstrapID = "" // disable DNS lookups since the test uses phonebook addresses
			cfg.NetAddress = "127.0.0.1:0"
			cfg.GossipFanout = 1
			cfg.EnableVoteCompression = test.netAEnableCompression
			log := logging.TestingLog(t)
			netA, err := NewP2PNetwork(log.With("name", "netA"), cfg, "", nil, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
			require.NoError(t, err)
			err = netA.Start()
			require.NoError(t, err)
			defer netA.Stop()

			peerInfoA := netA.service.AddrInfo()
			addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
			require.NoError(t, err)
			require.NotZero(t, addrsA[0])

			cfgB := cfg
			cfgB.EnableVoteCompression = test.netBEnableCompression
			cfgB.NetAddress = ""
			multiAddrStr := addrsA[0].String()
			phoneBookAddresses := []string{multiAddrStr}
			netB, err := NewP2PNetwork(log.With("name", "netB"), cfgB, "", phoneBookAddresses, GenesisInfo{genesisID, config.Devtestnet}, &nopeNodeInfo{}, nil, nil)
			require.NoError(t, err)
			err = netB.Start()
			require.NoError(t, err)
			defer netB.Stop()

			// ps is empty, so this is a valid vote
			vote1 := map[string]any{
				"cred": map[string]any{"pf": algocrypto.VrfProof{1}},
				"r":    map[string]any{"rnd": uint64(2), "snd": [32]byte{3}},
				"sig": map[string]any{
					"p": [32]byte{4}, "p1s": [64]byte{5}, "p2": [32]byte{6},
					"p2s": [64]byte{7}, "ps": [64]byte{}, "s": [64]byte{9},
				},
			}
			// ps is not empty: vpack compression will fail, but it will still be sent through
			vote2 := map[string]any{
				"cred": map[string]any{"pf": algocrypto.VrfProof{10}},
				"r":    map[string]any{"rnd": uint64(11), "snd": [32]byte{12}},
				"sig": map[string]any{
					"p": [32]byte{13}, "p1s": [64]byte{14}, "p2": [32]byte{15},
					"p2s": [64]byte{16}, "ps": [64]byte{17}, "s": [64]byte{18},
				},
			}
			// Send a totally invalid message to ensure that it goes through. Even though vpack compression
			// and decompression will fail, the message should still go through (as an intended fallback).
			vote3 := []byte("hello")
			messages := [][]byte{protocol.EncodeReflect(vote1), protocol.EncodeReflect(vote2), vote3}
			matcher := newMessageMatcher(t, messages)
			counterDone := matcher.done
			netB.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.AgreementVoteTag, MessageHandler: matcher}})

			// Wait for peers to connect
			require.Eventually(t, func() bool {
				return len(netA.service.Conns()) > 0 && len(netB.service.Conns()) > 0
			}, 2*time.Second, 50*time.Millisecond)

			for _, msg := range messages {
				netA.Broadcast(context.Background(), protocol.AgreementVoteTag, msg, true, nil)
			}

			select {
			case <-counterDone:
			case <-time.After(2 * time.Second):
				t.Errorf("timeout, count=%d, wanted %d", len(matcher.received), len(messages))
			}

			require.True(t, matcher.Match())

			// Verify compression feature is correctly reflected in peer properties
			// Check peers have the correct compression capability
			peers := netA.GetPeers(PeersConnectedIn)
			require.Len(t, peers, 1)
			peer := peers[0].(*wsPeer)
			require.Equal(t, test.netBEnableCompression, peer.vpackVoteCompressionSupported())

			peers = netB.GetPeers(PeersConnectedOut)
			require.Len(t, peers, 1)
			peer = peers[0].(*wsPeer)
			require.Equal(t, test.netAEnableCompression, peer.vpackVoteCompressionSupported())
		})
	}
}
