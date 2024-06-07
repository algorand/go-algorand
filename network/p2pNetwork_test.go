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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/limitcaller"
	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/network/p2p/dnsaddr"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
	"github.com/algorand/go-algorand/network/phonebook"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func (n *P2PNetwork) hasPeers() bool {
	n.wsPeersLock.RLock()
	defer n.wsPeersLock.RUnlock()
	return len(n.wsPeers) > 0
}

func TestP2PSubmitTX(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.ForceFetchTransactions = true
	log := logging.TestingLog(t)
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet, &nopeNodeInfo{})
	require.NoError(t, err)
	netA.Start()
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}
	netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet, &nopeNodeInfo{})
	require.NoError(t, err)
	netB.Start()
	defer netB.Stop()

	netC, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet, &nopeNodeInfo{})
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
	}, 2*time.Second, 50*time.Millisecond)

	// for some reason the above check is not enough in race builds on CI
	time.Sleep(time.Second) // give time for peers to connect.

	// now we should be connected in a line: B <-> A <-> C where both B and C are connected to A but not each other

	// Since we aren't using the transaction handler in this test, we need to register a pass-through handler
	passThroughHandler := []TaggedMessageProcessor{
		{
			Tag: protocol.TxnTag,
			MessageProcessor: struct {
				ProcessorValidateFunc
				ProcessorHandleFunc
			}{
				ProcessorValidateFunc(func(msg IncomingMessage) ValidatedMessage {
					return ValidatedMessage{Action: Accept, Tag: msg.Tag, ValidatorData: nil}
				}),
				ProcessorHandleFunc(func(msg ValidatedMessage) OutgoingMessage {
					return OutgoingMessage{Action: Ignore}
				}),
			},
		},
	}

	netA.RegisterProcessors(passThroughHandler)
	netB.RegisterProcessors(passThroughHandler)
	netC.RegisterProcessors(passThroughHandler)

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
	log := logging.TestingLog(t)
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet, &nopeNodeInfo{})
	require.NoError(t, err)
	netA.Start()
	defer netA.Stop()

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])

	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}
	netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet, &nopeNodeInfo{})
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
	netC, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet, &nopeNodeInfo{})
	require.NoError(t, err)
	netC.Start()
	defer netC.Stop()

	require.Eventually(t, func() bool {
		return netA.hasPeers() && netB.hasPeers() && netC.hasPeers()
	}, 2*time.Second, 50*time.Millisecond)

	time.Sleep(time.Second) // give time for peers to connect.

	// ensure netC cannot receive messages

	passThroughHandler := []TaggedMessageProcessor{
		{
			Tag: protocol.TxnTag,
			MessageProcessor: struct {
				ProcessorValidateFunc
				ProcessorHandleFunc
			}{
				ProcessorValidateFunc(func(msg IncomingMessage) ValidatedMessage {
					return ValidatedMessage{Action: Accept, Tag: msg.Tag, ValidatorData: nil}
				}),
				ProcessorHandleFunc(func(msg ValidatedMessage) OutgoingMessage {
					return OutgoingMessage{Action: Ignore}
				}),
			},
		},
	}

	netB.RegisterProcessors(passThroughHandler)
	netC.RegisterProcessors(passThroughHandler)
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
	log := logging.TestingLog(t)
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet, &nopeNodeInfo{})
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
	netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet, &nopeNodeInfo{})
	require.NoError(t, err)
	err = netB.Start()
	require.NoError(t, err)
	defer netB.Stop()

	netC, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet, &nopeNodeInfo{})
	require.NoError(t, err)
	err = netC.Start()
	require.NoError(t, err)
	defer netC.Stop()

	require.Eventually(t, func() bool {
		return netA.hasPeers() && netB.hasPeers() && netC.hasPeers()
	}, 2*time.Second, 50*time.Millisecond)

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

func (s *mockService) DialNode(ctx context.Context, peer *peer.AddrInfo) error {
	s.peers[peer.ID] = *peer
	return nil
}

func (s *mockService) DialPeersUntilTargetCount(targetConnCount int) {
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

func (s *mockService) GetStream(peer.ID) (network.Stream, bool) {
	return nil, false
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
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet, &nopeNodeInfo{})
	defer netA.Stop()
	require.NoError(t, err)
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

func TestP2PdnsLookupBootstrapPeersFailure(t *testing.T) {
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
	cfg.EnableDHTProviders = true
	log := logging.TestingLog(t)

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
			netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet, test.nis[0])
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
			netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet, test.nis[1])
			require.NoError(t, err)
			err = netB.Start()
			require.NoError(t, err)
			defer netB.Stop()

			netC, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet, test.nis[2])
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
					// it appears there are artifical peers because of listening on localhost and on a real network interface
					// so filter out and save only unique peers by their IDs
					net := nets[idx]
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
		c := h.net.GetHTTPRequestConnection(r)
		require.NotNil(h.tb, c)
	}
}

func TestP2PHTTPHandler(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	cfg := config.GetDefaultLocal()
	cfg.EnableDHTProviders = true
	cfg.GossipFanout = 1
	log := logging.TestingLog(t)

	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet, &nopeNodeInfo{})
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

	httpClient, err := p2p.MakeHTTPClient(&peerInfoA)
	require.NoError(t, err)
	resp, err := httpClient.Get("/test")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(body))

	// check another endpoint that also access the underlying connection/stream
	httpClient, err = p2p.MakeHTTPClient(&peerInfoA)
	require.NoError(t, err)
	resp, err = httpClient.Get("/check-conn")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "world", string(body))

	// check rate limiting client:
	// zero clients allowed, rate limiting window (10s) is greater than queue deadline (1s)
	pstore, err := peerstore.MakePhonebook(0, 10*time.Second)
	require.NoError(t, err)
	pstore.AddPersistentPeers([]interface{}{&peerInfoA}, "net", phonebook.PhoneBookEntryRelayRole)
	httpClient, err = p2p.MakeHTTPClientWithRateLimit(&peerInfoA, pstore, 1*time.Second, 1)
	require.NoError(t, err)
	_, err = httpClient.Get("/test")
	require.ErrorIs(t, err, limitcaller.ErrConnectionQueueingTimeout)
}

func TestP2PRelay(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.ForceFetchTransactions = true
	log := logging.TestingLog(t)
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet, &nopeNodeInfo{})
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

	netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet, &nopeNodeInfo{})
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

	makeCounterHandler := func(numExpected int) ([]TaggedMessageProcessor, *int, chan struct{}) {
		numActual := 0
		counterDone := make(chan struct{})
		counterHandler := []TaggedMessageProcessor{
			{
				Tag: protocol.TxnTag,
				MessageProcessor: struct {
					ProcessorValidateFunc
					ProcessorHandleFunc
				}{
					ProcessorValidateFunc(func(msg IncomingMessage) ValidatedMessage {
						return ValidatedMessage{Action: Accept, Tag: msg.Tag, ValidatorData: nil}
					}),
					ProcessorHandleFunc(func(msg ValidatedMessage) OutgoingMessage {
						numActual++
						if numActual >= numExpected {
							close(counterDone)
						}
						return OutgoingMessage{Action: Ignore}
					}),
				},
			},
		}
		return counterHandler, &numActual, counterDone
	}
	counterHandler, _, counterDone := makeCounterHandler(1)
	netA.RegisterProcessors(counterHandler)

	// send 5 messages from both netB to netA
	// since there is no node with listening address set => no messages should be received
	for i := 0; i < 5; i++ {
		err := netB.Relay(context.Background(), protocol.TxnTag, []byte{1, 2, 3, byte(i)}, true, nil)
		require.NoError(t, err)
	}

	select {
	case <-counterDone:
		require.Fail(t, "No messages should have been received")
	case <-time.After(1 * time.Second):
	}

	// add netC with listening address set, and enable relaying on netB
	// ensure all messages are received by netA
	cfg.NetAddress = "127.0.0.1:0"
	netC, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet, &nopeNodeInfo{})
	require.NoError(t, err)
	err = netC.Start()
	require.NoError(t, err)
	defer netC.Stop()

	netB.relayMessages = true

	require.Eventually(
		t,
		func() bool {
			return len(netA.service.ListPeersForTopic(p2p.TXTopicName)) > 0 &&
				len(netB.service.ListPeersForTopic(p2p.TXTopicName)) > 0 &&
				len(netC.service.ListPeersForTopic(p2p.TXTopicName)) > 0
		},
		2*time.Second,
		50*time.Millisecond,
	)

	require.Eventually(t, func() bool {
		return netA.hasPeers() && netB.hasPeers() && netC.hasPeers()
	}, 2*time.Second, 50*time.Millisecond)

	const expectedMsgs = 10
	counterHandler, count, counterDone := makeCounterHandler(expectedMsgs)
	netA.ClearProcessors()
	netA.RegisterProcessors(counterHandler)

	for i := 0; i < expectedMsgs/2; i++ {
		err := netB.Relay(context.Background(), protocol.TxnTag, []byte{1, 2, 3, byte(i)}, true, nil)
		require.NoError(t, err)
		err = netC.Relay(context.Background(), protocol.TxnTag, []byte{11, 12, 10 + byte(i), 14}, true, nil)
		require.NoError(t, err)
	}
	// send some duplicate messages, they should be dropped
	for i := 0; i < expectedMsgs/2; i++ {
		err := netB.Relay(context.Background(), protocol.TxnTag, []byte{1, 2, 3, byte(i)}, true, nil)
		require.NoError(t, err)
	}

	select {
	case <-counterDone:
	case <-time.After(2 * time.Second):
		if *count < expectedMsgs {
			require.Failf(t, "One or more messages failed to reach destination network", "%d > %d", expectedMsgs, *count)
		} else if *count > expectedMsgs {
			require.Failf(t, "One or more messages that were expected to be dropped, reached destination network", "%d < %d", expectedMsgs, *count)
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
		service:  mockService,
		log:      logging.TestingLog(t),
		ctx:      ctx,
		nodeInfo: &nopeNodeInfo{},
	}

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

func TestMergeP2PAddrInfoResolvedAddresses(t *testing.T) {
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

// TestP2PGossipSubPeerCasts checks that gossipSubPeer implements the ErlClient and IPAddressable interfaces
// needed by TxHandler
func TestP2PGossipSubPeerCasts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var g interface{} = gossipSubPeer{}
	_, ok := g.(util.ErlClient)
	require.True(t, ok)

	_, ok = g.(IPAddressable)
	require.True(t, ok)

	// check that gossipSubPeer is hashable as ERL wants
	var m map[util.ErlClient]struct{}
	require.Equal(t, m[gossipSubPeer{}], struct{}{})
	require.Equal(t, m[g.(util.ErlClient)], struct{}{})
}
