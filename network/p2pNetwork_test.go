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
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	peerstore "github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestP2PSubmitTX(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	log := logging.TestingLog(t)
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet)
	require.NoError(t, err)
	peerInfoA := netA.service.AddrInfo()

	addrsA, err := peerstore.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])
	netA.Start()
	defer netA.Stop()

	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}
	netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet)
	require.NoError(t, err)
	netB.Start()
	defer netB.Stop()

	netC, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet)

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
	time.Sleep(time.Second) // give time for peers to connect.
	// now we should be connected in a line: B <-> A <-> C where both B and C are connected to A but not each other

	// Since we aren't using the transaction handler in this test, we need to register a pass-through handler
	passThroughHandler := []TaggedMessageHandler{
		{Tag: protocol.TxnTag, MessageHandler: HandlerFunc(func(msg IncomingMessage) OutgoingMessage {
			return OutgoingMessage{Action: Broadcast}
		})},
	}

	netA.RegisterHandlers(passThroughHandler)
	netB.RegisterHandlers(passThroughHandler)
	netC.RegisterHandlers(passThroughHandler)

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

func TestP2PSubmitWS(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	log := logging.TestingLog(t)
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet)
	require.NoError(t, err)

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peerstore.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotZero(t, addrsA[0])
	netA.Start()
	defer netA.Stop()

	multiAddrStr := addrsA[0].String()
	phoneBookAddresses := []string{multiAddrStr}
	netB, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet)
	require.NoError(t, err)
	netB.Start()
	defer netB.Stop()

	netC, err := NewP2PNetwork(log, cfg, "", phoneBookAddresses, genesisID, config.Devtestnet)

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
	time.Sleep(time.Second) // XX give time for peers to connect. Knowing about them being subscribed to topics is clearly not enough
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

func (s *mockService) Close() error {
	return nil
}

func (s *mockService) ID() peer.ID {
	return s.id
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
	if _, ok := s.peers[peer]; ok {
		delete(s.peers, peer)
	}
	return nil
}

func (s *mockService) Conns() []network.Conn {
	return nil
}

func (s *mockService) ListPeersForTopic(topic string) []peer.ID {
	return nil
}

func (s *mockService) Subscribe(topic string, val pubsub.ValidatorEx) (*pubsub.Subscription, error) {
	return nil, nil
}
func (s *mockService) Publish(ctx context.Context, topic string, data []byte) error {
	return nil
}

func (s *mockService) setAddrs(addrs []ma.Multiaddr) {
	s.addrs = addrs
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
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet)
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
