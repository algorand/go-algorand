// Copyright (C) 2019-2023 Algorand, Inc.
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
	peerstore "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestP2PSubmitTX(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	log := logging.TestingLog(t)
	netA, err := NewP2PNetwork(log, cfg, "", nil, genesisID, config.Devtestnet)
	require.NoError(t, err)
	hostA := netA.service.Host()

	peerInfoA := peerstore.AddrInfo{
		ID:    hostA.ID(),
		Addrs: hostA.Addrs(),
	}
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
			return len(netA.service.ListPeers(p2p.TXTopicName)) == 2 && len(netB.service.ListPeers(p2p.TXTopicName)) == 1 && len(netC.service.ListPeers(p2p.TXTopicName)) == 1
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
			netCpeerStatsA, ok := netC.peerStats[netA.service.Host().ID()]
			netC.peerStatsMu.Unlock()
			if !ok {
				return false
			}
			return atomic.LoadUint64(&netCpeerStatsA.txReceived) == 10
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
	hostA := netA.service.Host()

	peerInfoA := peerstore.AddrInfo{
		ID:    hostA.ID(),
		Addrs: hostA.Addrs(),
	}
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
			return len(netA.service.ListPeers(p2p.TXTopicName)) == 2 && len(netB.service.ListPeers(p2p.TXTopicName)) == 1 && len(netC.service.ListPeers(p2p.TXTopicName)) == 1
		},
		2*time.Second,
		50*time.Millisecond,
	)
	time.Sleep(time.Second) // XX give time for peers to connect. Knowing about them being subscribed to topics is clearly not enough
	// now we should be connected in a line: B <-> A <-> C where both B and C are connected to A but not each other

	testTag := protocol.AgreementVoteTag
	var handlerCount uint32

	// Since we aren't using the transaction handler in this test, we need to register a pass-through handler
	passThroughHandler := []TaggedMessageHandler{
		{Tag: testTag, MessageHandler: HandlerFunc(func(msg IncomingMessage) OutgoingMessage {
			atomic.AddUint32(&handlerCount, 1)
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
			return atomic.LoadUint32(&handlerCount) == 20
		},
		1*time.Second,
		50*time.Millisecond,
	)
}
