// Copyright (C) 2019-2022 Algorand, Inc.
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
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestLatencyTracker(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestFilterWebsocketNode(t, "a")
	netA.config.GossipFanout = 1
	netA.config.PeerPingPeriodSeconds = 2
	netA.Start()
	defer func() { t.Log("stopping A"); netA.Stop(); t.Log("A done") }()

	netB := makeTestFilterWebsocketNode(t, "b")
	netB.config.GossipFanout = 1
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", PhoneBookEntryRelayRole)

	netB.Start()
	defer func() { t.Log("stopping B"); netB.Stop(); t.Log("B done") }()
	counter := &messageCounterHandler{t: t, limit: 1, done: make(chan struct{})}
	netB.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.AgreementVoteTag, MessageHandler: counter}})
	debugTag2 := protocol.ProposalPayloadTag
	counter2 := &messageCounterHandler{t: t, limit: 1, done: make(chan struct{})}
	netB.RegisterHandlers([]TaggedMessageHandler{{Tag: debugTag2, MessageHandler: counter2}})

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	msg := make([]byte, 200)
	rand.Read(msg)
	var lastMsgTime time.Time

	var connLatencyInitialA time.Duration
	// wait for up to 20 seconds for the network latency to be established.
	startTime := time.Now()
	for {
		if time.Since(lastMsgTime) > 100*time.Millisecond {
			netA.Broadcast(context.Background(), protocol.AgreementVoteTag, msg, true, nil)
			lastMsgTime = time.Now()
		}

		connLatencyA := netA.peers[0].GetConnectionLatency()
		if connLatencyA == time.Duration(0) {
			require.LessOrEqual(t, time.Since(startTime).Nanoseconds(), (20 * time.Second).Nanoseconds())
			time.Sleep(time.Millisecond)
			continue
		}
		require.LessOrEqual(t, connLatencyA.Nanoseconds(), (20 * time.Second).Nanoseconds())
		connLatencyInitialA = connLatencyA
		break
	}

	// wait for up to 20 seconds for the network latency to be established.
	startTime = time.Now()
	lastMsgTime = time.Time{}
	for {
		if time.Since(lastMsgTime) > 100*time.Millisecond {
			netB.Broadcast(context.Background(), protocol.AgreementVoteTag, msg, true, nil)
			lastMsgTime = time.Now()
		}

		connLatencyB := netB.peers[0].GetConnectionLatency()
		if connLatencyB == time.Duration(0) {
			require.LessOrEqual(t, time.Since(startTime).Nanoseconds(), (20 * time.Second).Nanoseconds())
			time.Sleep(time.Millisecond)
			continue
		}
		require.LessOrEqual(t, connLatencyB.Nanoseconds(), (20 * time.Second).Nanoseconds())
		break
	}

	// send the given message until we get a different latency.
	// wait for up to 20 seconds for the network latency to be established.
	startTime = time.Now()
	lastMsgTime = time.Time{}
	for {
		if time.Since(lastMsgTime) > 100*time.Millisecond {
			netA.Broadcast(context.Background(), protocol.AgreementVoteTag, msg, true, nil)
			lastMsgTime = time.Now()
		}

		connLatencyA := netA.peers[0].GetConnectionLatency()
		if connLatencyA != connLatencyInitialA {
			require.NotEqual(t, connLatencyA.Nanoseconds(), int64(0))
			waitTime := time.Since(lastMsgTime)
			require.Less(t, waitTime.Seconds(), float64(netA.config.PeerPingPeriodSeconds*2))
			break
		}
		time.Sleep(time.Millisecond)
	}
}
