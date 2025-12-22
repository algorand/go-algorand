// Copyright (C) 2019-2026 Algorand, Inc.
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
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func makeMsgPool(N int, peers []Peer) (out []IncomingMessage) {
	// preallocate enough.
	out = make([]IncomingMessage, 0, N*2)
	msgIndex := uint64(0)
	timer := int64(0)
	msgPerSecond := uint64(500)
	msgInterval := int64(time.Second) / int64(msgPerSecond)
	for {
		if len(out) >= N {
			break
		}

		msgData := crypto.Hash([]byte{byte(msgIndex & 0xff), byte((msgIndex >> 8) & 0xff), byte((msgIndex >> 16) & 0xff), byte((msgIndex >> 24) & 0xff)})
		msg := IncomingMessage{
			Tag:  protocol.AgreementVoteTag,
			Data: msgData[:],
		}

		addMsg := func(msgCount int) {
			for i := 0; i < msgCount; i++ {
				msg.Sender = peers[(int(msgIndex)+i)%len(peers)].(DisconnectableAddressablePeer)
				timer += int64(7 * time.Nanosecond)
				msg.Received = timer
				out = append(out, msg)
			}
		}
		switch {
		case (msgIndex % 10) == 0: // 10% of the messages comes from a single source
			addMsg(1)
		case (msgIndex%10) == 1 || (msgIndex%10) == 2: // 20% of the messages comes from two sources
			addMsg(2)
		case (msgIndex%10) == 3 || (msgIndex%10) == 4: // 20% of the messages comes from three sources
			addMsg(3)
		default: // 50% of the messages comes from all sources
			addMsg(len(peers))
		}

		msgIndex++
		if msgIndex%msgPerSecond == 0 {
			timer += int64(time.Second * 3)
		}
		timer += msgInterval + int64(123*time.Nanosecond)
	}
	return
}

func BenchmarkConnMonitor(b *testing.B) {
	peers := []Peer{&wsPeer{}, &wsPeer{}, &wsPeer{}, &wsPeer{}}
	msgPool := makeMsgPool(b.N, peers)

	b.ResetTimer()
	startTestTime := time.Now().UnixNano()
	perfMonitor := makeConnectionPerformanceMonitor([]Tag{protocol.AgreementVoteTag})
	perfMonitor.Reset(peers)
	for _, msg := range msgPool {
		msg.Received += startTestTime
		perfMonitor.Notify(&msg)
		if perfMonitor.GetPeersStatistics() != nil {
			perfMonitor.Reset(peers)
			startTestTime = time.Now().UnixNano()
		}
	}
}

func TestConnMonitor_StageTiming(t *testing.T) {
	partitiontest.PartitionTest(t)

	peers := []Peer{&wsPeer{}, &wsPeer{}, &wsPeer{}, &wsPeer{}}
	msgPool := makeMsgPool(60000, peers)

	stageTimings := make([]time.Duration, 5)
	stageNotifyCalls := make([]int, 5)
	startTestTime := time.Now().UnixNano()
	perfMonitor := makeConnectionPerformanceMonitor([]Tag{protocol.AgreementVoteTag})
	// measure measuring overhead.
	measuringOverhead := time.Since(time.Now())
	perfMonitor.Reset(peers)
	for msgIdx, msg := range msgPool {
		msg.Received += startTestTime
		beforeNotify := time.Now()
		beforeNotifyStage := perfMonitor.stage
		perfMonitor.Notify(&msg)
		notifyTime := time.Since(beforeNotify)
		stageTimings[beforeNotifyStage] += notifyTime
		stageNotifyCalls[beforeNotifyStage]++
		if perfMonitor.GetPeersStatistics() != nil {
			fmt.Printf("TestConnMonitorStageTiming is done after going over %d messages\n", msgIdx)
			break
		}
	}
	for i := 0; i < len(stageTimings); i++ {
		if stageNotifyCalls[i] == 0 {
			continue
		}
		fmt.Printf("ConnectionPerformanceMonitor stage %d had %d calls with avarage of %dns and total of %dns\n",
			i,
			stageNotifyCalls[i],
			int64(stageTimings[i])/int64(stageNotifyCalls[i])-int64(measuringOverhead),
			stageTimings[i])
	}

}
func TestConnMonitor_BucketsPruning(t *testing.T) {
	partitiontest.PartitionTest(t)

	bucketsCount := 100
	curTime := time.Now().UnixNano()
	for i := 0; i < bucketsCount; i++ {
		perfMonitor := makeConnectionPerformanceMonitor([]Tag{protocol.AgreementVoteTag})
		// create bucketsCount buckets, where i of them are before the "current" time stamp and bucketsCount-i are after the time stamp.
		for j := 0; j < bucketsCount; j++ {
			if j < i {
				perfMonitor.pendingMessagesBuckets = append(perfMonitor.pendingMessagesBuckets, &pmPendingMessageBucket{endTime: curTime - 1})
			} else {
				perfMonitor.pendingMessagesBuckets = append(perfMonitor.pendingMessagesBuckets, &pmPendingMessageBucket{endTime: curTime + 1})
			}
		}
		perfMonitor.pruneOldMessages(curTime + int64(pmMaxMessageWaitTime))
		require.Equal(t, bucketsCount-i, len(perfMonitor.pendingMessagesBuckets))
	}

	for i := 0; i < bucketsCount; i++ {
		perfMonitor := makeConnectionPerformanceMonitor([]Tag{protocol.AgreementVoteTag})

		for j := 0; j < bucketsCount; j++ {
			perfMonitor.pendingMessagesBuckets = append(perfMonitor.pendingMessagesBuckets, &pmPendingMessageBucket{endTime: curTime + int64(j)})
		}

		perfMonitor.pruneOldMessages(curTime + int64(pmMaxMessageWaitTime) + int64(i-1))
		require.Equal(t, bucketsCount-i, len(perfMonitor.pendingMessagesBuckets))
	}
}

type mockOutgoingNet struct {
	peers            []Peer
	pending          int
	disconnectedPeer Peer
	disconnectReason disconnectReason
	advanceCalled    bool
}

func (m *mockOutgoingNet) outgoingPeers() (peers []Peer) { return m.peers }
func (m *mockOutgoingNet) numOutgoingPending() int       { return m.pending }
func (m *mockOutgoingNet) disconnect(badnode Peer, reason disconnectReason) {
	m.disconnectedPeer = badnode
	m.disconnectReason = reason
}
func (m *mockOutgoingNet) OnNetworkAdvance() { m.advanceCalled = true }

func TestConnMonitor_CheckExistingConnections_ThrottledPeers(t *testing.T) {
	partitiontest.PartitionTest(t)
	mon := makeConnectionPerformanceMonitor(nil)

	p1 := &wsPeer{throttledOutgoingConnection: true}
	mockNet := &mockOutgoingNet{peers: []Peer{p1}}
	cc := makeOutgoingConnsCloser(logging.TestingLog(t), mockNet, mon, 100*time.Second)

	res := cc.checkExistingConnectionsNeedDisconnecting(2)
	require.False(t, res)
	require.Nil(t, mockNet.disconnectedPeer)

	p2 := &wsPeer{throttledOutgoingConnection: false} // not throttled
	mockNet = &mockOutgoingNet{peers: []Peer{p1, p2}}
	cc = makeOutgoingConnsCloser(logging.TestingLog(t), mockNet, mon, 100*time.Second)

	mon.Reset(mockNet.peers)
	mon.stage = pmStageStopped
	mon.connectionDelay = map[Peer]int64{p1: 20, p2: 10}
	mon.firstMessageCount = map[Peer]int64{p1: 1, p2: 2}
	mon.msgCount = 3

	res = cc.checkExistingConnectionsNeedDisconnecting(2)
	require.True(t, res, "expected disconnect")
	require.Equal(t, p1, mockNet.disconnectedPeer)
	require.Equal(t, disconnectLeastPerformingPeer, mockNet.disconnectReason)
}

func TestConnMonitor_CheckExistingConnections_NoThrottledPeers(t *testing.T) {
	partitiontest.PartitionTest(t)
	mon := makeConnectionPerformanceMonitor(nil)
	p1 := &wsPeer{throttledOutgoingConnection: false}
	p2 := &wsPeer{throttledOutgoingConnection: false}
	mockNet := &mockOutgoingNet{peers: []Peer{p1, p2}}
	cc := makeOutgoingConnsCloser(logging.TestingLog(t), mockNet, mon, 0)
	mon.Reset(mockNet.peers)
	mon.stage = pmStageStopped
	mon.connectionDelay = map[Peer]int64{p1: 5, p2: 6}
	mon.firstMessageCount = map[Peer]int64{p1: 1, p2: 1}
	mon.msgCount = 2

	res := cc.checkExistingConnectionsNeedDisconnecting(2)
	require.True(t, res)
	require.NotNil(t, mockNet.disconnectedPeer)
	require.NotEqual(t, disconnectLeastPerformingPeer, mockNet.disconnectReason)
}

func TestNetworkAdvanceMonitor(t *testing.T) {
	partitiontest.PartitionTest(t)
	m := makeNetworkAdvanceMonitor()

	require.True(t, m.lastAdvancedWithin(500*time.Millisecond))

	m.mu.Lock()
	m.lastNetworkAdvance = time.Now().Add(-2 * time.Second)
	m.mu.Unlock()
	require.False(t, m.lastAdvancedWithin(500*time.Millisecond), "expected false after stale interval")

	// update and verify within again
	m.updateLastAdvance()
	require.True(t, m.lastAdvancedWithin(500*time.Millisecond))
}

// shuffleNormal reorders elements by assigning each element a priority based on
// normal distribution centered at its original index, then sorting by priority.
// The stddevFactor controls how much elements can move from their original position:
// - smaller values (e.g., 0.1) keep elements closer to original positions
// - larger values (e.g., 1.0) allow more mixing
// - very large values approach uniform distribution behavior
func shuffleNormal[T any](slice []T, stddevFactor float64) {
	n := len(slice)
	if n <= 1 {
		return
	}

	// Each element gets a priority = originalIndex + normalRandom * stddev
	// where stddev = stddevFactor * n
	stddev := stddevFactor * float64(n)

	type indexedItem struct {
		original int
		priority float64
		item     T
	}

	items := make([]indexedItem, n)
	for i := range slice {
		items[i] = indexedItem{
			original: i,
			priority: float64(i) + rand.NormFloat64()*stddev,
			item:     slice[i],
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].priority < items[j].priority
	})

	for i := range slice {
		slice[i] = items[i].item
	}
}

func shuffleUniform[T any](slice []T) {
	rand.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})
}

func TestConnMonitor_Simulate(t *testing.T) {
	partitiontest.PartitionTest(t)

	// t.Skip("Use locally for conn perf logic adjustment as needed")

	const (
		numNoDupPeers   = 2 // peers that provide only unique msgs
		numDupPeers     = 3 // peers that provide duplicate msgs
		numDupPlusPeers = 3 // peers that provide "smart" duplicate msgs (like txn with changed note field)
		dupRatio        = 2 // each duplicate peer sends this many duplicates per message
		smartDupRatio   = 3 // each "smart" duplicate peer sends this many duplicates per message (including the original)
	)
	const numMsgsPerTick = 1*numNoDupPeers + (numDupPeers * dupRatio) + (numDupPlusPeers * smartDupRatio)

	msgs := make([]IncomingMessage, numMsgsPerTick)
	data := make([][]byte, numMsgsPerTick)
	for i := range numMsgsPerTick {
		data[i] = make([]byte, 10) // each msg data, 8 bytes for uint64 + 2 bytes for randomness
	}

	senders := make([]*wsPeer, numNoDupPeers+numDupPeers+numDupPlusPeers)
	for i := range numNoDupPeers {
		senders[i] = &wsPeer{wsPeerCore: wsPeerCore{rootURL: fmt.Sprintf("noDupPeer%d", i+1)}}
	}
	for i := range numDupPeers {
		senders[numNoDupPeers+i] = &wsPeer{wsPeerCore: wsPeerCore{rootURL: fmt.Sprintf("dupPeer%d", i+1)}}
	}
	for i := range numDupPlusPeers {
		senders[numNoDupPeers+numDupPeers+i] = &wsPeer{wsPeerCore: wsPeerCore{rootURL: fmt.Sprintf("dupPlusPeer%d", i+1)}}
	}

	nextTickMsgs := func(tick uint64, shuffleFn func([]IncomingMessage)) []IncomingMessage {
		for i := range data {
			binary.LittleEndian.PutUint64(data[i], tick)
		}

		// noDup peers
		for i := range numNoDupPeers {
			msgs[i] = IncomingMessage{
				Tag:    protocol.TxnTag,
				Data:   data[i],
				Sender: senders[i],
			}
		}

		// dup peers
		for i := range numDupPeers {
			for j := 0; j < dupRatio; j++ {
				msgs[numNoDupPeers+i*dupRatio+j] = IncomingMessage{
					Tag:    protocol.TxnTag,
					Data:   data[numNoDupPeers+i],
					Sender: senders[numNoDupPeers+i],
				}
			}
		}

		// "smart" dup peers
		for i := range numDupPlusPeers {
			for j := 0; j < smartDupRatio; j++ {
				// change last byte to make data different
				idx := numNoDupPeers + numDupPeers*dupRatio + i*smartDupRatio + j
				data[idx][9] = byte(j)

				msgs[idx] = IncomingMessage{
					Tag:    protocol.TxnTag,
					Data:   data[idx],
					Sender: senders[numNoDupPeers+numDupPeers+i],
				}
			}
		}

		// for i := range msgs {
		// 	t.Logf("tick %d: msg from %s data=%x\n", tick, msgs[i].Sender.(*wsPeer).rootURL, msgs[i].Data)
		// }

		// shuffle to simulate different receiving orders
		shuffleFn(msgs)

		now := time.Now().UnixNano()
		for i := range msgs {
			msgs[i].Received = now + int64(i*10)
		}
		return msgs
	}

	tests := []struct {
		name      string
		shuffleFn func([]IncomingMessage)
	}{
		{
			name:      "normalShuffle",
			shuffleFn: func(msgs []IncomingMessage) { shuffleNormal(msgs, 0.5) },
		},
		{
			name:      "uniformShuffle",
			shuffleFn: shuffleUniform[IncomingMessage],
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			mon := makeConnectionPerformanceMonitor([]Tag{protocol.TxnTag})
			peers := make([]Peer, len(senders))
			for i := range senders {
				peers[i] = senders[i]
			}
			mon.Reset(peers)

			i := uint64(0)
			prevStage := -1
			for mon.stage != pmStageStopped {
				if int(mon.stage) != prevStage {
					t.Logf("Monitor advanced to stage %d at tick %d\n", mon.stage, i)
					prevStage = int(mon.stage)
				}
				msgs := nextTickMsgs(i, test.shuffleFn)
				for _, msg := range msgs {
					mon.Notify(&msg)
				}
				i++
			}

			// at the very end get stats
			stats := mon.GetPeersStatistics()
			t.Logf("%s:  %d messages over %d ticks\n", test.name, mon.msgCount, i)
			for _, ps := range stats.peerStatistics {
				t.Logf("%s: delay=%d firstMessagePercentage=%.2f\n", ps.peer.(*wsPeer).rootURL, ps.peerDelay, ps.peerFirstMessage)
			}
		})
	}
}
