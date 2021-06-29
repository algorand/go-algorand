// Copyright (C) 2019-2021 Algorand, Inc.
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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testPartitioning"
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
				msg.Sender = peers[(int(msgIndex)+i)%len(peers)]
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

func TestConnMonitorStageTiming(t *testing.T) {
	testPartitioning.PartitionTest(t)

	peers := []Peer{&wsPeer{}, &wsPeer{}, &wsPeer{}, &wsPeer{}}
	msgPool := makeMsgPool(60000, peers)

	stageTimings := make([]time.Duration, 5)
	stageNotifyCalls := make([]int, 5)
	startTestTime := time.Now().UnixNano()
	perfMonitor := makeConnectionPerformanceMonitor([]Tag{protocol.AgreementVoteTag})
	// measure measuring overhead.
	measuringOverhead := time.Now().Sub(time.Now())
	perfMonitor.Reset(peers)
	for msgIdx, msg := range msgPool {
		msg.Received += startTestTime
		beforeNotify := time.Now()
		beforeNotifyStage := perfMonitor.stage
		perfMonitor.Notify(&msg)
		notifyTime := time.Now().Sub(beforeNotify)
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
func TestBucketsPruning(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
