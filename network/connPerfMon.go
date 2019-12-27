// Copyright (C) 2019 Algorand, Inc.
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
	"sort"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
)

const (
	pmStagePresync    = iota // pmStagePresync used as a warmup for the monitoring. it ensures that we've received at least a single message from each peer, and that we've waited enough time before attempting to sync up.
	pmStageSync              // pmStageSync is syncing up the peer message streams. It exists once all the connections have demonstrated a given idle time.
	pmStageAccumulate        // pmStageAccumulate monitors streams and accumulate the messages between the connections.
	pmStageStopping          // pmStageStopping keep monitoring the streams, but do not accept new messages. It tries to expire pending messages until all pending messages expires.
	pmStageStopped           // pmStageStopped is the final stage; it means that the performance monitor reached a conclusion regarding the performance statistics
)

const (
	pmPresyncTime                   = 10 * time.Second
	pmSyncIdleTime                  = 2 * time.Second
	pmAccumulationTime              = 60 * time.Second
	pmAccumulationIdlingTime        = 2 * time.Second
	pmMaxMessageWaitTime            = 30 * time.Second
	pmUndeliveredMessagePenaltyTime = 5 * time.Second
)

type pmMessage struct {
	peerMsgTime   map[Peer]int64 // for each peer, when did we see a message the first time
	firstPeerTime int64          // the timestamp of the first peer that has seen this message.
}

type pmPeerStatistics struct {
	peer      Peer  // the peer interface
	peerDelay int64 // the peer avarage relative message delay
}

type pmStatistics struct {
	leastPerformingPeer      Peer               // the least performing peer
	leastPerformingPeerDelay int64              // the avarage message delay of the least performing peer
	peerStatistics           []pmPeerStatistics // an ordered list of the peers performance statistics
	messageCount             int64              // the number of messages used to calculate the above statistics
}

// IncomingMessage represents a message arriving from some peer in our p2p network
type connectionPerformanceMonitor struct {
	deadlock.Mutex
	monitoredConnections map[Peer]bool                // the map of the connection we're going to monitor. Messages coming from other connections would be ignored.
	monitoredMessageTags map[Tag]bool                 // the map of the message tags we're interested in monitoring. Messages that aren't broadcast-type typically would be a good choice heer.
	stage                int                          // the performance monitoring stage.
	lastPeerMsgTime      map[Peer]int64               // the map describing the last time we received a message from each of the peers.
	stageStartTime       int64                        // the timestamp at which we switched to the current stage.
	pendingMessages      map[crypto.Digest]*pmMessage // the pendingMessages map contains messages that haven't been received from all the peers within the pmMaxMessageWaitTime
	connectionDelay      map[Peer]int64               // contains the total delay we've sustained by each peer when we're in stages pmStagePresync-pmStageStopping and the average delay after that. ( in nano seconds )
	msgCount             int64                        // total number of messages that we've accumulated.
}

func makeConnectionPerformanceMonitor(messageTags []Tag) *connectionPerformanceMonitor {
	msgTagMap := make(map[Tag]bool, len(messageTags))
	for _, tag := range messageTags {
		msgTagMap[tag] = true
	}
	return &connectionPerformanceMonitor{
		monitoredConnections: make(map[Peer]bool, 0),
		monitoredMessageTags: msgTagMap,
	}
}

func (pm *connectionPerformanceMonitor) GetPeersStatistics() (stat *pmStatistics) {
	pm.Lock()
	defer pm.Unlock()
	if pm.stage != pmStageStopped || len(pm.connectionDelay) == 0 {
		return nil
	}
	stat = &pmStatistics{
		peerStatistics: make([]pmPeerStatistics, 0, len(pm.connectionDelay)),
		messageCount:   pm.msgCount,
	}
	for peer, delay := range pm.connectionDelay {
		stat.peerStatistics = append(stat.peerStatistics, pmPeerStatistics{peer: peer, peerDelay: delay})
	}
	sort.Slice(stat.peerStatistics, func(i, j int) bool {
		return stat.peerStatistics[i].peerDelay > stat.peerStatistics[j].peerDelay
	})
	stat.leastPerformingPeer = stat.peerStatistics[0].peer
	stat.leastPerformingPeerDelay = stat.peerStatistics[0].peerDelay
	return
}

func (pm *connectionPerformanceMonitor) ComparePeers(peers []Peer) bool {
	pm.Lock()
	defer pm.Unlock()
	for _, peer := range peers {
		if pm.monitoredConnections[peer] == false {
			return false
		}
	}
	return true
}

func (pm *connectionPerformanceMonitor) Reset(peers []Peer) {
	pm.Lock()
	defer pm.Unlock()
	pm.pendingMessages = make(map[crypto.Digest]*pmMessage, 0)
	pm.monitoredConnections = make(map[Peer]bool, len(peers))
	pm.lastPeerMsgTime = make(map[Peer]int64, len(peers))
	pm.connectionDelay = make(map[Peer]int64, len(peers))
	pm.msgCount = 0
	pm.advanceStage(pmStagePresync, time.Now().UnixNano())

	for _, peer := range peers {
		pm.monitoredConnections[peer] = true
		pm.lastPeerMsgTime[peer] = pm.stageStartTime
		pm.connectionDelay[peer] = 0
	}

}

func (pm *connectionPerformanceMonitor) Notify(msg *IncomingMessage) {
	pm.Lock()
	defer pm.Unlock()
	if pm.monitoredConnections[msg.Sender] == false {
		return
	}
	if pm.monitoredMessageTags[msg.Tag] == false {
		return
	}
	switch pm.stage {
	case pmStagePresync:
		pm.notifyPresync(msg)
	case pmStageSync:
		pm.notifySync(msg)
	case pmStageAccumulate:
		pm.notifyAccumulate(msg)
	case pmStageStopping:
		pm.notifyStopping(msg)
	default: // pmStageStopped
	}
}

// notifyPresync waits until pmPresyncTime has passed and monitor the last arrivial time
// of messages from each of the peers.
func (pm *connectionPerformanceMonitor) notifyPresync(msg *IncomingMessage) {
	pm.lastPeerMsgTime[msg.Sender] = msg.Received
	if (msg.Received - pm.stageStartTime) < int64(pmPresyncTime) {
		return
	}
	// presync complete. move to the next stage.
	noMsgPeers := make(map[Peer]bool, 0)
	for peer, lastMsgTime := range pm.lastPeerMsgTime {
		if lastMsgTime == pm.stageStartTime {
			// we haven't received a single message from this peer during the entire presync time.
			noMsgPeers[peer] = true
		}
	}
	if len(noMsgPeers) >= (len(pm.lastPeerMsgTime) / 2) {
		// if more than half of the peers have not sent us a single message,
		// extend the presync time. We might be in recovery, where we have very low
		// traffic.
		pm.stageStartTime = time.Now().UnixNano()
		return
	}
	if len(noMsgPeers) > 0 {
		// we have one or more peers that did not send a single message thoughtout the presync time.
		// ( but less than half ). since we cannot rely on these to send us messages in the future,
		// we'll disconnect from these peers.
		// todo : disconnect.
		pm.advanceStage(pmStageStopped, msg.Received)
		for peer := range pm.monitoredConnections {
			if noMsgPeers[peer] {
				pm.connectionDelay[peer] = int64(pmUndeliveredMessagePenaltyTime)
			} else {
				pm.connectionDelay[peer] = 0
			}
		}
		return
	}
	// otherwise, once we recieved a message from each of the peers, move to the sync stage.
	pm.advanceStage(pmStageSync, msg.Received)
}

// notifySync waits for all the peers connection's to go into an idle phase.
// when we go into this stage, the lastPeerMsgTime will be already updated
// with the recent message time per peer.
func (pm *connectionPerformanceMonitor) notifySync(msg *IncomingMessage) {
	minMsgInterval := pm.calculateMsgIdlingInterval(msg.Received)
	pm.lastPeerMsgTime[msg.Sender] = msg.Received
	if minMsgInterval > int64(pmSyncIdleTime) {
		// move to the next stage.
		pm.accumulateMessage(msg, true)
		pm.advanceStage(pmStageAccumulate, msg.Received)
	}
}

func (pm *connectionPerformanceMonitor) notifyAccumulate(msg *IncomingMessage) {
	minMsgInterval := pm.calculateMsgIdlingInterval(msg.Received)
	pm.lastPeerMsgTime[msg.Sender] = msg.Received
	if msg.Received-pm.stageStartTime >= int64(pmAccumulationTime) {
		if minMsgInterval > int64(pmAccumulationIdlingTime) {
			// move to the next stage.
			pm.advanceStage(pmStageStopping, msg.Received)
			return
		}
	}
	pm.accumulateMessage(msg, true)
	pm.pruneOldMessages(msg.Received)
}

func (pm *connectionPerformanceMonitor) notifyStopping(msg *IncomingMessage) {
	pm.accumulateMessage(msg, false)
	pm.pruneOldMessages(msg.Received)
	if len(pm.pendingMessages) == 0 {
		// time to wrap up.
		pm.advanceStage(pmStageStopped, msg.Received)
		if pm.msgCount > 0 {
			for peer := range pm.monitoredConnections {
				pm.connectionDelay[peer] /= int64(pm.msgCount)
			}
		}
		return
	}
}

func (pm *connectionPerformanceMonitor) advanceStage(newStage int, now int64) {
	pm.stage = newStage
	pm.stageStartTime = now
}

func (pm *connectionPerformanceMonitor) calculateMsgIdlingInterval(now int64) (minMsgInterval int64) {
	minMsgInterval = int64(time.Hour)
	for _, prevMsgTime := range pm.lastPeerMsgTime {
		if now-prevMsgTime < minMsgInterval {
			minMsgInterval = now - prevMsgTime
		}
	}
	return
}

func (pm *connectionPerformanceMonitor) pruneOldMessages(now int64) {
	msgToPrune := make([]crypto.Digest, 0, len(pm.pendingMessages))
	for digest, msg := range pm.pendingMessages {
		if now-msg.firstPeerTime > int64(pmMaxMessageWaitTime) {
			msgToPrune = append(msgToPrune, digest)
		}
	}
	for _, digest := range msgToPrune {
		pendingMsg := pm.pendingMessages[digest]
		for peer := range pm.monitoredConnections {
			if msgTime, hasPeer := pendingMsg.peerMsgTime[peer]; hasPeer {
				msgDelayInterval := msgTime - pendingMsg.firstPeerTime
				pm.connectionDelay[peer] += msgDelayInterval
			} else {
				// we never received this message from this peer.
				pm.connectionDelay[peer] += int64(pmUndeliveredMessagePenaltyTime)
			}
		}
		delete(pm.pendingMessages, digest)
	}
}

func (pm *connectionPerformanceMonitor) accumulateMessage(msg *IncomingMessage, newMessages bool) {
	msgDigest := generateMessageDigest(msg.Tag, msg.Data)

	pendingMsg := pm.pendingMessages[msgDigest]
	if pendingMsg == nil {
		if newMessages {
			// we don't have this one yet, add it.
			pm.pendingMessages[msgDigest] = &pmMessage{
				peerMsgTime: map[Peer]int64{
					msg.Sender: msg.Received,
				},
				firstPeerTime: msg.Received,
			}
			pm.msgCount++
		}
		return
	}
	// we already seen this digest
	// make sure we're only moving forward in time. This could be caused when
	// we have lock contension.
	if msg.Received >= pendingMsg.firstPeerTime {
		pendingMsg.peerMsgTime[msg.Sender] = msg.Received
	} else {
		// just use the first timestamp. ( the inaccuracy here doesn't really matter )
		pendingMsg.peerMsgTime[msg.Sender] = pendingMsg.firstPeerTime
	}
	if len(pendingMsg.peerMsgTime) == len(pm.monitoredConnections) {
		// we've received the same message from all out peers.
		for peer, msgTime := range pendingMsg.peerMsgTime {
			if msgTime == pendingMsg.firstPeerTime {
				continue
			}
			msgDelayInterval := msgTime - pendingMsg.firstPeerTime
			pm.connectionDelay[peer] += msgDelayInterval
		}
		delete(pm.pendingMessages, msgDigest)
	}
}
