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
	"sort"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
)

//msgp:ignore pmStage
type pmStage int

const (
	pmStagePresync    pmStage = iota // pmStagePresync used as a warmup for the monitoring. it ensures that we've received at least a single message from each peer, and that we've waited enough time before attempting to sync up.
	pmStageSync       pmStage = iota // pmStageSync is syncing up the peer message streams. It exists once all the connections have demonstrated a given idle time.
	pmStageAccumulate pmStage = iota // pmStageAccumulate monitors streams and accumulate the messages between the connections.
	pmStageStopping   pmStage = iota // pmStageStopping keep monitoring the streams, but do not accept new messages. It tries to expire pending messages until all pending messages expires.
	pmStageStopped    pmStage = iota // pmStageStopped is the final stage; it means that the performance monitor reached a conclusion regarding the performance statistics
)

const (
	pmPresyncTime                   = 10 * time.Second
	pmSyncIdleTime                  = 2 * time.Second
	pmSyncMaxTime                   = 25 * time.Second
	pmAccumulationTime              = 60 * time.Second
	pmAccumulationTimeRange         = 30 * time.Second
	pmAccumulationIdlingTime        = 2 * time.Second
	pmMaxMessageWaitTime            = 15 * time.Second
	pmUndeliveredMessagePenaltyTime = 5 * time.Second
	pmDesiredMessegeDelayThreshold  = 50 * time.Millisecond
	pmMessageBucketDuration         = time.Second
)

// pmMessage is the internal storage for a single message. We save the time the message arrived from each of the peers.
type pmMessage struct {
	peerMsgTime   map[Peer]int64 // for each peer, when did we see a message the first time
	firstPeerTime int64          // the timestamp of the first peer that has seen this message.
}

// pmPeerStatistics is the per-peer resulting datastructure of the performance analysis.
type pmPeerStatistics struct {
	peer             Peer    // the peer interface
	peerDelay        int64   // the peer avarage relative message delay
	peerFirstMessage float32 // what percentage of the messages were delivered by this peer before any other peer
}

// pmStatistics is the resulting datastructure of the performance analysis.
type pmStatistics struct {
	peerStatistics []pmPeerStatistics // an ordered list of the peers performance statistics
	messageCount   int64              // the number of messages used to calculate the above statistics
}

// pmPendingMessageBucket is used to buffer messages in time ranges blocks.
type pmPendingMessageBucket struct {
	messages  map[crypto.Digest]*pmMessage // the pendingMessages map contains messages that haven't been received from all the peers within the pmMaxMessageWaitTime, and belong to the timerange of this bucket.
	startTime int64                        // the inclusive start-range of the timestamp which bounds the messages ranges which would go into this bucket. Time is in nano seconds UTC epoch time.
	endTime   int64                        // the inclusive end-range of the timestamp which bounds the messages ranges which would go into this bucket. Time is in nano seconds UTC epoch time.
}

// connectionPerformanceMonitor is the connection monitor datatype. We typically would like to have a single monitor for all
// the outgoing connections.
type connectionPerformanceMonitor struct {
	deadlock.Mutex
	monitoredConnections   map[Peer]bool             // the map of the connection we're going to monitor. Messages coming from other connections would be ignored.
	monitoredMessageTags   map[Tag]bool              // the map of the message tags we're interested in monitoring. Messages that aren't broadcast-type typically would be a good choice here.
	stage                  pmStage                   // the performance monitoring stage.
	peerLastMsgTime        map[Peer]int64            // the map describing the last time we received a message from each of the peers.
	lastIncomingMsgTime    int64                     // the time at which the last message was received from any of the peers.
	stageStartTime         int64                     // the timestamp at which we switched to the current stage.
	pendingMessagesBuckets []*pmPendingMessageBucket // the pendingMessagesBuckets array contains messages buckets for messages that haven't been received from all the peers within the pmMaxMessageWaitTime
	connectionDelay        map[Peer]int64            // contains the total delay we've sustained by each peer when we're in stages pmStagePresync-pmStageStopping and the average delay after that. ( in nano seconds )
	firstMessageCount      map[Peer]int64            // maps the peers to their accumulated first messages ( the number of times a message seen coming from this peer first )
	msgCount               int64                     // total number of messages that we've accumulated.
	accumulationTime       int64                     // the duration of which we're going to accumulate messages. This will get randomized to prevent cross-node synchronization.
}

// makeConnectionPerformanceMonitor creates a new performance monitor instance, that is configured for monitoring the given message tags.
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

// GetPeersStatistics returns the statistics result of the performance monitoring, once these becomes available.
// otherwise, it returns nil.
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
		peerStat := pmPeerStatistics{
			peer:      peer,
			peerDelay: delay,
		}
		if pm.msgCount > 0 {
			peerStat.peerFirstMessage = float32(pm.firstMessageCount[peer]) / float32(pm.msgCount)
		}
		stat.peerStatistics = append(stat.peerStatistics, peerStat)
	}
	sort.Slice(stat.peerStatistics, func(i, j int) bool {
		return stat.peerStatistics[i].peerDelay > stat.peerStatistics[j].peerDelay
	})
	return
}

// ComparePeers compares the given peers list or the existing peers being monitored. If the
// peers list have changed since Reset was called, it would return false.
// The method is insensitive to peer ordering and uses the peer interface pointer to determine equality.
func (pm *connectionPerformanceMonitor) ComparePeers(peers []Peer) bool {
	pm.Lock()
	defer pm.Unlock()
	for _, peer := range peers {
		if !pm.monitoredConnections[peer] {
			return false
		}
	}
	return len(peers) == len(pm.monitoredConnections)
}

// Reset updates the existing peers list to the one provided. The Reset method is expected to be used
// in three scenarios :
// 1. clearing out the existing monitoring - which brings it to initial state and disable monitoring.
// 2. change monitored peers - in case we've had some of our peers disconnected/reconnected during the monitoring process.
// 3. start monitoring
func (pm *connectionPerformanceMonitor) Reset(peers []Peer) {
	pm.Lock()
	defer pm.Unlock()
	pm.monitoredConnections = make(map[Peer]bool, len(peers))
	pm.peerLastMsgTime = make(map[Peer]int64, len(peers))
	pm.connectionDelay = make(map[Peer]int64, len(peers))
	pm.firstMessageCount = make(map[Peer]int64, len(peers))
	pm.msgCount = 0
	pm.advanceStage(pmStagePresync, time.Now().UnixNano())
	pm.accumulationTime = int64(pmAccumulationTime) + int64(crypto.RandUint63())%int64(pmAccumulationTime)

	for _, peer := range peers {
		pm.monitoredConnections[peer] = true
		pm.peerLastMsgTime[peer] = pm.stageStartTime
		pm.connectionDelay[peer] = 0
		pm.firstMessageCount[peer] = 0
	}

}

// Notify is the single entrypoint for an incoming message processing. When an outgoing connection
// is being monitored, it would make a call to Notify, sending the incoming message details.
// The Notify function will forward this notification to the current stage processing function.
func (pm *connectionPerformanceMonitor) Notify(msg *IncomingMessage) {
	pm.Lock()
	defer pm.Unlock()
	if !pm.monitoredConnections[msg.Sender] {
		return
	}
	if !pm.monitoredMessageTags[msg.Tag] {
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
	pm.peerLastMsgTime[msg.Sender] = msg.Received
	if (msg.Received - pm.stageStartTime) < int64(pmPresyncTime) {
		return
	}
	// presync complete. move to the next stage.
	noMsgPeers := make(map[Peer]bool, 0)
	for peer, lastMsgTime := range pm.peerLastMsgTime {
		if lastMsgTime == pm.stageStartTime {
			// we haven't received a single message from this peer during the entire presync time.
			noMsgPeers[peer] = true
		}
	}
	if len(noMsgPeers) >= (len(pm.peerLastMsgTime) / 2) {
		// if more than half of the peers have not sent us a single message,
		// extend the presync time. We might be in agreement recovery, where we have very low
		// traffic. If this becomes a repeated issue, it will get solved by the
		// clique detection algorithm and some of the nodes would get disconnected.
		pm.stageStartTime = msg.Received
		return
	}
	if len(noMsgPeers) > 0 {
		// we have one or more peers that did not send a single message thoughtout the presync time.
		// ( but less than half ). since we cannot rely on these to send us messages in the future,
		// we'll disconnect from these peers.
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
	pm.lastIncomingMsgTime = msg.Received
	// otherwise, once we received a message from each of the peers, move to the sync stage.
	pm.advanceStage(pmStageSync, msg.Received)
}

// notifySync waits for all the peers connection's to go into an idle phase.
// when we go into this stage, the peerLastMsgTime will be already updated
// with the recent message time per peer.
func (pm *connectionPerformanceMonitor) notifySync(msg *IncomingMessage) {
	minMsgInterval := pm.updateMessageIdlingInterval(msg.Received)
	if minMsgInterval > int64(pmSyncIdleTime) || (msg.Received-pm.stageStartTime > int64(pmSyncMaxTime)) {
		// if we hit the first expression, then it means that we've managed to sync up the connections.
		// otherwise, we've failed to sync up the connections. That's not great, as we're likely to
		// have some "penalties" applied, but we can't do much about it.
		pm.accumulateMessage(msg, true)
		pm.advanceStage(pmStageAccumulate, msg.Received)
	}
}

// notifyAccumulate accumulate the incoming message as needed, and waiting between pm.accumulationTime to
// (pm.accumulationTime + pmAccumulationTimeRange) before moving to the next stage.
func (pm *connectionPerformanceMonitor) notifyAccumulate(msg *IncomingMessage) {
	minMsgInterval := pm.updateMessageIdlingInterval(msg.Received)
	if msg.Received-pm.stageStartTime >= pm.accumulationTime {
		if minMsgInterval > int64(pmAccumulationIdlingTime) ||
			(msg.Received-pm.stageStartTime >= pm.accumulationTime+int64(pmAccumulationTimeRange)) {
			// move to the next stage.
			pm.advanceStage(pmStageStopping, msg.Received)
			return
		}
	}
	pm.accumulateMessage(msg, true)
	pm.pruneOldMessages(msg.Received)
}

// notifyStopping attempts to stop the message accumulation. Once we reach this stage, no new messages are being
// added, and old pending messages are being pruned. Once all messages are pruned, it moves to the next stage.
func (pm *connectionPerformanceMonitor) notifyStopping(msg *IncomingMessage) {
	pm.accumulateMessage(msg, false)
	pm.pruneOldMessages(msg.Received)
	if len(pm.pendingMessagesBuckets) > 0 {
		return
	}
	// time to wrap up.
	if pm.msgCount > 0 {
		for peer := range pm.monitoredConnections {
			pm.connectionDelay[peer] /= int64(pm.msgCount)
		}
	}
	pm.advanceStage(pmStageStopped, msg.Received)
}

// advanceStage set the stage variable and update the stage start time.
func (pm *connectionPerformanceMonitor) advanceStage(newStage pmStage, now int64) {
	pm.stage = newStage
	pm.stageStartTime = now
}

// updateMessageIdlingInterval updates the last message received timestamps and determines how long it has been since
// the last message was received on any of the incoming peers
func (pm *connectionPerformanceMonitor) updateMessageIdlingInterval(now int64) (minMsgInterval int64) {
	currentIncomingMsgTime := pm.lastIncomingMsgTime
	if pm.lastIncomingMsgTime < now {
		pm.lastIncomingMsgTime = now
	}
	if currentIncomingMsgTime <= now {
		return now - currentIncomingMsgTime
	}
	return 0
}

func (pm *connectionPerformanceMonitor) pruneOldMessages(now int64) {
	oldestMessage := now - int64(pmMaxMessageWaitTime)
	prunedBucketsCount := 0
	for bucketIdx, currentMsgBucket := range pm.pendingMessagesBuckets {
		if currentMsgBucket.endTime > oldestMessage {
			pm.pendingMessagesBuckets[bucketIdx-prunedBucketsCount] = currentMsgBucket
			continue
		}
		for _, pendingMsg := range currentMsgBucket.messages {
			for peer := range pm.monitoredConnections {
				if msgTime, hasPeer := pendingMsg.peerMsgTime[peer]; hasPeer {
					msgDelayInterval := msgTime - pendingMsg.firstPeerTime
					pm.connectionDelay[peer] += msgDelayInterval
				} else {
					// we never received this message from this peer.
					pm.connectionDelay[peer] += int64(pmUndeliveredMessagePenaltyTime)
				}
			}
		}
		prunedBucketsCount++
	}
	pm.pendingMessagesBuckets = pm.pendingMessagesBuckets[:len(pm.pendingMessagesBuckets)-prunedBucketsCount]
}

func (pm *connectionPerformanceMonitor) accumulateMessage(msg *IncomingMessage, newMessages bool) {
	msgDigest := generateMessageDigest(msg.Tag, msg.Data)

	var msgBucket *pmPendingMessageBucket
	var pendingMsg *pmMessage
	var msgFound bool
	// try to find the message. It's more likely to be found in the most recent bucket, so start there and go backward.
	for bucketIndex := range pm.pendingMessagesBuckets {
		currentMsgBucket := pm.pendingMessagesBuckets[len(pm.pendingMessagesBuckets)-1-bucketIndex]
		if pendingMsg, msgFound = currentMsgBucket.messages[msgDigest]; msgFound {
			msgBucket = currentMsgBucket
			break
		}
		if msg.Received >= currentMsgBucket.startTime && msg.Received <= currentMsgBucket.endTime {
			msgBucket = currentMsgBucket
		}
	}
	if pendingMsg == nil {
		if newMessages {
			if msgBucket == nil {
				// no bucket was found. create one.
				msgBucket = &pmPendingMessageBucket{
					messages:  make(map[crypto.Digest]*pmMessage),
					startTime: msg.Received - (msg.Received % int64(pmMessageBucketDuration)), // align with pmMessageBucketDuration
				}
				msgBucket.endTime = msgBucket.startTime + int64(pmMessageBucketDuration) - 1
				pm.pendingMessagesBuckets = append(pm.pendingMessagesBuckets, msgBucket)
			}
			// we don't have this one yet, add it.
			msgBucket.messages[msgDigest] = &pmMessage{
				peerMsgTime: map[Peer]int64{
					msg.Sender: msg.Received,
				},
				firstPeerTime: msg.Received,
			}
			pm.firstMessageCount[msg.Sender]++
			pm.msgCount++
		}
		return
	}
	// we already seen this digest
	// make sure we're only moving forward in time. This could be caused when
	// we have lock contention.
	pendingMsg.peerMsgTime[msg.Sender] = msg.Received
	if msg.Received < pendingMsg.firstPeerTime {
		pendingMsg.firstPeerTime = msg.Received
	}

	if len(pendingMsg.peerMsgTime) == len(pm.monitoredConnections) {
		// we've received the same message from all out peers.
		for peer, msgTime := range pendingMsg.peerMsgTime {
			pm.connectionDelay[peer] += msgTime - pendingMsg.firstPeerTime
		}
		delete(msgBucket.messages, msgDigest)
	}
}

type networkAdvanceMonitor struct {
	// lastNetworkAdvance contains the last timestamp where the agreement protocol was able to make a notable progress.
	// it used as a watchdog to help us detect connectivity issues ( such as cliques )
	lastNetworkAdvance time.Time

	mu deadlock.Mutex
}

func makeNetworkAdvanceMonitor() *networkAdvanceMonitor {
	return &networkAdvanceMonitor{
		lastNetworkAdvance: time.Now().UTC(),
	}
}

func (m *networkAdvanceMonitor) lastAdvancedWithin(interval time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	// now < last + interval <=> now - last < interval
	return time.Now().UTC().Before(m.lastNetworkAdvance.Add(interval))
}

func (m *networkAdvanceMonitor) updateLastAdvance() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastNetworkAdvance = time.Now().UTC()
}

type outgoingConnsCloser struct {
	log                   logging.Logger
	net                   outgoingDisconnectable
	cliqueResolveInterval time.Duration
	connPerfMonitor       *connectionPerformanceMonitor
	netAdvMonitor         *networkAdvanceMonitor
}

type outgoingDisconnectable interface {
	outgoingPeers() (peers []Peer)
	numOutgoingPending() int
	disconnect(badnode Peer, reason disconnectReason)
	OnNetworkAdvance()
}

func makeOutgoingConnsCloser(log logging.Logger, net outgoingDisconnectable, connPerfMonitor *connectionPerformanceMonitor, cliqueResolveInterval time.Duration) *outgoingConnsCloser {
	return &outgoingConnsCloser{
		log:                   log,
		net:                   net,
		cliqueResolveInterval: cliqueResolveInterval,
		connPerfMonitor:       connPerfMonitor,
		netAdvMonitor:         makeNetworkAdvanceMonitor(),
	}
}

// checkExistingConnectionsNeedDisconnecting check to see if existing connection need to be dropped due to
// performance issues and/or network being stalled.
func (cc *outgoingConnsCloser) checkExistingConnectionsNeedDisconnecting(targetConnCount int) bool {
	// we already connected ( or connecting.. ) to  GossipFanout peers.
	// get the actual peers.
	outgoingPeers := cc.net.outgoingPeers()
	if len(outgoingPeers) < targetConnCount {
		// reset the performance monitor.
		cc.connPerfMonitor.Reset([]Peer{})
		return cc.checkNetworkAdvanceDisconnect()
	}

	if !cc.connPerfMonitor.ComparePeers(outgoingPeers) {
		// different set of peers. restart monitoring.
		cc.connPerfMonitor.Reset(outgoingPeers)
	}

	// same set of peers.
	peerStat := cc.connPerfMonitor.GetPeersStatistics()
	if peerStat == nil {
		// performance metrics are not yet ready.
		return cc.checkNetworkAdvanceDisconnect()
	}

	// update peers with the performance metrics we've gathered.
	var leastPerformingPeer *wsPeer = nil
	for _, stat := range peerStat.peerStatistics {
		wsPeer := stat.peer.(*wsPeer)
		wsPeer.peerMessageDelay = stat.peerDelay
		cc.log.Infof("network performance monitor - peer '%s' delay %d first message portion %d%%", wsPeer.GetAddress(), stat.peerDelay, int(stat.peerFirstMessage*100))
		if wsPeer.throttledOutgoingConnection && leastPerformingPeer == nil {
			leastPerformingPeer = wsPeer
		}
	}
	if leastPerformingPeer == nil {
		return cc.checkNetworkAdvanceDisconnect()
	}
	cc.net.disconnect(leastPerformingPeer, disconnectLeastPerformingPeer)
	cc.connPerfMonitor.Reset([]Peer{})

	return true
}

// checkNetworkAdvanceDisconnect is using the lastNetworkAdvance indicator to see if the network is currently "stuck".
// if it's seems to be "stuck", a randomly picked peer would be disconnected.
func (cc *outgoingConnsCloser) checkNetworkAdvanceDisconnect() bool {
	if cc.netAdvMonitor.lastAdvancedWithin(cc.cliqueResolveInterval) {
		return false
	}
	outgoingPeers := cc.net.outgoingPeers()
	if len(outgoingPeers) == 0 {
		return false
	}
	if cc.net.numOutgoingPending() > 0 {
		// we're currently trying to extend the list of outgoing connections. no need to
		// disconnect any existing connection to free up room for another connection.
		return false
	}
	var peer *wsPeer
	disconnectPeerIdx := crypto.RandUint63() % uint64(len(outgoingPeers))
	peer = outgoingPeers[disconnectPeerIdx].(*wsPeer)

	cc.net.disconnect(peer, disconnectCliqueResolve)
	cc.connPerfMonitor.Reset([]Peer{})
	cc.net.OnNetworkAdvance()
	return true
}

func (cc *outgoingConnsCloser) updateLastAdvance() {
	cc.netAdvMonitor.updateLastAdvance()
}
