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

package txnsync

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/timers"
)

const (
	kickoffTime      = 200 * time.Millisecond
	randomRange      = 100 * time.Millisecond
	sendMessagesTime = 10 * time.Millisecond
)

type syncState struct {
	service *Service
	log     Logger
	node    NodeConnector
	isRelay bool
	clock   timers.WallClock

	lastBeta                   time.Duration
	round                      basics.Round
	fetchTransactions          bool
	scheduler                  peerScheduler
	interruptablePeers         []*Peer
	interruptablePeersMap      map[*Peer]int // map a peer into the index of interruptablePeers
	incomingMessagesCh         chan incomingMessage
	outgoingMessagesCallbackCh chan *messageSentCallback
	nextOffsetRollingCh        <-chan time.Time
	requestsOffset             uint64

	// The lastBloomFilter allows us to share the same bloom filter across multiples messages,
	// and compute it only once. Since this bloom filter could contain many hashes ( especially on relays )
	// it's important to avoid recomputing it needlessly.
	lastBloomFilter bloomFilter

	profiler *profiler
}

func (s *syncState) mainloop(serviceCtx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	// The following would allow the emulator to start the service in a "stopped" mode.
	s.node.NotifyMonitor()

	s.clock = s.node.Clock()
	s.incomingMessagesCh = make(chan incomingMessage, 1024)
	s.outgoingMessagesCallbackCh = make(chan *messageSentCallback, 1024)
	s.interruptablePeersMap = make(map[*Peer]int)
	s.scheduler.node = s.node
	s.lastBeta = beta(0)
	roundSettings := s.node.GetCurrentRoundSettings()
	s.onNewRoundEvent(MakeNewRoundEvent(roundSettings.Round, roundSettings.FetchTransactions))

	// create a profiler, and it's profiling elements.
	s.profiler = makeProfiler(200*time.Millisecond, s.clock, s.log, 2000*time.Millisecond) // todo : make the time configurable.
	profIdle := s.profiler.getElement(profElementIdle)
	profTxChange := s.profiler.getElement(profElementTxChange)
	profNewRounnd := s.profiler.getElement(profElementNewRounnd)
	profPeerState := s.profiler.getElement(profElementPeerState)
	profIncomingMsg := s.profiler.getElement(profElementIncomingMsg)
	profOutgoingMsg := s.profiler.getElement(profElementOutgoingMsg)
	profNextOffset := s.profiler.getElement(profElementNextOffset)

	externalEvents := s.node.Events()
	var nextPeerStateCh <-chan time.Time
	for {
		nextPeerStateTime := s.scheduler.nextDuration()
		if nextPeerStateTime != time.Duration(0) {
			nextPeerStateCh = s.clock.TimeoutAt(nextPeerStateTime)
		} else {
			nextPeerStateCh = nil
		}

		select {
		case ent := <-externalEvents:
			switch ent.eventType {
			case transactionPoolChangedEvent:
				profTxChange.start()
				s.onTransactionPoolChangedEvent(ent)
				profTxChange.end()
			case newRoundEvent:
				profNewRounnd.start()
				s.onNewRoundEvent(ent)
				profNewRounnd.end()
			}
			continue
		case <-nextPeerStateCh:
			profPeerState.start()
			s.evaluatePeerStateChanges(nextPeerStateTime)
			profPeerState.end()
			continue
		case incomingMsg := <-s.incomingMessagesCh:
			profIncomingMsg.start()
			s.evaluateIncomingMessage(incomingMsg)
			profIncomingMsg.end()
			continue
		case msgSent := <-s.outgoingMessagesCallbackCh:
			profOutgoingMsg.start()
			s.evaluateOutgoingMessage(msgSent)
			profOutgoingMsg.end()
			continue
		case <-s.nextOffsetRollingCh:
			profNextOffset.start()
			s.rollOffsets()
			profNextOffset.end()
			continue
		case <-serviceCtx.Done():
			return
		default:
		}

		profIdle.start()
		select {
		case ent := <-externalEvents:
			profIdle.end()
			switch ent.eventType {
			case transactionPoolChangedEvent:
				profTxChange.start()
				s.onTransactionPoolChangedEvent(ent)
				profTxChange.end()
			case newRoundEvent:
				profNewRounnd.start()
				s.onNewRoundEvent(ent)
				profNewRounnd.end()
			}
		case <-nextPeerStateCh:
			profIdle.end()
			profPeerState.start()
			s.evaluatePeerStateChanges(nextPeerStateTime)
			profPeerState.end()
		case incomingMsg := <-s.incomingMessagesCh:
			profIdle.end()
			profIncomingMsg.start()
			s.evaluateIncomingMessage(incomingMsg)
			profIncomingMsg.end()
		case msgSent := <-s.outgoingMessagesCallbackCh:
			profIdle.end()
			profOutgoingMsg.start()
			s.evaluateOutgoingMessage(msgSent)
			profOutgoingMsg.end()
		case <-s.nextOffsetRollingCh:
			profIdle.end()
			profNextOffset.start()
			s.rollOffsets()
			profNextOffset.end()
		case <-serviceCtx.Done():
			profIdle.end()
			return
		case <-s.node.NotifyMonitor():
			profIdle.end()
		}
	}
}

func (s *syncState) onTransactionPoolChangedEvent(ent Event) {
	newBeta := beta(ent.transactionPoolSize)
	// see if the newBeta is at least 20% smaller than the current one.
	if (s.lastBeta * 9 / 10) <= newBeta {
		// no, it's not.
		return
	}
	// yes, the number of transactions in the pool have changed dramatically since the last time.
	s.lastBeta = newBeta

	peers := make([]*Peer, 0, len(s.interruptablePeers))
	for _, peer := range s.interruptablePeers {
		if peer == nil {
			continue
		}
		peers = append(peers, peer)
		peer.state = peerStateHoldsoff

	}
	// reset the interruptablePeers array, since all it's members were made into holdsoff
	s.interruptablePeers = nil
	s.interruptablePeersMap = make(map[*Peer]int)
	deadlineMonitor := s.clock.DeadlineMonitorAt(s.clock.Since() + sendMessagesTime)
	s.sendMessageLoop(s.clock.Since(), deadlineMonitor, peers)

	currentTimeout := s.clock.Since()
	for _, peer := range peers {
		peerNext := s.scheduler.peerDuration(peer)
		if peerNext < currentTimeout {
			// shouldn't be, but let's reschedule it if this is the case.
			s.scheduler.schedulerPeer(peer, currentTimeout+s.lastBeta)
			continue
		}
		// given that peerNext is after currentTimeout, find out what's the difference, and divide by the beta.
		betaCount := (peerNext - currentTimeout) / s.lastBeta
		peerNext = currentTimeout + s.lastBeta*betaCount
		s.scheduler.schedulerPeer(peer, peerNext)
	}
}

// calculate the beta parameter, based on the transcation pool size.
func beta(txPoolSize int) time.Duration {
	if txPoolSize < 200 {
		txPoolSize = 200
	} else if txPoolSize > 10000 {
		txPoolSize = 10000
	}
	beta := 1.0 / (2 * 3.6923 * math.Exp(float64(txPoolSize)*0.00026))
	return time.Duration(float64(time.Second) * beta)

}

func (s *syncState) onNewRoundEvent(ent Event) {
	s.clock = s.clock.Zero().(timers.WallClock)
	peers := s.getPeers()
	newRoundPeers := peers
	if s.isRelay {
		// on relays, outgoing peers have a difference scheduling, which is based on the incoming message timing
		// rather then a priodic message transmission.
		newRoundPeers = incomingPeersOnly(newRoundPeers)
	}
	s.scheduler.scheduleNewRound(newRoundPeers, s.isRelay)
	s.updatePeersRequestParams(peers)
	s.round = ent.roundSettings.Round
	s.fetchTransactions = ent.roundSettings.FetchTransactions
	if !s.isRelay {
		s.nextOffsetRollingCh = s.clock.TimeoutAt(kickoffTime + 2*s.lastBeta)
	}
}

func (s *syncState) evaluatePeerStateChanges(currentTimeout time.Duration) {
	peers := s.scheduler.nextPeers()
	if len(peers) == 0 {
		return
	}

	sendMessagePeers := 0
	for _, peer := range peers {
		ops := peer.advancePeerState(currentTimeout, s.isRelay)
		if (ops & peerOpsSendMessage) == peerOpsSendMessage {
			peers[sendMessagePeers] = peer
			sendMessagePeers++
		}
		if (ops & peerOpsSetInterruptible) == peerOpsSetInterruptible {
			if _, has := s.interruptablePeersMap[peer]; !has {
				s.interruptablePeers = append(s.interruptablePeers, peer)
				s.interruptablePeersMap[peer] = len(s.interruptablePeers) - 1
			}
		}
		if (ops & peerOpsClearInterruptible) == peerOpsClearInterruptible {
			if idx, has := s.interruptablePeersMap[peer]; has {
				delete(s.interruptablePeersMap, peer)
				s.interruptablePeers[idx] = nil
			}
		}
		if (ops & peerOpsReschedule) == peerOpsReschedule {
			s.scheduler.schedulerPeer(peer, currentTimeout+s.lastBeta)
		}
	}

	peers = peers[:sendMessagePeers]
	deadlineMonitor := s.clock.DeadlineMonitorAt(currentTimeout + sendMessagesTime)
	s.sendMessageLoop(currentTimeout, deadlineMonitor, peers)
}

// rollOffsets rolls the "base" offset for the peers offset selection. This method is only called
// for non-relays.
func (s *syncState) rollOffsets() {
	s.nextOffsetRollingCh = s.clock.TimeoutAt(s.clock.Since() + 2*s.lastBeta)
	s.requestsOffset++

	if !s.fetchTransactions {
		return
	}

	// iterate on the outgoing peers and see if we want to send them an update as needed.
	// note that because this function is only called for non-relays, then all the connections
	// are outgoing.
	peers := s.getPeers()
	s.updatePeersRequestParams(peers)

	// check when each of these peers is expected to send a message. we might want to promote a message to be sent earlier.
	currentTimeOffset := s.clock.Since()
	deadlineMonitor := s.clock.DeadlineMonitorAt(currentTimeOffset + sendMessagesTime)

	for _, peer := range peers {
		nextSchedule := s.scheduler.peerDuration(peer)
		if nextSchedule == 0 {
			// a new peer - ignore for now. This peer would get scheduled on the next new round.
			continue
		}
		if currentTimeOffset+sendMessagesTime > nextSchedule {
			// there was a message scheudled already in less than 20ms, so keep that one.
			s.scheduler.schedulerPeer(peer, nextSchedule)
			continue
		}

		// otherwise, send a message to that peer. Note that we're passing the `nextSchedule-s.lastBeta` as the currentTime,
		// so that the time offset would be based on that one. ( i.e. effectively, it would retain the existing timing, and prevent
		// the peers from getting aligned )
		s.sendMessageLoop(nextSchedule-s.lastBeta, deadlineMonitor, []*Peer{peer})
	}
}

func (s *syncState) getPeers() (result []*Peer) {
	peersInfo := s.node.GetPeers()
	updatedNetworkPeers := []interface{}{}
	updatedNetworkPeersSync := []*Peer{}
	// some of the network peers might not have a sync peer, so we need to create one for these.
	for _, peerInfo := range peersInfo {
		if peerInfo.TxnSyncPeer == nil {
			syncPeer := makePeer(peerInfo.NetworkPeer, peerInfo.IsOutgoing, s.isRelay)
			peerInfo.TxnSyncPeer = syncPeer
			updatedNetworkPeers = append(updatedNetworkPeers, peerInfo.NetworkPeer)
			updatedNetworkPeersSync = append(updatedNetworkPeersSync, syncPeer)
		}
		result = append(result, peerInfo.TxnSyncPeer)
	}
	if len(updatedNetworkPeers) > 0 {
		s.node.UpdatePeers(updatedNetworkPeersSync, updatedNetworkPeers)
	}
	return result
}

func (s *syncState) updatePeersRequestParams(peers []*Peer) {
	if s.isRelay {
		for _, peer := range peers {
			peer.setLocalRequestParams(0, 1)
		}
	} else {
		for i, peer := range peers {
			// on non-relay, ask for offset/modulator
			peer.setLocalRequestParams(uint64(i)+s.requestsOffset, uint64(len(peers)))
		}
	}
}
