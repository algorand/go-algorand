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
	"sync"

	"github.com/algorand/go-deadlock"
)

// incomingMessageQueue manages the global incoming message queue across all the incoming peers.
type incomingMessageQueue struct {
	outboundPeerCh    chan incomingMessage
	enqueuedPeersMap  map[*Peer]int
	enqueuedMessages  []incomingMessage
	enqueuedPeersMu   deadlock.Mutex
	enqueuedPeersCond *sync.Cond
	shutdownRequest   chan struct{}
	shutdownConfirmed chan struct{}
	deletePeersCh     chan interface{}
	firstMessage      int
	lastMessage       int
}

// maxPeersCount defines the maximum number of supported peers that can have their messages waiting
// in the incoming message queue at the same time. This number can be lower then the actual number of
// connected peers, as it's used only for pending messages.
const maxPeersCount = 1024

// makeIncomingMessageQueue creates an incomingMessageQueue object and initializes all the internal variables.
func makeIncomingMessageQueue() *incomingMessageQueue {
	imq := &incomingMessageQueue{
		outboundPeerCh:    make(chan incomingMessage),
		enqueuedPeersMap:  make(map[*Peer]int, maxPeersCount),
		enqueuedMessages:  make([]incomingMessage, maxPeersCount),
		shutdownRequest:   make(chan struct{}, 1),
		shutdownConfirmed: make(chan struct{}, 1),
		deletePeersCh:     make(chan interface{}),
	}
	imq.enqueuedPeersCond = sync.NewCond(&imq.enqueuedPeersMu)
	go imq.messagePump()
	return imq
}

func (imq *incomingMessageQueue) shutdown() {
	imq.enqueuedPeersMu.Lock()
	close(imq.shutdownRequest)
	imq.enqueuedPeersCond.Signal()
	imq.enqueuedPeersMu.Unlock()
	<-imq.shutdownConfirmed
}

func (imq *incomingMessageQueue) messagePump() {
	defer close(imq.shutdownConfirmed)
	imq.enqueuedPeersMu.Lock()
	defer imq.enqueuedPeersMu.Unlock()

	for {
		// check if we need to shutdown.
		select {
		case <-imq.shutdownRequest:
			return
		default:
		}

		// do we have any item to enqueue ?
		if imq.firstMessage != imq.lastMessage {
			msg := imq.enqueuedMessages[imq.firstMessage]
			imq.firstMessage = (imq.firstMessage + 1) % len(imq.enqueuedMessages)
			if msg.peer != nil {
				delete(imq.enqueuedPeersMap, msg.peer)
			}

			imq.enqueuedPeersMu.Unlock()
		writeOutboundMessage:
			select {
			case imq.outboundPeerCh <- msg:
				imq.enqueuedPeersMu.Lock()
				continue
			case <-imq.shutdownRequest:
				imq.enqueuedPeersMu.Lock()
				return
			// see if this msg need to be delivered or not.
			case droppedPeer := <-imq.deletePeersCh:
				if msg.networkPeer == droppedPeer {
					// we want to skip this message.
					imq.enqueuedPeersMu.Lock()
					continue
				}
				goto writeOutboundMessage
			}
		}
		imq.enqueuedPeersCond.Wait()
	}
}

// getIncomingMessageChannel returns the incoming messages channel, which would contain entries once
// we have one ( or more ) pending incoming messages.
func (imq *incomingMessageQueue) getIncomingMessageChannel() <-chan incomingMessage {
	return imq.outboundPeerCh
}

// enqueue places the given message on the queue, if and only if it's associated peer doesn't
// appear on the incoming message queue already. In the case there is no peer, the message
// would be placed on the queue as is.
// The method returns false if the incoming message doesn't have it's peer on the queue and
// the method has failed to place the message on the queue. True is returned otherwise.
func (imq *incomingMessageQueue) enqueue(m incomingMessage) bool {
	imq.enqueuedPeersMu.Lock()
	defer imq.enqueuedPeersMu.Unlock()
	if m.peer != nil {
		if _, has := imq.enqueuedPeersMap[m.peer]; has {
			return true
		}
	}
	// do we have enough room in the message queue for the new message ?
	if imq.firstMessage == (imq.lastMessage+1)%len(imq.enqueuedMessages) {
		// no - we don't have enough room in the circular buffer.
		return false
	}
	imq.enqueuedMessages[imq.lastMessage] = m
	// if we successfully enqueued the message, set the enqueuedPeersMap so that we won't enqueue the same peer twice.
	if m.peer != nil {
		imq.enqueuedPeersMap[m.peer] = imq.lastMessage
	}
	imq.lastMessage = (imq.lastMessage + 1) % len(imq.enqueuedMessages)
	imq.enqueuedPeersCond.Signal()
	return true
}

// clear removes the peer that is associated with the message ( if any ) from
// the enqueuedPeers map, allowing future messages from this peer to be placed on the
// incoming message queue.
func (imq *incomingMessageQueue) clear(m incomingMessage) {
	if m.peer != nil {
		imq.enqueuedPeersMu.Lock()
		defer imq.enqueuedPeersMu.Unlock()
		delete(imq.enqueuedPeersMap, m.peer)
	}
}

// erase removes all the entries associated with the given network peer.
// this method isn't very efficient, and should be used only in cases where
// we disconnect from a peer and want to cleanup all the pending tasks associated
// with that peer.
func (imq *incomingMessageQueue) erase(peer *Peer, networkPeer interface{}) {
	imq.enqueuedPeersMu.Lock()

	var idxPeer int
	if peer == nil {
		// lookup for a Peer object.
		for peer, idxPeer = range imq.enqueuedPeersMap {
			if peer.networkPeer != networkPeer {
				continue
			}
			break
		}
	} else {
		var has bool
		if idxPeer, has = imq.enqueuedPeersMap[peer]; !has {
			// the peer object is not in the map.
			peer = nil
		}
	}

	if peer != nil {
		delete(imq.enqueuedPeersMap, peer)
		imq.removeMessageByIndex(idxPeer)
		imq.enqueuedPeersMu.Unlock()
		select {
		case imq.deletePeersCh <- networkPeer:
		default:
		}
		return
	}

	// rewrite the array by eliminating the network peer.
	adjustedIdx := imq.firstMessage
	for idx := imq.firstMessage; idx != imq.lastMessage; idx = (idx + 1) % len(imq.enqueuedMessages) {
		if imq.enqueuedMessages[idx].networkPeer == networkPeer {
			continue
		}
		imq.enqueuedMessages[adjustedIdx] = imq.enqueuedMessages[idx]
		adjustedIdx = (adjustedIdx + 1) % len(imq.enqueuedMessages)
	}
	imq.lastMessage = adjustedIdx
	imq.enqueuedPeersMu.Unlock()
	select {
	case imq.deletePeersCh <- networkPeer:
	default:
	}
}

func (imq *incomingMessageQueue) removeMessageByIndex(removeIdx int) {
	adjustedIdx := imq.firstMessage
	for idx := imq.firstMessage; idx != imq.lastMessage; idx = (idx + 1) % len(imq.enqueuedMessages) {
		if idx == removeIdx {
			continue
		}
		imq.enqueuedMessages[adjustedIdx] = imq.enqueuedMessages[idx]
		adjustedIdx = (adjustedIdx + 1) % len(imq.enqueuedMessages)
	}
	imq.lastMessage = adjustedIdx
}

func (imq *incomingMessageQueue) prunePeers(activePeers []PeerInfo) bool {
	activePeersMap := make(map[*Peer]bool)
	activeNetworkPeersMap := make(map[interface{}]bool)
	for _, activePeer := range activePeers {
		if activePeer.TxnSyncPeer != nil {
			activePeersMap[activePeer.TxnSyncPeer] = true
		}
		if activePeer.NetworkPeer != nil {
			activeNetworkPeersMap[activePeer.NetworkPeer] = true
		}
	}
	imq.enqueuedPeersMu.Lock()
	defer imq.enqueuedPeersMu.Unlock()

	adjustedIdx := imq.firstMessage
	for idx := imq.firstMessage; idx != imq.lastMessage; idx = (idx + 1) % len(imq.enqueuedMessages) {
		if imq.enqueuedMessages[idx].peer != nil {
			if !activePeersMap[imq.enqueuedMessages[idx].peer] {
				continue
			}
		}
		if imq.enqueuedMessages[idx].networkPeer != nil {
			if !activeNetworkPeersMap[imq.enqueuedMessages[idx].networkPeer] {
				continue
			}
		}
		imq.enqueuedMessages[adjustedIdx] = imq.enqueuedMessages[idx]
		adjustedIdx = (adjustedIdx + 1) % len(imq.enqueuedMessages)
	}
	imq.lastMessage = adjustedIdx
	return true
}
