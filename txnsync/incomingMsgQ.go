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

// queuedMsgEntry used as a helper struct to manage the manipulation of incoming
// message queue.
type queuedMsgEntry struct {
	msg  incomingMessage
	next *queuedMsgEntry
	prev *queuedMsgEntry
}

type queuedMsgList struct {
	head *queuedMsgEntry
}

// incomingMessageQueue manages the global incoming message queue across all the incoming peers.
type incomingMessageQueue struct {
	outboundPeerCh    chan incomingMessage
	enqueuedPeersMap  map[*Peer]*queuedMsgEntry
	messages          queuedMsgList
	freelist          queuedMsgList
	enqueuedPeersMu   deadlock.Mutex
	enqueuedPeersCond *sync.Cond
	shutdownRequest   chan struct{}
	shutdownConfirmed chan struct{}
	deletePeersCh     chan interface{}
	peerlessCount     int
}

// maxPeersCount defines the maximum number of supported peers that can have their messages waiting
// in the incoming message queue at the same time. This number can be lower then the actual number of
// connected peers, as it's used only for pending messages.
const maxPeersCount = 2048

// maxPeerlessCount is the number of messages that we've received that doesn't have a Peer object allocated
// for them ( yet )
const maxPeerlessCount = 512

// makeIncomingMessageQueue creates an incomingMessageQueue object and initializes all the internal variables.
func makeIncomingMessageQueue() *incomingMessageQueue {
	imq := &incomingMessageQueue{
		outboundPeerCh:    make(chan incomingMessage),
		enqueuedPeersMap:  make(map[*Peer]*queuedMsgEntry, maxPeersCount),
		shutdownRequest:   make(chan struct{}, 1),
		shutdownConfirmed: make(chan struct{}, 1),
		deletePeersCh:     make(chan interface{}),
	}
	imq.enqueuedPeersCond = sync.NewCond(&imq.enqueuedPeersMu)
	imq.freelist.initialize(maxPeersCount)
	go imq.messagePump()
	return imq
}

// dequeueHead removes the first head message from the linked list.
func (ml *queuedMsgList) dequeueHead() (out *queuedMsgEntry) {
	if ml.head == nil {
		return nil
	}
	entry := ml.head
	out = entry
	if entry.next == entry {
		ml.head = nil
		return
	}
	entry.next.prev = entry.prev
	entry.prev.next = entry.next
	ml.head = entry.next
	out.next = out
	out.prev = out
	return
}

// dequeueHead initialize a list to have msgCount entries.
func (ml *queuedMsgList) initialize(msgCount int) {
	msgs := make([]queuedMsgEntry, msgCount)
	for i := 0; i < msgCount; i++ {
		msgs[i].next = &msgs[(i+1)%msgCount]
		msgs[i].prev = &msgs[(i+msgCount-1)%msgCount]
	}
	ml.head = &msgs[0]
}

// empty methods tests to see if the linked list is empty
func (ml *queuedMsgList) empty() bool {
	return ml.head == nil
}

// remove removes the given msg from the linked list. The method
// is written with the assumption that the given msg is known to be
// part of the linked list.
func (ml *queuedMsgList) remove(msg *queuedMsgEntry) {
	if msg.next == msg {
		ml.head = nil
		return
	}
	msg.prev.next = msg.next
	msg.next.prev = msg.prev
	if ml.head == msg {
		ml.head = msg.next
	}
	msg.prev = msg
	msg.next = msg
	return
}

// filterRemove removes zero or more messages from the linked list, for which the given
// removeFunc returns true. The removed linked list entries are returned as a linked list.
func (ml *queuedMsgList) filterRemove(removeFunc func(*queuedMsgEntry) bool) *queuedMsgEntry {
	if ml.empty() {
		return nil
	}
	// do we have a single item ?
	if ml.head.next == ml.head {
		if removeFunc(ml.head) {
			out := ml.head
			ml.head = nil
			return out
		}
		return nil
	}
	current := ml.head
	last := ml.head.prev
	var letGo queuedMsgList
	for {
		next := current.next
		if removeFunc(current) {
			ml.remove(current)
			letGo.enqueueTail(current)
		}
		if current == last {
			break
		}
		current = next
	}
	return letGo.head
}

// enqueueTail adds to the current linked list another linked list whose head is msg.
func (ml *queuedMsgList) enqueueTail(msg *queuedMsgEntry) {
	if ml.head == nil {
		ml.head = msg
		return
	} else if msg == nil {
		return
	}
	lastEntryOld := ml.head.prev
	lastEntryNew := msg.prev
	lastEntryOld.next = msg
	ml.head.prev = lastEntryNew
	msg.prev = lastEntryOld
	lastEntryNew.next = ml.head
}

// shutdown signals to the message pump to shut down and waits until the message pump goroutine
// aborts.
func (imq *incomingMessageQueue) shutdown() {
	imq.enqueuedPeersMu.Lock()
	close(imq.shutdownRequest)
	imq.enqueuedPeersCond.Signal()
	imq.enqueuedPeersMu.Unlock()
	<-imq.shutdownConfirmed
}

// messagePump is the incoming message queue message pump. It takes messages from the messages list
// and attempt to write these to the outboundPeerCh.
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
		if !imq.messages.empty() {
			msgEntry := imq.messages.dequeueHead()
			msg := msgEntry.msg
			imq.freelist.enqueueTail(msgEntry)
			if msg.peer != nil {
				delete(imq.enqueuedPeersMap, msg.peer)
			} else {
				imq.peerlessCount--
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
	} else {
		// do we have enough "room" for peerless messages ?
		if imq.peerlessCount >= maxPeerlessCount {
			return false
		}
	}
	// do we have enough room in the message queue for the new message ?
	if imq.freelist.empty() {
		// no - we don't have enough room in the circular buffer.
		return false
	}
	freeMsgEntry := imq.freelist.dequeueHead()
	freeMsgEntry.msg = m
	imq.messages.enqueueTail(freeMsgEntry)
	// if we successfully enqueued the message, set the enqueuedPeersMap so that we won't enqueue the same peer twice.
	if m.peer != nil {
		imq.enqueuedPeersMap[m.peer] = freeMsgEntry
	} else {
		imq.peerlessCount++
	}
	imq.enqueuedPeersCond.Signal()
	return true
}

// erase removes all the entries associated with the given network peer.
// this method isn't very efficient, and should be used only in cases where
// we disconnect from a peer and want to cleanup all the pending tasks associated
// with that peer.
func (imq *incomingMessageQueue) erase(peer *Peer, networkPeer interface{}) {
	imq.enqueuedPeersMu.Lock()

	var peerMsgEntry *queuedMsgEntry
	if peer == nil {
		// lookup for a Peer object.
		for peer, peerMsgEntry = range imq.enqueuedPeersMap {
			if peer.networkPeer != networkPeer {
				continue
			}
			break
		}
	} else {
		var has bool
		if peerMsgEntry, has = imq.enqueuedPeersMap[peer]; !has {
			// the peer object is not in the map.
			peer = nil
		}
	}

	if peer != nil {
		delete(imq.enqueuedPeersMap, peer)
		imq.messages.remove(peerMsgEntry)
		imq.freelist.enqueueTail(peerMsgEntry)
		imq.enqueuedPeersMu.Unlock()
		select {
		case imq.deletePeersCh <- networkPeer:
		default:
		}
		return
	}

	imq.removeMessageByNetworkPeer(networkPeer)
	imq.enqueuedPeersMu.Unlock()
	select {
	case imq.deletePeersCh <- networkPeer:
	default:
	}
}

// removeMessageByNetworkPeer removes the messages associated with the given network peer from the
// queue.
// note : the method expect that the enqueuedPeersMu lock would be taken.
func (imq *incomingMessageQueue) removeMessageByNetworkPeer(networkPeer interface{}) {
	peerlessCount := 0
	removeByNetworkPeer := func(msg *queuedMsgEntry) bool {
		if msg.msg.networkPeer == networkPeer {
			if msg.msg.peer == nil {
				peerlessCount++
			}
			return true
		}
		return false
	}
	removeList := imq.messages.filterRemove(removeByNetworkPeer)
	imq.freelist.enqueueTail(removeList)
	imq.peerlessCount -= peerlessCount
}

// prunePeers removes from the enqueuedMessages queue all the entries that are not provided in the
// given activePeers slice.
func (imq *incomingMessageQueue) prunePeers(activePeers []PeerInfo) (peerRemoved bool) {
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
	peerlessCount := 0
	isPeerMissing := func(msg *queuedMsgEntry) bool {
		if msg.msg.peer != nil {
			if !activePeersMap[msg.msg.peer] {
				return true
			}
		}
		if !activeNetworkPeersMap[msg.msg.networkPeer] {
			if msg.msg.peer == nil {
				peerlessCount++
			}
			return true
		}
		return false
	}
	removeList := imq.messages.filterRemove(isPeerMissing)
	peerRemoved = removeList != nil
	imq.freelist.enqueueTail(removeList)
	imq.peerlessCount -= peerlessCount
	return
}
