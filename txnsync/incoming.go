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
	"errors"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/transactions"
)

var (
	errUnsupportedTransactionSyncMessageVersion = errors.New("unsupported transaction sync message version")
	errTransactionSyncIncomingMessageQueueFull  = errors.New("transaction sync incoming message queue is full")
	errInvalidBloomFilter                       = errors.New("invalid bloom filter")
	errDecodingReceivedTransactionGroupsFailed  = errors.New("failed to decode incoming transaction groups")
)

type incomingMessage struct {
	networkPeer       interface{}
	message           transactionBlockMessage
	sequenceNumber    uint64
	peer              *Peer
	encodedSize       int
	bloomFilter       bloomFilter
	transactionGroups []transactions.SignedTxGroup
}

// incomingMessageQueue manages the global incoming message queue across all the incoming peers.
type incomingMessageQueue struct {
	incomingMessages chan incomingMessage
	enqueuedPeers    map[*Peer]struct{}
	enqueuedPeersMu  deadlock.Mutex
}

// maxPeersCount defines the maximum number of supported peers that can have their messages waiting
// in the incoming message queue at the same time. This number can be lower then the actual number of
// connected peers, as it's used only for pending messages.
const maxPeersCount = 1024

// makeIncomingMessageQueue creates an incomingMessageQueue object and initializes all the internal variables.
func makeIncomingMessageQueue() incomingMessageQueue {
	return incomingMessageQueue{
		incomingMessages: make(chan incomingMessage, maxPeersCount),
		enqueuedPeers:    make(map[*Peer]struct{}, maxPeersCount),
	}
}

// getIncomingMessageChannel returns the incoming messages channel, which would contain entries once
// we have one ( or more ) pending incoming messages.
func (imq *incomingMessageQueue) getIncomingMessageChannel() <-chan incomingMessage {
	return imq.incomingMessages
}

// enqueue places the given message on the queue, if and only if it's associated peer doesn't
// appear on the incoming message queue already. In the case there is no peer, the message
// would be placed on the queue as is.
func (imq *incomingMessageQueue) enqueue(m incomingMessage) bool {
	if m.peer != nil {
		imq.enqueuedPeersMu.Lock()
		defer imq.enqueuedPeersMu.Unlock()
		if _, has := imq.enqueuedPeers[m.peer]; has {
			return true
		}
	}
	select {
	case imq.incomingMessages <- m:
		// if we successfully enqueued the message, set the enqueuedPeers so that we won't enqueue the same peer twice.
		if m.peer != nil {
			// at this time, the enqueuedPeersMu is still under lock ( due to the above defer ), so we can access
			// the enqueuedPeers here.
			imq.enqueuedPeers[m.peer] = struct{}{}
		}
		return true
	default:
		return false
	}
}

// clear removes the peer that is associated with the message ( if any ) from
// the enqueuedPeers map, allowing future messages from this peer to be placed on the
// incoming message queue.
func (imq *incomingMessageQueue) clear(m incomingMessage) {
	if m.peer != nil {
		imq.enqueuedPeersMu.Lock()
		defer imq.enqueuedPeersMu.Unlock()
		delete(imq.enqueuedPeers, m.peer)
	}
}

// incomingMessageHandler
// note - this message is called by the network go-routine dispatch pool, and is not syncronized with the rest of the transaction syncronizer
func (s *syncState) asyncIncomingMessageHandler(networkPeer interface{}, peer *Peer, message []byte, sequenceNumber uint64) error {
	incomingMessage := incomingMessage{networkPeer: networkPeer, sequenceNumber: sequenceNumber, encodedSize: len(message), peer: peer}
	_, err := incomingMessage.message.UnmarshalMsg(message)
	if err != nil {
		// if we recieved a message that we cannot parse, disconnect.
		s.log.Infof("received unparsable transaction sync message from peer. disconnecting from peer.")
		return err
	}

	if incomingMessage.message.Version != txnBlockMessageVersion {
		// we receive a message from a version that we don't support, disconnect.
		s.log.Infof("received unsupported transaction sync message version from peer. disconnecting from peer.")
		return errUnsupportedTransactionSyncMessageVersion
	}

	// if the peer sent us a bloom filter, decode it
	if incomingMessage.message.TxnBloomFilter.BloomFilterType != 0 {
		bloomFilter, err := decodeBloomFilter(incomingMessage.message.TxnBloomFilter)
		if err != nil {
			s.log.Infof("Invalid bloom filter received from peer : %v", err)
			return errInvalidBloomFilter
		}
		incomingMessage.bloomFilter = bloomFilter
	}

	// if the peer sent us any transactions, decode these.
	incomingMessage.transactionGroups, err = decodeTransactionGroups(incomingMessage.message.TransactionGroups, s.genesisID, s.genesisHash)
	if err != nil {
		s.log.Infof("failed to decode received transactions groups: %v\n", err)
		return errDecodingReceivedTransactionGroupsFailed
	}

	if peer == nil {
		// if we don't have a peer, then we need to enqueue this task to be handled by the main loop since we want to ensure that
		// all the peer objects are created synchronously.
		enqueued := s.incomingMessagesQ.enqueue(incomingMessage)
		if !enqueued {
			// if we can't enqueue that, return an error, which would disconnect the peer.
			// ( we have to disconnect, since otherwise, we would have no way to syncronize the sequence number)
			s.log.Infof("unable to enqueue incoming message from a peer without txsync allocated data; incoming messages queue is full. disconnecting from peer.")
			return errTransactionSyncIncomingMessageQueueFull
		}
		return nil
	}
	// place the incoming message on the *peer* heap, allowing us to dequeue it in the correct sequence order.
	err = peer.incomingMessages.enqueue(incomingMessage)
	if err != nil {
		// if the incoming message queue for this peer is full, disconnect from this peer.
		s.log.Infof("unable to enqueue incoming message into peer incoming message backlog. disconnecting from peer.")
		return err
	}

	// (maybe) place the peer message on the main queue. This would get skipped if the peer is already on the queue.
	enqueued := s.incomingMessagesQ.enqueue(incomingMessage)
	if !enqueued {
		// if we can't enqueue that, return an error, which would disconnect the peer.
		s.log.Infof("unable to enqueue incoming message from a peer with txsync allocated data; incoming messages queue is full. disconnecting from peer.")
		return errTransactionSyncIncomingMessageQueueFull
	}
	return nil
}

func (s *syncState) evaluateIncomingMessage(message incomingMessage) {
	peer := message.peer
	if peer == nil {
		// check if a peer was created already for this network peer object.
		peerInfo := s.node.GetPeer(message.networkPeer)
		if peerInfo.NetworkPeer == nil {
			// the message.networkPeer isn't a valid unicast peer, so we can exit right here.
			return
		}
		if peerInfo.TxnSyncPeer == nil {
			// we couldn't really do much about this message previously, since we didn't have the peer.
			peer = makePeer(message.networkPeer, peerInfo.IsOutgoing, s.isRelay)
			// let the network peer object know about our peer
			s.node.UpdatePeers([]*Peer{peer}, []interface{}{message.networkPeer})
		} else {
			peer = peerInfo.TxnSyncPeer
		}
		message.peer = peer
		err := peer.incomingMessages.enqueue(message)
		if err != nil {
			// this is not really likely, since we won't saturate the peer heap right after creating it..
			return
		}
	}
	// clear the peer that is associated with this incoming message from the message queue, allowing future
	// messages from the peer to be placed on the message queue.
	s.incomingMessagesQ.clear(message)
	messageProcessed := false
	transacationPoolSize := 0
	for {
		seq, err := peer.incomingMessages.peekSequence()
		if err != nil {
			// this is very likely, once we run out of consecutive messages.
			break
		}
		if seq != peer.nextReceivedMessageSeq {
			// if we recieve a message which wasn't in-order, just let it go.
			s.log.Debugf("received message out of order; seq = %d, expecting seq = %d\n", seq, peer.nextReceivedMessageSeq)
			break
		}

		incomingMsg, err := peer.incomingMessages.pop()
		if err != nil {
			// if the queue is empty ( not expected, since we peek'ed into it before ), then we can't do much here.
			return
		}

		// increase the message sequence number, since we're processing this message.
		peer.nextReceivedMessageSeq++

		// update the round number if needed.
		if incomingMsg.message.Round > peer.lastRound {
			peer.lastRound = incomingMsg.message.Round
		} else if incomingMsg.message.Round < peer.lastRound {
			// peer sent us message for an older round, *after* a new round ?!
			continue
		}

		// if the peer sent us a bloom filter, store this.
		if (incomingMsg.bloomFilter != bloomFilter{}) {
			peer.addIncomingBloomFilter(incomingMsg.message.Round, incomingMsg.bloomFilter, s.round)
		}

		peer.updateRequestParams(incomingMsg.message.UpdatedRequestParams.Modulator, incomingMsg.message.UpdatedRequestParams.Offset)
		peer.updateIncomingMessageTiming(incomingMsg.message.MsgSync, s.round, s.clock.Since(), incomingMsg.encodedSize)

		// if the peer's round is more than a single round behind the local node, then we don't want to
		// try and load the transactions. The other peer should first catch up before getting transactions.
		if (peer.lastRound + 1) < s.round {
			s.log.Infof("Incoming Txsync #%d late round %d", seq, peer.lastRound)
			continue
		}

		// add the received transaction groups to the peer's recentSentTransactions so that we won't be sending these back to the peer.
		peer.updateIncomingTransactionGroups(incomingMsg.transactionGroups)

		// before enqueing more data to the transaction pool, make sure we flush the ack channel
		peer.dequeuePendingTransactionPoolAckMessages()

		// if we recieved at least a single transaction group, then forward it to the transaction handler.
		if len(incomingMsg.transactionGroups) > 0 {
			// send the incoming transaction group to the node last, so that the txhandler could modify the underlaying array if needed.
			transacationPoolSize = s.node.IncomingTransactionGroups(peer, peer.nextReceivedMessageSeq-1, incomingMsg.transactionGroups)
		}

		s.log.incomingMessage(msgStats{seq, incomingMsg.message.Round, len(incomingMsg.transactionGroups), incomingMsg.message.UpdatedRequestParams, len(incomingMsg.message.TxnBloomFilter.BloomFilter), incomingMsg.message.MsgSync.NextMsgMinDelay, peer.networkAddress()})
		messageProcessed = true
	}
	// if we're a relay, this is an outgoing peer and we've processed a valid message,
	// then we want to respond right away as well as schedule bloom message.
	if messageProcessed && peer.isOutgoing && s.isRelay && peer.lastReceivedMessageNextMsgMinDelay != time.Duration(0) {
		peer.state = peerStateStartup
		// if we had another message coming from this peer previously, we need to ensure there are not scheduled tasks.
		s.scheduler.peerDuration(peer)

		s.scheduler.schedulerPeer(peer, s.clock.Since())
	}
	if transacationPoolSize > 0 {
		s.onTransactionPoolChangedEvent(MakeTranscationPoolChangeEvent(transacationPoolSize))
	}
}
