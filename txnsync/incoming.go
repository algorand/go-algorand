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
)

var errUnsupportedTransactionSyncMessageVersion = errors.New("unsupported transaction sync message version")

type incomingMessage struct {
	networkPeer    interface{}
	message        transactionBlockMessage
	sequenceNumber uint64
	peer           *Peer
	encodedSize    int
}

// incomingMessageHandler
// note - this message is called by the network go-routine dispatch pool, and is not syncronized with the rest of the transaction syncronizer
func (s *syncState) asyncIncomingMessageHandler(networkPeer interface{}, peer *Peer, message []byte, sequenceNumber uint64) error {
	var txMsg transactionBlockMessage
	_, err := txMsg.UnmarshalMsg(message)
	if err != nil {
		// if we recieved a message that we cannot parse, disconnect.
		return err
	}
	if txMsg.Version != txnBlockMessageVersion {
		// we receive a message from a version that we don't support, disconnect.
		return errUnsupportedTransactionSyncMessageVersion
	}
	if peer == nil {
		// if we don't have a peer, then we need to enqueue this task to be handled by the main loop since we want to ensure that
		// all the peer objects are created syncroniously.
		select {
		case s.incomingMessagesCh <- incomingMessage{networkPeer: networkPeer, message: txMsg, sequenceNumber: sequenceNumber, encodedSize: len(message)}:
		default:
			// todo - handle the case where we can't write to the channel.
		}
		return nil
	}
	err = peer.incomingMessages.enqueue(txMsg, sequenceNumber, len(message))
	if err != nil {
		return err
	}

	select {
	case s.incomingMessagesCh <- incomingMessage{peer: peer}:
	default:
		// todo - handle the case where we can't write to the channel.
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
		err := peer.incomingMessages.enqueue(message.message, message.sequenceNumber, message.encodedSize)
		if err != nil {
			// this is not really likely, since we won't saturate the peer heap right after creating it..
			return
		}
	}
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
			//fmt.Printf("received message out of order; seq = %d, expecting seq = %d\n", seq, peer.nextReceivedMessageSeq)
			break
		}
		txMsg, encodedSize, err := peer.incomingMessages.pop()
		if err != nil {
			// if the queue is empty ( not expected, since we peek'ed into it before ), then we can't do much here.
			return
		}

		// increase the message sequence number, since we're processing this message.
		peer.nextReceivedMessageSeq++

		// update the round number if needed.
		if txMsg.Round > peer.lastRound {
			peer.lastRound = txMsg.Round
		} else if txMsg.Round < peer.lastRound {
			// peer sent us message for an older round, *after* a new round ?!
			continue
		}

		// if the peer sent us a bloom filter, store this.
		if txMsg.TxnBloomFilter.BloomFilterType != 0 {
			bloomFilter, err := decodeBloomFilter(txMsg.TxnBloomFilter)
			if err == nil {
				peer.addIncomingBloomFilter(txMsg.Round, bloomFilter, s.round)
			} else {
				panic(err)
			}
		}
		peer.updateRequestParams(txMsg.UpdatedRequestParams.Modulator, txMsg.UpdatedRequestParams.Offset)
		peer.updateIncomingMessageTiming(txMsg.MsgSync, s.round, s.clock.Since(), encodedSize)

		// if the peer's round is more than a single round behind the local node, then we don't want to
		// try and load the transactions. The other peer should first catch up before getting transactions.
		if (peer.lastRound + 1) < s.round {
			s.log.Info("Incoming Txsync #%d late round %d", seq, peer.lastRound)
			continue
		}
		txnGroups, err := decodeTransactionGroups(txMsg.TransactionGroups.Bytes)
		if err != nil {
			s.log.Warn("received transactions groups failed %v\n", err)
			continue
		}

		transacationPoolSize = s.node.IncomingTransactionGroups(peer.networkPeer, txnGroups)

		// add the received transaction groups to the peer's recentSentTransactions so that we won't be sending these back to the peer.
		peer.updateIncomingTransactionGroups(txnGroups)

		s.log.incomingMessage(msgStats{seq, txMsg.Round, len(txnGroups), txMsg.UpdatedRequestParams, len(txMsg.TxnBloomFilter.BloomFilter), txMsg.MsgSync.NextMsgMinDelay, peer.networkAddress()})
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
