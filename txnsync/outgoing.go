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
	"fmt"
	"github.com/algorand/go-algorand/util/timers"
	"time"

	"github.com/algorand/go-algorand/data/transactions"
)

var _ = fmt.Printf

const messageTimeWindow = 20 * time.Millisecond

var outgoingTxSyncMsgFormat = "Outgoing Txsync #%d round %d transacations %d request [%d/%d] bloom %d nextTS %d"

type sentMessageMetadata struct {
	encodedMessageSize  int
	sentTranscationsIDs []transactions.Txid
	message             *transactionBlockMessage
	peer                *Peer
	sentTimestamp       time.Duration
	sequenceNumber      uint64
	partialMessage      bool
	filter              bloomFilter
}

type messageSentCallback struct {
	state       *syncState
	messageData sentMessageMetadata
}

// asyncMessageSent called via the network package to inform the txsync that a message was enqueued, and the associated sequence number.
func (msc *messageSentCallback) asyncMessageSent(enqueued bool, sequenceNumber uint64) {
	if !enqueued {
		return
	}
	// record the timestamp here, before placing the entry on the queue
	msc.messageData.sentTimestamp = msc.state.clock.Since()
	msc.messageData.sequenceNumber = sequenceNumber

	select {
	case msc.state.outgoingMessagesCallbackCh <- msc:
	default:
		// if we can't place it on the channel, just let it drop and log it.
	}
}

func (s *syncState) sendMessageLoop(currentTime time.Duration, deadline timers.DeadlineMonitor, peers []*Peer) {
	if len(peers) == 0 {
		// no peers - no messages that need to be sent.
		return
	}
	pendingTransactionGroups := s.node.GetPendingTransactionGroups()

	for _, peer := range peers {
		msgCallback := &messageSentCallback{state: s}
		msgCallback.messageData = s.assemblePeerMessage(peer, pendingTransactionGroups, currentTime)
		encodedMessage := msgCallback.messageData.message.MarshalMsg([]byte{})
		msgCallback.messageData.encodedMessageSize = len(encodedMessage)
		s.node.SendPeerMessage(peer.networkPeer, encodedMessage, msgCallback.asyncMessageSent)

		scheduleOffset, ops := peer.getNextScheduleOffset(s.isRelay, s.lastBeta, msgCallback.messageData.partialMessage, currentTime)
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
			s.scheduler.schedulerPeer(peer, currentTime+scheduleOffset)
		}

		if deadline.Expired() {
			// we ran out of time sending messages, stop sending any more messages.
			break
		}
	}
}

func (s *syncState) assemblePeerMessage(peer *Peer, pendingTransactions []transactions.SignedTxGroup, currentTime time.Duration) (metaMessage sentMessageMetadata) {
	metaMessage = sentMessageMetadata{
		peer: peer,
		message: &transactionBlockMessage{
			Version: txnBlockMessageVersion,
			Round:   s.round,
		},
	}

	bloomFilterSize := 0

	msgOps := peer.getMessageConstructionOps(s.isRelay, s.fetchTransactions)

	if msgOps&messageConstUpdateRequestParams == messageConstUpdateRequestParams {
		// update the UpdatedRequestParams
		offset, modulator := peer.getLocalRequestParams()
		metaMessage.message.UpdatedRequestParams.Modulator = modulator
		if modulator > 0 {
			// for relays, the modulator is always one, which means the following would always be zero.
			metaMessage.message.UpdatedRequestParams.Offset = byte((s.requestsOffset + uint64(offset)) % uint64(modulator))
		}
	}

	if (msgOps&messageConstBloomFilter == messageConstBloomFilter) && len(pendingTransactions) > 0 {
		// generate a bloom filter that matches the requests params.
		metaMessage.filter = makeBloomFilter(metaMessage.message.UpdatedRequestParams, pendingTransactions, uint32(s.node.Random(0xffffffff)))
		if !metaMessage.filter.compare(peer.lastSentBloomFilter) {
			metaMessage.message.TxnBloomFilter = metaMessage.filter.encode()
			bloomFilterSize = metaMessage.message.TxnBloomFilter.Msgsize()
		}
	}

	if msgOps&messageConstTransactions == messageConstTransactions {
		if !s.isRelay {
			// on non-relay, we need to filter out the non-locally originated messages since we don't want
			// non-relays to send transcation that they received via the transaction sync back.
			pendingTransactions = locallyGeneratedTransactions(pendingTransactions)
		}
		var txnGroups []transactions.SignedTxGroup
		txnGroups, metaMessage.sentTranscationsIDs, metaMessage.partialMessage = peer.selectPendingTransactions(pendingTransactions, messageTimeWindow, s.round, bloomFilterSize)
		metaMessage.message.TransactionGroups.Bytes = encodeTransactionGroups(txnGroups)

		// clear the last sent bloom filter on the end of a series of partial messages.
		// this would ensure we generate a new bloom filter every beta, which is needed
		// in order to avoid the bloom filter inherent false positive rate.
		if !metaMessage.partialMessage {
			peer.lastSentBloomFilter = bloomFilter{}
		}
	}

	metaMessage.message.MsgSync.RefTxnBlockMsgSeq = peer.nextReceivedMessageSeq - 1
	if peer.lastReceivedMessageTimestamp != 0 && peer.lastReceivedMessageLocalRound == s.round {
		metaMessage.message.MsgSync.ResponseElapsedTime = uint64((currentTime - peer.lastReceivedMessageTimestamp).Nanoseconds())
	}

	if msgOps&messageConstNextMinDelay == messageConstNextMinDelay {
		metaMessage.message.MsgSync.NextMsgMinDelay = uint64(s.lastBeta.Nanoseconds()) * 2
	}

	return metaMessage
}

func (s *syncState) evaluateOutgoingMessage(msg *messageSentCallback) {
	msgData := msg.messageData
	msgData.peer.updateMessageSent(msgData.message, msgData.sentTranscationsIDs, msgData.sentTimestamp, msgData.sequenceNumber, msgData.encodedMessageSize, msgData.filter)
	s.log.Infof(outgoingTxSyncMsgFormat, msgData.sequenceNumber, msgData.message.Round, len(msgData.sentTranscationsIDs), msgData.message.UpdatedRequestParams.Offset, msgData.message.UpdatedRequestParams.Modulator, len(msgData.message.TxnBloomFilter.BloomFilter), msgData.message.MsgSync.NextMsgMinDelay)
	//s.log.Infof("outgoing message %v \n", msgData.message.MsgSync.NextMsgMinDelay)
}

// locallyGeneratedTransactions return a subset of the given transactionGroups array by filtering out transactions that are not locally generated.
func locallyGeneratedTransactions(transactionGroups []transactions.SignedTxGroup) (result []transactions.SignedTxGroup) {
	result = make([]transactions.SignedTxGroup, len(transactionGroups))
	count := 0
	for _, txnGroup := range transactionGroups {
		if txnGroup.LocallyOriginated {
			result[count] = txnGroup
			count++
		}
	}
	return result[:count]
}
