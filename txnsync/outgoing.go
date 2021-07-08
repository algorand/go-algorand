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
	"errors"
	"sort"
	"time"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/util/timers"
)

const messageTimeWindow = 20 * time.Millisecond

var errTransactionSyncOutgoingMessageQueueFull = errors.New("transaction sync outgoing message queue is full")
var errTransactionSyncOutgoingMessageSendFailed = errors.New("transaction sync failed to send message")

// sentMessageMetadata is the message metadata for a message that is being sent. It includes some extra
// pieces of information about the message itself, used for tracking the "content" of the message beyond
// the point where it's being encoded.
type sentMessageMetadata struct {
	encodedMessageSize  int
	sentTranscationsIDs []transactions.Txid
	message             *transactionBlockMessage
	peer                *Peer
	sentTimestamp       time.Duration
	sequenceNumber      uint64
	partialMessage      bool
	filter              bloomFilter
	transactionGroups   []transactions.SignedTxGroup
}

// messageAsyncEncoder structure encapsulates the encoding and sending of a given message to the network. The encoding
// could be a lengthy operation which does't need to be blocking the main loop. Moving the actual encoding into an
// execution pool thread frees up the main loop, allowing smoother operation.
type messageAsyncEncoder struct {
	state                *syncState
	messageData          sentMessageMetadata
	roundClock           timers.WallClock
	peerDataExchangeRate uint64
}

// asyncMessageSent called via the network package to inform the txsync that a message was enqueued, and the associated sequence number.
func (encoder *messageAsyncEncoder) asyncMessageSent(enqueued bool, sequenceNumber uint64) error {
	if !enqueued {
		encoder.state.log.Infof("unable to send message to peer. disconnecting from peer.")
		return errTransactionSyncOutgoingMessageSendFailed
	}
	// record the timestamp here, before placing the entry on the queue
	encoder.messageData.sentTimestamp = encoder.roundClock.Since()
	encoder.messageData.sequenceNumber = sequenceNumber

	select {
	case encoder.state.outgoingMessagesCallbackCh <- encoder.messageData:
		return nil
	default:
		// if we can't place it on the channel, return an error so that the node could disconnect from this peer.
		encoder.state.log.Infof("unable to enqueue outgoing message confirmation; outgoingMessagesCallbackCh is full. disconnecting from peer.")
		return errTransactionSyncOutgoingMessageQueueFull
	}
}
func (encoder *messageAsyncEncoder) asyncEncodeAndSend(interface{}) interface{} {
	defer encoder.state.messageSendWaitGroup.Done()

	var err error
	if len(encoder.messageData.transactionGroups) > 0 {
		encoder.messageData.message.TransactionGroups, err = encoder.state.encodeTransactionGroups(encoder.messageData.transactionGroups, encoder.peerDataExchangeRate)
		if err != nil {
			encoder.state.log.Warnf("unable to encode transaction groups : %v", err)
		}
		encoder.messageData.transactionGroups = nil // clear out to allow GC to reclaim
	}

	encodedMessage := encoder.messageData.message.MarshalMsg(getMessageBuffer())
	encoder.messageData.encodedMessageSize = len(encodedMessage)
	// now that the message is ready, we can discard the encoded transcation group slice to allow the GC to collect it.
	releaseEncodedTransactionGroups(encoder.messageData.message.TransactionGroups.Bytes)

	encoder.state.node.SendPeerMessage(encoder.messageData.peer.networkPeer, encodedMessage, encoder.asyncMessageSent)
	releaseMessageBuffer(encodedMessage)

	encoder.messageData.message.TransactionGroups.Bytes = nil
	return nil
}

// enqueue add the given message encoding task to the execution pool, and increase the waitgroup as needed.
func (encoder *messageAsyncEncoder) enqueue() {
	encoder.state.messageSendWaitGroup.Add(1)
	if err := encoder.state.threadpool.EnqueueBacklog(context.Background(), encoder.asyncEncodeAndSend, nil, nil); err != nil {
		encoder.state.messageSendWaitGroup.Done()
	}
}

// pendingTransactionGroupsSnapshot is used to represent a snapshot of a pending transcation groups along with the latestLocallyOriginatedGroupCounter value.
// The goal is to ensure we're "capturing"  this only once per `sendMessageLoop` call. In order to do so, we allocate that structure on the stack, and passing
// a pointer to that structure downstream.
type pendingTransactionGroupsSnapshot struct {
	pendingTransactionsGroups           []transactions.SignedTxGroup
	latestLocallyOriginatedGroupCounter uint64
}

func (s *syncState) sendMessageLoop(currentTime time.Duration, deadline timers.DeadlineMonitor, peers []*Peer) {
	if len(peers) == 0 {
		// no peers - no messages that need to be sent.
		return
	}
	var pendingTransactions pendingTransactionGroupsSnapshot
	profGetTxnsGroups := s.profiler.getElement(profElementGetTxnsGroups)
	profAssembleMessage := s.profiler.getElement(profElementAssembleMessage)
	profGetTxnsGroups.start()
	pendingTransactions.pendingTransactionsGroups, pendingTransactions.latestLocallyOriginatedGroupCounter = s.node.GetPendingTransactionGroups()
	profGetTxnsGroups.end()
	for _, peer := range peers {
		msgEncoder := &messageAsyncEncoder{state: s, roundClock: s.clock, peerDataExchangeRate: peer.dataExchangeRate}
		profAssembleMessage.start()
		var err error
		msgEncoder.messageData, err = s.assemblePeerMessage(peer, &pendingTransactions)
		if err != nil {
			s.log.Errorf("failed to send peer msg: %v", err)
		}
		profAssembleMessage.end()
		isPartialMessage := msgEncoder.messageData.partialMessage
		msgEncoder.enqueue()

		scheduleOffset, ops := peer.getNextScheduleOffset(s.isRelay, s.lastBeta, isPartialMessage, currentTime)
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

func (s *syncState) assemblePeerMessage(peer *Peer, pendingTransactions *pendingTransactionGroupsSnapshot) (metaMessage sentMessageMetadata, err error) {
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
			metaMessage.message.UpdatedRequestParams.Offset = byte(uint64(offset) % uint64(modulator))
		}
	}

	if (msgOps&messageConstBloomFilter == messageConstBloomFilter) && len(pendingTransactions.pendingTransactionsGroups) > 0 {
		var lastBloomFilter *bloomFilter
		// for relays, where we send a full bloom filter to everyone, we want to coordinate that with a single
		// copy of the bloom filter, to prevent re-creation.
		if s.isRelay {
			lastBloomFilter = &s.lastBloomFilter
		} else {
			// for peers, we want to make sure we don't regenerate the same bloom filter as before.
			lastBloomFilter = &peer.lastSentBloomFilter
		}
		profMakeBloomFilter := s.profiler.getElement(profElementMakeBloomFilter)
		profMakeBloomFilter.start()
		// generate a bloom filter that matches the requests params.
		metaMessage.filter = s.makeBloomFilter(metaMessage.message.UpdatedRequestParams, pendingTransactions.pendingTransactionsGroups, lastBloomFilter)
		if !metaMessage.filter.sameParams(peer.lastSentBloomFilter) {
			bf, _ := metaMessage.filter.encode()
			metaMessage.message.TxnBloomFilter = *bf
			bloomFilterSize = metaMessage.message.TxnBloomFilter.Msgsize()
		}
		profMakeBloomFilter.end()
		s.lastBloomFilter = metaMessage.filter
	}

	if msgOps&messageConstTransactions == messageConstTransactions {
		transactionGroups := pendingTransactions.pendingTransactionsGroups
		if !s.isRelay {
			// on non-relay, we need to filter out the non-locally originated messages since we don't want
			// non-relays to send transcation that they received via the transaction sync back.
			transactionGroups = s.locallyGeneratedTransactions(pendingTransactions)
		}

		profTxnsSelection := s.profiler.getElement(profElementTxnsSelection)
		profTxnsSelection.start()
		metaMessage.transactionGroups, metaMessage.sentTranscationsIDs, metaMessage.partialMessage = peer.selectPendingTransactions(transactionGroups, messageTimeWindow, s.round, bloomFilterSize)
		profTxnsSelection.end()

		// clear the last sent bloom filter on the end of a series of partial messages.
		// this would ensure we generate a new bloom filter every beta, which is needed
		// in order to avoid the bloom filter inherent false positive rate.
		if !metaMessage.partialMessage {
			peer.lastSentBloomFilter = bloomFilter{}
		}
	}

	metaMessage.message.MsgSync.RefTxnBlockMsgSeq = peer.nextReceivedMessageSeq - 1
	if peer.lastReceivedMessageTimestamp != 0 && peer.lastReceivedMessageLocalRound == s.round {
		metaMessage.message.MsgSync.ResponseElapsedTime = uint64((s.clock.Since() - peer.lastReceivedMessageTimestamp).Nanoseconds())
	}
	// use the messages seq number that we've accepted so far, and let the other peer
	// know about them. The getAcceptedMessages would delete the returned list from the peer's storage before
	// returning.
	metaMessage.message.MsgSync.AcceptedMsgSeq = peer.getAcceptedMessages()

	if msgOps&messageConstNextMinDelay == messageConstNextMinDelay {
		metaMessage.message.MsgSync.NextMsgMinDelay = uint64(s.lastBeta.Nanoseconds()) * 2
	}
	return
}

func (s *syncState) evaluateOutgoingMessage(msgData sentMessageMetadata) {
	msgData.peer.updateMessageSent(msgData.message, msgData.sentTranscationsIDs, msgData.sentTimestamp, msgData.sequenceNumber, msgData.encodedMessageSize, msgData.filter)
	s.log.outgoingMessage(msgStats{msgData.sequenceNumber, msgData.message.Round, len(msgData.sentTranscationsIDs), msgData.message.UpdatedRequestParams, len(msgData.message.TxnBloomFilter.BloomFilter), msgData.message.MsgSync.NextMsgMinDelay, msgData.peer.networkAddress()})
}

// locallyGeneratedTransactions return a subset of the given transactionGroups array by filtering out transactions that are not locally generated.
func (s *syncState) locallyGeneratedTransactions(pendingTransactions *pendingTransactionGroupsSnapshot) (result []transactions.SignedTxGroup) {
	if pendingTransactions.latestLocallyOriginatedGroupCounter == transactions.InvalidSignedTxGroupCounter || len(pendingTransactions.pendingTransactionsGroups) == 0 {
		return []transactions.SignedTxGroup{}
	}
	n := sort.Search(len(pendingTransactions.pendingTransactionsGroups), func(i int) bool {
		return pendingTransactions.pendingTransactionsGroups[i].GroupCounter >= pendingTransactions.latestLocallyOriginatedGroupCounter
	})
	if n == len(pendingTransactions.pendingTransactionsGroups) {
		n--
	}
	result = make([]transactions.SignedTxGroup, n+1)

	count := 0
	for i := 0; i <= n; i++ {
		txnGroup := pendingTransactions.pendingTransactionsGroups[i]
		if !txnGroup.LocallyOriginated {
			continue
		}
		result[count] = txnGroup
		count++
	}
	return result[:count]
}
