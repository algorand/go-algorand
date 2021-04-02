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
	"sort"
	"time"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/util/timers"
)

var errTransactionSyncOutgoingMessageQueueFull = errors.New("transaction sync outgoing message queue is full")

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
	roundClock  timers.WallClock
}

// asyncMessageSent called via the network package to inform the txsync that a message was enqueued, and the associated sequence number.
func (msc *messageSentCallback) asyncMessageSent(enqueued bool, sequenceNumber uint64) error {
	if !enqueued {
		return nil
	}
	// record the timestamp here, before placing the entry on the queue
	msc.messageData.sentTimestamp = msc.roundClock.Since()
	msc.messageData.sequenceNumber = sequenceNumber

	select {
	case msc.state.outgoingMessagesCallbackCh <- msc:
	default:
		// if we can't place it on the channel, return an error so that the node could disconnect from this peer.
		msc.state.log.Infof("unable to enqueue outgoing message confirmation; outgoingMessagesCallbackCh is full. disconnecting from peer.")
		return errTransactionSyncOutgoingMessageQueueFull
	}
	return nil
}

// pendingTransactionGroupsSnapshot is used to represent a snapshot of a pending transcation groups along with the latestLocallyOriginatedGroupCounter value.
// The goal is to ensure we're "capturing"  this only once per `sendMessageLoop` call. In order to do so, we allocate that structure on the stack, and passing
// a pointer to that structure downstream.
type pendingTransactionGroupsSnapshot struct {
	pendingTransactionsGroups           []transactions.SignedTxGroup
	latestLocallyOriginatedGroupCounter uint64
}

func (s *syncState) sendMessageLoop(deadline timers.DeadlineMonitor, peers []*Peer) {
	if len(peers) == 0 {
		// no peers - no messages that need to be sent.
		return
	}
	var pendingTransactions pendingTransactionGroupsSnapshot
	pendingTransactions.pendingTransactionsGroups, pendingTransactions.latestLocallyOriginatedGroupCounter = s.node.GetPendingTransactionGroups()
	seenPeers := make(map[*Peer]bool)
	for _, peer := range peers {
		if seenPeers[peer] {
			continue
		}
		seenPeers[peer] = true
		msgCallback := &messageSentCallback{state: s, roundClock: s.clock}
		msgCallback.messageData = s.assemblePeerMessage(peer, &pendingTransactions)
		encodedMessage := msgCallback.messageData.message.MarshalMsg([]byte{})
		msgCallback.messageData.encodedMessageSize = len(encodedMessage)
		// now that the message is ready, we can discard the encoded transcation group slice to allow the GC to collect it.
		releaseEncodedTransactionGroups(msgCallback.messageData.message.TransactionGroups.Bytes)
		msgCallback.messageData.message.TransactionGroups.Bytes = nil

		s.node.SendPeerMessage(peer.networkPeer, encodedMessage, msgCallback.asyncMessageSent)

		scheduleOffset, ops := peer.getNextScheduleOffset(s.isRelay, s.lastBeta, msgCallback.messageData.partialMessage, s.clock.Since())
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
			s.scheduler.schedulerPeer(peer, s.clock.Since()+scheduleOffset)
			/*if scheduleOffset < 20*time.Millisecond {
				s.log.Debugf("rescheduling for %v", s.clock.Since()+scheduleOffset)
				panic(nil)
			}*/
		}

		if deadline.Expired() {
			// we ran out of time sending messages, stop sending any more messages.
			break
		}
	}
}

func (s *syncState) assemblePeerMessage(peer *Peer, pendingTransactions *pendingTransactionGroupsSnapshot) (metaMessage sentMessageMetadata) {
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
		// generate a bloom filter that matches the requests params.
		metaMessage.filter = makeBloomFilter(metaMessage.message.UpdatedRequestParams, pendingTransactions.pendingTransactionsGroups, uint32(s.node.Random(0xffffffff)), lastBloomFilter)
		if !metaMessage.filter.sameParams(peer.lastSentBloomFilter) {
			metaMessage.message.TxnBloomFilter = metaMessage.filter.encode()
			bloomFilterSize = metaMessage.message.TxnBloomFilter.Msgsize()
		}
		s.lastBloomFilter = metaMessage.filter
	}

	if msgOps&messageConstTransactions == messageConstTransactions {
		transactionGroups := pendingTransactions.pendingTransactionsGroups
		if !s.isRelay {
			if !peer.isWithinMessageSeries() {
				// on non-relay, we need to filter out the non-locally originated transactions since we don't want
				// non-relays to send transcation that they received via the transaction sync back.
				transactionGroups = s.locallyGeneratedTransactions(pendingTransactions)
			}
		}
		var txnGroups []transactions.SignedTxGroup
		txnGroups, metaMessage.sentTranscationsIDs, metaMessage.partialMessage = peer.selectPendingTransactions(transactionGroups, messageTimeWindow, s.round, bloomFilterSize)
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
		metaMessage.message.MsgSync.ResponseElapsedTime = uint64((s.clock.Since() - peer.lastReceivedMessageTimestamp).Nanoseconds())
	}

	if msgOps&messageConstNextMinDelay == messageConstNextMinDelay {
		metaMessage.message.MsgSync.NextMsgMinDelay = uint64(s.lastBeta.Nanoseconds()) * 2
	}

	return metaMessage
}

func (s *syncState) evaluateOutgoingMessage(msg *messageSentCallback) {
	msgData := &msg.messageData

	msgData.peer.updateMessageSent(msgData.message.Round, msgData.sentTranscationsIDs, msgData.sentTimestamp, msgData.sequenceNumber, msgData.encodedMessageSize, msgData.filter)
	s.log.outgoingMessage(msgStats{msgData.sequenceNumber, msgData.message.Round, len(msgData.sentTranscationsIDs), msgData.message.UpdatedRequestParams, len(msgData.message.TxnBloomFilter.BloomFilter), msgData.message.MsgSync.NextMsgMinDelay, msg.messageData.peer.networkAddress()})
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
		if txnGroup.LocallyOriginated {
			result[count] = txnGroup
			count++
		}
	}
	return result[:count]
}
