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
	"sort"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
)

//msgp:ignore peerState
type peerState int

//msgp:ignore peersOps
type peersOps int

//msgp:ignore messageConstructionOps
type messageConstructionOps int

const maxIncomingBloomFilterHistory = 20
const recentTransactionsSentBufferLength = 10000
const minDataExchangeRateThreshold = 100 * 1024            // 100KB/s, which is ~0.8Mbps
const maxDataExchangeRateThreshold = 100 * 1024 * 1024 / 8 // 100Mbps
const defaultDataExchangeRate = minDataExchangeRateThreshold
const defaultRelayToRelayDataExchangeRate = 10 * 1024 * 1024 / 8 // 10Mbps

const (
	// peerStateStartup is before the timeout for the sending the first message to the peer has reached.
	// for an outgoing peer, it means that an incoming message arrived, and one or more messages need to be sent out.
	peerStateStartup peerState = iota
	// peerStateHoldsoff is set once a message was sent to a peer, and we're holding off before sending additional messages.
	peerStateHoldsoff
	// peerStateInterrupt is set once the holdoff period for the peer have expired.
	peerStateInterrupt
	// peerStateLateBloom is set for outgoing peers on relays, indicating that the next message should be a bloom filter only message.
	peerStateLateBloom

	peerOpsSendMessage        peersOps = 1
	peerOpsSetInterruptible   peersOps = 2
	peerOpsClearInterruptible peersOps = 4
	peerOpsReschedule         peersOps = 8

	messageConstBloomFilter         messageConstructionOps = 1
	messageConstTransactions        messageConstructionOps = 2
	messageConstNextMinDelay        messageConstructionOps = 4
	messageConstUpdateRequestParams messageConstructionOps = 8
)

// incomingBloomFilter stores an incoming bloom filter, along with the associated round number.
// the round number allow us to prune filters from rounds n-2 and below.
type incomingBloomFilter struct {
	filter bloomFilter
	round  basics.Round
}

// Peer contains peer-related data which extends the data "known" and managed by the network package.
type Peer struct {
	// networkPeer is the network package exported peer. It's created on construction and never change afterward.
	networkPeer interface{}
	// isOutgoing defines whether the peer is an outgoing peer or not. For relays, this is meaningful as these have
	// slighly different message timing logic.
	isOutgoing bool
	// state defines the peer state ( in terms of state machine state ). It's touched only by the sync main state machine
	state peerState

	// lastRound is the latest round reported by the peer.
	lastRound basics.Round

	// incomingMessages contains the incoming messages from this peer. This heap help us to reorder the imcoming messages so that
	// we could process them in the tcp-transport order.
	incomingMessages messageOrderingHeap

	// nextReceivedMessageSeq is a counter containing the next message sequence number that we expect to see from this peer.
	nextReceivedMessageSeq uint64 // the next message seq that we expect to recieve from that peer; implies that all previous messages have been accepted.

	// recentIncomingBloomFilters contains the recent list of bloom filters sent from the peer. When considering sending transactions, we check this
	// array to determine if the peer already has this message.
	recentIncomingBloomFilters []incomingBloomFilter

	// recentSentTransactions contains the recently sent transactions. It's needed since we don't want to rely on the other peer's bloom filter while
	// sending back-to-back messages.
	recentSentTransactions *transactionCache
	// recentSentTransactionsRound is the round associated with the cache of recently sent transactions. We keep this variable around so that we can
	// flush the cache on every round so that we can give pending transaction another chance of being transmitted.
	recentSentTransactionsRound basics.Round

	// these two fields describe "what does that peer asked us to send it"
	requestedTransactionsModulator byte
	requestedTransactionsOffset    byte

	// lastSentMessageSequenceNumber is the last sequence number of the message that we sent.
	lastSentMessageSequenceNumber uint64
	// lastSentMessageRound is the round the last sent message was sent on. The timestamps are relative to the begining of the round
	// and therefore need to be evaluated togather.
	lastSentMessageRound basics.Round
	// lastSentMessageTimestamp the timestamp at which the last message was sent.
	lastSentMessageTimestamp time.Duration
	// lastSentMessageSize is the encoded message size of the last sent message
	lastSentMessageSize int
	// lastSentBloomFilter is the last bloom filter that was sent to this peer. This bloom filter could be stale if no bloom filter was included in the last message.
	lastSentBloomFilter bloomFilter

	// lastConfirmedMessageSeqReceived is the last message sequence number that was confirmed by the peer to have been accepted.
	lastConfirmedMessageSeqReceived    uint64
	lastReceivedMessageLocalRound      basics.Round
	lastReceivedMessageTimestamp       time.Duration
	lastReceivedMessageSize            int
	lastReceivedMessageNextMsgMinDelay time.Duration

	// dataExchangeRate is the combined upload/download rate in bytes/second
	dataExchangeRate uint64

	// these two fields describe "what does the local peer want the remote peer to send back"
	localTransactionsModulator  byte
	localTransactionsBaseOffset byte

	// lastTransactionSelectionGroupCounter is the last transaction group counter that we've evaluated on the selectPendingTransactions method.
	// it used to ensure that on subsequent calls, we won't need to scan the entire pending transactions array from the begining.
	lastTransactionSelectionGroupCounter uint64

	// nextStateTimestamp indicates the next timestamp where the peer state would need to be changed.
	// it used to allow sending partial message while retaining the "next-beta time", or, in the case of outgoing relays,
	// its being used to hold when we need to send the last (bloom) message.
	nextStateTimestamp time.Duration
	// messageSeriesPendingTransactions contain the transactions we are sending in the current "message-series". It allows us to pick a given
	// "snapshot" from the transaction pool, and send that "snapshot" to completion before attempting to re-iterate.
	messageSeriesPendingTransactions []transactions.SignedTxGroup
}

func makePeer(networkPeer interface{}, isOutgoing bool, isLocalNodeRelay bool) *Peer {
	p := &Peer{
		networkPeer:            networkPeer,
		isOutgoing:             isOutgoing,
		recentSentTransactions: makeTransactionCache(recentTransactionsSentBufferLength),
		dataExchangeRate:       defaultDataExchangeRate,
	}
	if isOutgoing {
		// outgoing implies it's a relay, which means that it would want to receive all messages.
		p.requestedTransactionsModulator = 1
		if isLocalNodeRelay {
			p.dataExchangeRate = defaultRelayToRelayDataExchangeRate
		}
	}
	return p
}

// outgoing related methods :

func (p *Peer) selectPendingTransactions(pendingTransactions []transactions.SignedTxGroup, sendWindow time.Duration, round basics.Round, bloomFilterSize int) (selectedTxns []transactions.SignedTxGroup, selectedTxnIDs []transactions.Txid, partialTranscationsSet bool) {
	// if peer is too far back, don't send it any transactions ( or if the peer is not interested in transactions )
	if p.lastRound < round.SubSaturate(1) || p.requestedTransactionsModulator == 0 {
		return nil, nil, false
	}

	if len(p.messageSeriesPendingTransactions) > 0 {
		pendingTransactions = p.messageSeriesPendingTransactions
	}

	if len(pendingTransactions) == 0 {
		return nil, nil, false
	}

	// flush the recent sent transaction cache on the begining of a new round to give pending transactions another
	// chance of being transmitted.
	if p.recentSentTransactionsRound != round {
		p.recentSentTransactions.reset()
		p.recentSentTransactionsRound = round
		p.lastTransactionSelectionGroupCounter = 0
	}

	windowLengthBytes := int(uint64(sendWindow) * p.dataExchangeRate / uint64(time.Second))
	windowLengthBytes -= bloomFilterSize

	accumulatedSize := 0
	selectedTxnIDs = make([]transactions.Txid, 0, len(pendingTransactions))

	startIndex := sort.Search(len(pendingTransactions), func(i int) bool {
		return pendingTransactions[i].GroupCounter >= p.lastTransactionSelectionGroupCounter
	})

	windowSizedReached := false
	hasMorePendingTransactions := false

	//removedTxn := 0
	grpIdx := startIndex
	for ; grpIdx < len(pendingTransactions); grpIdx++ {
		txID := pendingTransactions[grpIdx].FirstTransactionID

		// check if the peer would be interested in these messages -
		if p.requestedTransactionsModulator > 1 {
			if txidToUint64(txID)%uint64(p.requestedTransactionsModulator) != uint64(p.requestedTransactionsOffset) {
				continue
			}
		}

		// filter out transactions that we already previously sent.
		if p.recentSentTransactions.contained(txID) {
			// we already sent that transaction. no need to send again.
			continue
		}

		// check if the peer alrady received these messages from a different source other than us.
		alreadyReceived := false
		for filterIdx := len(p.recentIncomingBloomFilters) - 1; filterIdx >= 0; filterIdx-- {
			if p.recentIncomingBloomFilters[filterIdx].filter.test(txID) {
				//removedTxn++
				alreadyReceived = true
				break
			}
		}
		if alreadyReceived {
			continue
		}

		if windowSizedReached {
			hasMorePendingTransactions = true
			break
		}
		selectedTxns = append(selectedTxns, pendingTransactions[grpIdx])
		selectedTxnIDs = append(selectedTxnIDs, txID)

		// add the size of the transaction group
		accumulatedSize += pendingTransactions[grpIdx].EncodedLength

		if accumulatedSize > windowLengthBytes {
			windowSizedReached = true
		}
	}

	// update the lastTransactionSelectionGroupCounter if needed -
	// if we selected any transaction to be sent, update the lastTransactionSelectionGroupCounter with the latest
	// group counter. If the startIndex was *after* the last pending transaction, it means that we don't
	// need to update the lastTransactionSelectionGroupCounter since it's already ahead of everything in the pending transactions.
	if grpIdx >= 0 && startIndex < len(pendingTransactions) {
		if grpIdx == len(pendingTransactions) {
			if grpIdx > 0 {
				p.lastTransactionSelectionGroupCounter = pendingTransactions[grpIdx-1].GroupCounter + 1
			}
		} else {
			p.lastTransactionSelectionGroupCounter = pendingTransactions[grpIdx].GroupCounter
		}
	}

	if !hasMorePendingTransactions {
		// we're done with the current sequence.
		p.messageSeriesPendingTransactions = nil
	}

	//fmt.Printf("selectPendingTransactions : selected %d transactions, %d not needed and aborted after exceeding data length %d/%d more = %v\n", len(selectedTxnIDs), removedTxn, accumulatedSize, windowLengthBytes, hasMorePendingTransactions)

	return selectedTxns, selectedTxnIDs, hasMorePendingTransactions
}

// getLocalRequestParams returns the local requests params
func (p *Peer) getLocalRequestParams() (offset, modulator byte) {
	return p.localTransactionsBaseOffset, p.localTransactionsModulator
}

// update the peer once the message was sent successfully.
func (p *Peer) updateMessageSent(txMsg *transactionBlockMessage, selectedTxnIDs []transactions.Txid, timestamp time.Duration, sequenceNumber uint64, messageSize int, filter bloomFilter) {
	for _, txid := range selectedTxnIDs {
		p.recentSentTransactions.add(txid)
	}
	p.lastSentMessageSequenceNumber = sequenceNumber
	p.lastSentMessageRound = txMsg.Round
	p.lastSentMessageTimestamp = timestamp
	p.lastSentMessageSize = messageSize
	if filter.filter != nil {
		p.lastSentBloomFilter = filter
	}
}

// setLocalRequestParams stores the peer request params.
func (p *Peer) setLocalRequestParams(offset, modulator uint64) {
	if modulator > 255 {
		modulator = 255
	}
	p.localTransactionsModulator = byte(modulator)
	if modulator != 0 {
		p.localTransactionsBaseOffset = byte(offset % modulator)
	}
}

// peers array functions

// incomingPeersOnly scan the input peers array and return a subset of the peers that are incoming peers.
func incomingPeersOnly(peers []*Peer) (incomingPeers []*Peer) {
	incomingPeers = make([]*Peer, 0, len(peers))
	for _, peer := range peers {
		if !peer.isOutgoing {
			incomingPeers = append(incomingPeers, peer)
		}
	}
	return
}

// incoming related functions

func (p *Peer) addIncomingBloomFilter(round basics.Round, incomingFilter bloomFilter, currentRound basics.Round) {
	bf := incomingBloomFilter{
		round:  round,
		filter: incomingFilter,
	}
	// scan the current list and find if we can removed entries.
	firstValidEntry := sort.Search(len(p.recentIncomingBloomFilters), func(i int) bool {
		return p.recentIncomingBloomFilters[i].round >= currentRound.SubSaturate(1)
	})
	if firstValidEntry < len(p.recentIncomingBloomFilters) {
		// delete some of the old entries.
		p.recentIncomingBloomFilters = p.recentIncomingBloomFilters[firstValidEntry:]
	}
	// scan the existing bloom filter, and ensure we have only one bloom filter for every
	// set of encoding paramters. this would allow us to accumulate false positive
	for idx, bloomFltr := range p.recentIncomingBloomFilters {
		if bloomFltr.filter.encodingParams == incomingFilter.encodingParams {
			// replace.
			p.recentIncomingBloomFilters[idx] = bf
			// reset the counter, since we might need to re-evaluate some of the transaction group with the new bloom filter.
			p.lastTransactionSelectionGroupCounter = 0
			return
		}
	}

	p.recentIncomingBloomFilters = append(p.recentIncomingBloomFilters, bf)
	if len(p.recentIncomingBloomFilters) > maxIncomingBloomFilterHistory {
		p.recentIncomingBloomFilters = p.recentIncomingBloomFilters[1:]
	}
}

func (p *Peer) updateRequestParams(modulator, offset byte) {
	if p.requestedTransactionsModulator == modulator && p.requestedTransactionsOffset == offset {
		return
	}
	p.requestedTransactionsModulator, p.requestedTransactionsOffset = modulator, offset

	// if we've changed the request params for this peer, we need to reset the lastTransactionSelectionGroupCounter since we might have
	// skipped entries that need to be re-evaluated.
	p.lastTransactionSelectionGroupCounter = 0
}

// update the recentSentTransactions with the incoming transaction groups. This would prevent us from sending the received transactions back to the
// peer that sent it to us. This comes in addition to the bloom filter, if being sent by the other peer.
func (p *Peer) updateIncomingTransactionGroups(txnGroups []transactions.SignedTxGroup) {
	for _, txnGroup := range txnGroups {
		if len(txnGroup.Transactions) > 0 {
			p.recentSentTransactions.add(txnGroup.FirstTransactionID)
		}
	}
}

func (p *Peer) updateIncomingMessageTiming(timings timingParams, currentRound basics.Round, currentTime time.Duration, incomingMessageSize int) {
	p.lastConfirmedMessageSeqReceived = timings.RefTxnBlockMsgSeq
	// if we received a message that references our privious message, see if they occured on the same round
	if p.lastConfirmedMessageSeqReceived == p.lastSentMessageSequenceNumber && p.lastSentMessageRound == currentRound {
		// if so, we might be able to calculate the bandwidth.
		timeSinceLastMessageWasSent := currentTime - p.lastSentMessageTimestamp
		if timeSinceLastMessageWasSent > time.Duration(timings.ResponseElapsedTime) {
			networkTrasmitTime := timeSinceLastMessageWasSent - time.Duration(timings.ResponseElapsedTime)
			networkMessageSize := uint64(p.lastSentMessageSize + incomingMessageSize)
			dataExchangeRate := uint64(time.Second) * networkMessageSize / uint64(networkTrasmitTime)

			if dataExchangeRate < minDataExchangeRateThreshold {
				dataExchangeRate = minDataExchangeRateThreshold
			} else if dataExchangeRate > maxDataExchangeRateThreshold {
				dataExchangeRate = maxDataExchangeRateThreshold
			}
			// clamp data exchange rate to realistic metrics
			p.dataExchangeRate = dataExchangeRate
			//fmt.Printf("incoming message : updating data exchange to %d; network msg size = %d+%d, transmit time = %v\n", dataExchangeRate, p.lastSentMessageSize, incomingMessageSize, networkTrasmitTime)
		}
	}
	p.lastReceivedMessageLocalRound = currentRound
	p.lastReceivedMessageTimestamp = currentTime
	p.lastReceivedMessageSize = incomingMessageSize
	p.lastReceivedMessageNextMsgMinDelay = time.Duration(timings.NextMsgMinDelay) * time.Nanosecond
}

// advancePeerState is called when a peer schedule arrives, before we're doing any operation.
// The method would determine whether a message need to be sent, and adjust the peer state
// accordingly.
func (p *Peer) advancePeerState(currenTime time.Duration, isRelay bool) (ops peersOps) {
	if isRelay {
		if p.isOutgoing {
			// outgoing peers are "special", as they respond to messages rather then generating their own.
			// we need to figure the special state needed for "late bloom filter message"
			switch p.state {
			case peerStateStartup:
				p.nextStateTimestamp = currenTime + p.lastReceivedMessageNextMsgMinDelay
				messagesCount := p.lastReceivedMessageNextMsgMinDelay / messageTimeWindow
				if messagesCount <= 2 {
					// we have time to send only a single message. This message need to include both transactions and bloom filter.
					p.state = peerStateLateBloom
				} else {
					// we have enough time to send multiple messages, make the first n-1 message have no bloom filter, and have the last one
					// include a bloom filter.
					p.state = peerStateHoldsoff
				}

				// send a message
				ops |= peerOpsSendMessage
			case peerStateHoldsoff:
				// calculate how more messages we can send ( if needed )
				messagesCount := (p.nextStateTimestamp - currenTime) / messageTimeWindow
				if messagesCount <= 2 {
					// we have time to send only a single message. This message need to include both transactions and bloom filter.
					p.state = peerStateLateBloom
				}

				// send a message
				ops |= peerOpsSendMessage

				// the rescehduling would be done in the sendMessageLoop, since we need to know if additional messages are needed.
			case peerStateLateBloom:
				// send a message
				ops |= peerOpsSendMessage

			default:
				// this isn't expected, so we can just ignore this.
				// todo : log
			}
		} else {
			// non-outgoing
			switch p.state {
			case peerStateStartup:
				p.state = peerStateHoldsoff
				fallthrough
			case peerStateHoldsoff:
				// prepare the send message array.
				ops |= peerOpsSendMessage
			default: // peerStateInterrupt & peerStateLateBloom
				// this isn't expected, so we can just ignore this.
				// todo : log
			}
		}
	} else {
		switch p.state {
		case peerStateStartup:
			p.state = peerStateHoldsoff
			ops |= peerOpsSendMessage

		case peerStateHoldsoff:
			if p.nextStateTimestamp == 0 {
				p.state = peerStateInterrupt
				ops |= peerOpsSetInterruptible | peerOpsReschedule
			} else {
				ops |= peerOpsSendMessage
			}

		case peerStateInterrupt:
			p.state = peerStateHoldsoff
			ops |= peerOpsSendMessage | peerOpsClearInterruptible

		default: // peerStateLateBloom
			// this isn't expected, so we can just ignore this.
			// todo : log
		}
	}
	return
}

func (p *Peer) getMessageConstructionOps(isRelay bool, fetchTransactions bool) (ops messageConstructionOps) {
	// on outgoing peers of relays, we want have some custom logic.
	if isRelay {
		if p.isOutgoing {
			switch p.state {
			case peerStateLateBloom:
				ops |= messageConstBloomFilter
			case peerStateHoldsoff:
				ops |= messageConstTransactions
			}
		} else {
			ops |= messageConstTransactions
			if p.nextStateTimestamp == 0 {
				ops |= messageConstBloomFilter
			}
			if p.nextStateTimestamp == 0 {
				ops |= messageConstNextMinDelay
			}
		}
		ops |= messageConstUpdateRequestParams
	} else {
		ops |= messageConstTransactions
		if fetchTransactions {
			if p.localTransactionsModulator == 1 {
				// special optimization if we have just one relay that we're connected to:
				// generate the bloom filter only once per 2*beta message.
				// this would reduce the number of unneeded bloom filters generation dramatically.
				// that single relay would know which messages it previously sent us, and would refrain from
				// sending these again.
				if p.nextStateTimestamp == 0 {
					ops |= messageConstBloomFilter
				}
			} else {
				ops |= messageConstBloomFilter
			}
			ops |= messageConstUpdateRequestParams
		}
	}
	return
}

// getNextScheduleOffset is called after a message was sent to the peer, and we need to evaluate the next
// scheduling time.
func (p *Peer) getNextScheduleOffset(isRelay bool, beta time.Duration, partialMessage bool, currentTime time.Duration) (offset time.Duration, ops peersOps) {
	if partialMessage {
		if isRelay {
			if p.isOutgoing {
				if p.state == peerStateHoldsoff {
					// we have enough time to send another message.
					return messageTimeWindow, peerOpsReschedule
				}
			} else {
				// a partial message was sent to an incoming peer
				if p.nextStateTimestamp > time.Duration(0) {
					if currentTime+messageTimeWindow*2 < p.nextStateTimestamp {
						// we have enough time to send another message
						return messageTimeWindow, peerOpsReschedule
					}
					// we don't have enough time to send another message.
					next := p.nextStateTimestamp
					p.nextStateTimestamp = 0
					return next - currentTime, peerOpsReschedule
				}
				p.nextStateTimestamp = currentTime + 2*beta
				return messageTimeWindow, peerOpsReschedule
			}
		} else {
			if p.nextStateTimestamp > time.Duration(0) {
				if currentTime+messageTimeWindow*2 < p.nextStateTimestamp {
					// we have enough time to send another message
					return messageTimeWindow, peerOpsReschedule
				}
				// we don't have enough time, so don't get into "interrupt" state,
				// since we're already sending messages.
				next := p.nextStateTimestamp
				p.nextStateTimestamp = 0
				p.messageSeriesPendingTransactions = nil
				// move to the next state.
				p.state = peerStateHoldsoff
				return next - currentTime, peerOpsReschedule | peerOpsClearInterruptible

			}
			// this is the first message
			p.nextStateTimestamp = currentTime + 2*beta

			return messageTimeWindow, peerOpsReschedule
		}
	} else {
		if isRelay {
			if p.isOutgoing {
				if p.state == peerStateHoldsoff {
					// even that we're done now, we need to send another message that would contain the bloom filter
					p.state = peerStateLateBloom

					bloomMessageExtrapolatedSendingTime := messageTimeWindow
					// try to improve the sending time by using the last sent bloom filter as the expected message size.
					if p.lastSentBloomFilter.containedTxnsRange.transactionsCount > 0 {
						lastBloomFilterSize := uint64(len(p.lastSentBloomFilter.encode().BloomFilter))
						bloomMessageExtrapolatedSendingTime = time.Duration(lastBloomFilterSize * uint64(p.dataExchangeRate))
					}

					next := p.nextStateTimestamp - bloomMessageExtrapolatedSendingTime - currentTime
					p.nextStateTimestamp = 0
					return next, peerOpsReschedule
				}
				p.nextStateTimestamp = 0
			} else {
				// we sent a message to an incoming connection. No more data to send.
				if p.nextStateTimestamp > time.Duration(0) {
					next := p.nextStateTimestamp
					p.nextStateTimestamp = 0
					return next - currentTime, peerOpsReschedule
				}
				p.nextStateTimestamp = 0
				return beta * 2, peerOpsReschedule
			}
		} else {
			if p.nextStateTimestamp > time.Duration(0) {
				next := p.nextStateTimestamp
				p.nextStateTimestamp = 0
				return next - currentTime, peerOpsReschedule
			}
			return beta, peerOpsReschedule
		}
	}
	return time.Duration(0), 0
}

func (p *Peer) networkAddress() string {
	if peerAddress, supportInterface := p.networkPeer.(networkPeerAddress); supportInterface {
		return peerAddress.GetAddress()
	}
	return ""
}
