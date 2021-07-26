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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/util/bloom"
	"github.com/algorand/go-algorand/util/timers"
)

func TestAsyncMessageSent(t *testing.T) {
	a := require.New(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	s.log = mockLogger{}

	asyncEncoder := messageAsyncEncoder{
		state: &s,
		messageData: sentMessageMetadata{
			encodedMessageSize:  0,
			sentTranscationsIDs: []transactions.Txid{},
			message: &transactionBlockMessage{
				Version: txnBlockMessageVersion,
				Round:   1,
			},
			peer:              &Peer{},
			sentTimestamp:     0 * time.Millisecond,
			sequenceNumber:    0,
			partialMessage:    false,
			filter:            bloomFilter{},
			transactionGroups: []transactions.SignedTxGroup{},
		},
		roundClock:           timers.MakeMonotonicClock(time.Now()),
		peerDataExchangeRate: 0,
	}

	oldTimestamp := asyncEncoder.messageData.sentTimestamp
	a.Equal(asyncEncoder.asyncMessageSent(false, 0), errTransactionSyncOutgoingMessageSendFailed)
	err := asyncEncoder.asyncMessageSent(true, 1337)
	a.Equal(err, errTransactionSyncOutgoingMessageQueueFull)
	a.NotEqual(asyncEncoder.messageData.sentTimestamp, oldTimestamp)
	a.Equal(asyncEncoder.messageData.sequenceNumber, uint64(1337))

	// Make this buffered for now so we catch the select statement
	asyncEncoder.state.outgoingMessagesCallbackCh = make(chan sentMessageMetadata, 1)

	err = asyncEncoder.asyncMessageSent(true, 1337)
	a.Nil(err)
}

type mockAsyncNodeConnector struct {
	NodeConnector
	called *bool
}

func (m mockAsyncNodeConnector) SendPeerMessage(netPeer interface{}, msg []byte, callback SendMessageCallback) {
	*m.called = true
}

func (m mockAsyncNodeConnector) GetPendingTransactionGroups() (txGroups []transactions.SignedTxGroup, latestLocallyOriginatedGroupCounter uint64) {
	return []transactions.SignedTxGroup{}, 1
}

func TestAsyncEncodeAndSend(t *testing.T) {
	a := require.New(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	s.log = mockLogger{}
	called := false
	s.node = mockAsyncNodeConnector{called: &called}
	s.messageSendWaitGroup = sync.WaitGroup{}

	asyncEncoder := messageAsyncEncoder{
		state: &s,
		messageData: sentMessageMetadata{
			encodedMessageSize:  0,
			sentTranscationsIDs: []transactions.Txid{},
			message: &transactionBlockMessage{
				Version: txnBlockMessageVersion,
				Round:   1,
			},
			peer:              &Peer{},
			sentTimestamp:     0 * time.Millisecond,
			sequenceNumber:    0,
			partialMessage:    false,
			filter:            bloomFilter{},
			transactionGroups: []transactions.SignedTxGroup{},
		},
		roundClock:           timers.MakeMonotonicClock(time.Now()),
		peerDataExchangeRate: 0,
	}

	asyncEncoder.state.messageSendWaitGroup.Add(1)

	err := asyncEncoder.asyncEncodeAndSend(nil)

	a.Nil(err)
	a.True(called)

}

func TestAssemblePeerMessage(t *testing.T) {

	a := require.New(t)

	s := syncState{
		service:                    nil,
		log:                        mockLogger{},
		node:                       mockAsyncNodeConnector{},
		isRelay:                    false,
		clock:                      timers.MakeMonotonicClock(time.Now()),
		config:                     config.Local{},
		threadpool:                 nil,
		genesisID:                  "",
		genesisHash:                crypto.Digest{},
		lastBeta:                   0,
		round:                      42,
		fetchTransactions:          false,
		scheduler:                  peerScheduler{},
		interruptablePeers:         nil,
		interruptablePeersMap:      nil,
		incomingMessagesQ:          incomingMessageQueue{},
		outgoingMessagesCallbackCh: nil,
		nextOffsetRollingCh:        nil,
		requestsOffset:             0,
		lastBloomFilter:            bloomFilter{},
		transactionPoolFull:        false,
		messageSendWaitGroup:       sync.WaitGroup{},
		xorBuilder:                 bloom.XorBuilder{},
	}

	s.profiler = makeProfiler(1*time.Millisecond, s.clock, s.log, 1*time.Millisecond)

	s.isRelay = false

	peer := Peer{
		networkPeer:                        nil,
		isOutgoing:                         false,
		state:                              0,
		lastRound:                          0,
		incomingMessages:                   messageOrderingHeap{},
		nextReceivedMessageSeq:             0,
		recentIncomingBloomFilters:         nil,
		recentSentTransactions:             nil,
		recentSentTransactionsRound:        0,
		requestedTransactionsModulator:     0,
		requestedTransactionsOffset:        0,
		lastSentMessageSequenceNumber:      0,
		lastSentMessageRound:               0,
		lastSentMessageTimestamp:           0,
		lastSentMessageSize:                0,
		lastSentBloomFilter:                bloomFilter{},
		lastConfirmedMessageSeqReceived:    0,
		lastReceivedMessageLocalRound:      0,
		lastReceivedMessageTimestamp:       0,
		lastReceivedMessageSize:            0,
		lastReceivedMessageNextMsgMinDelay: 0,
		dataExchangeRate:                   0,
		localTransactionsModulator:         0,
		localTransactionsBaseOffset:        0,
		lastTransactionSelectionTracker:    nil,
		nextStateTimestamp:                 0,
		messageSeriesPendingTransactions:   nil,
		transactionPoolAckCh:               nil,
		transactionPoolAckMessages:         nil,
		lastSelectedTransactionsCount:      0,
	}

	pendingTransactions := pendingTransactionGroupsSnapshot{
		pendingTransactionsGroups:           nil,
		latestLocallyOriginatedGroupCounter: 0,
	}

	peer.setLocalRequestParams(111, 222)
	peer.lastReceivedMessageTimestamp = 100
	peer.lastReceivedMessageLocalRound = s.round

	s.isRelay = true

	metaMessage := s.assemblePeerMessage(&peer, &pendingTransactions)

	a.Equal(metaMessage.message.UpdatedRequestParams.Modulator, byte(222))
	a.Equal(metaMessage.message.UpdatedRequestParams.Offset, byte(111))
	a.Equal(metaMessage.peer, &peer)
	a.Equal(metaMessage.message.Version, int32(txnBlockMessageVersion))
	a.Equal(metaMessage.message.Round, s.round)
	a.True(metaMessage.message.MsgSync.ResponseElapsedTime != 0)

}

func TestLocallyGeneratedTransactions(t *testing.T) {

	a := require.New(t)

	pendingTransactions := &pendingTransactionGroupsSnapshot{
		pendingTransactionsGroups:           []transactions.SignedTxGroup{},
		latestLocallyOriginatedGroupCounter: 0,
	}

	s := syncState{}

	pendingTransactions.latestLocallyOriginatedGroupCounter = 1

	a.Equal(s.locallyGeneratedTransactions(pendingTransactions), []transactions.SignedTxGroup{})

	pendingTransactions.pendingTransactionsGroups = []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions:       nil,
			LocallyOriginated:  true,
			GroupCounter:       0,
			GroupTransactionID: transactions.Txid{},
			EncodedLength:      2,
		},
		transactions.SignedTxGroup{
			Transactions:       nil,
			LocallyOriginated:  false,
			GroupCounter:       0,
			GroupTransactionID: transactions.Txid{},
			EncodedLength:      1,
		},
		transactions.SignedTxGroup{
			Transactions:       nil,
			LocallyOriginated:  true,
			GroupCounter:       0,
			GroupTransactionID: transactions.Txid{},
			EncodedLength:      3,
		},
	}

	pendingTransactions.latestLocallyOriginatedGroupCounter = transactions.InvalidSignedTxGroupCounter

	a.Equal(s.locallyGeneratedTransactions(pendingTransactions), []transactions.SignedTxGroup{})

	pendingTransactions.latestLocallyOriginatedGroupCounter = 1

	expected := []transactions.SignedTxGroup{

		transactions.SignedTxGroup{
			Transactions:       nil,
			LocallyOriginated:  true,
			GroupCounter:       0,
			GroupTransactionID: transactions.Txid{},
			EncodedLength:      2,
		},

		transactions.SignedTxGroup{
			Transactions:       nil,
			LocallyOriginated:  true,
			GroupCounter:       0,
			GroupTransactionID: transactions.Txid{},
			EncodedLength:      3,
		},
	}

	a.Equal(s.locallyGeneratedTransactions(pendingTransactions), expected)

}
