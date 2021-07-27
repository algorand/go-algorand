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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/timers"
)

type mockAsyncLogger struct {
	logging.Logger
	warnCalled *bool
}

func (m mockAsyncLogger) outgoingMessage(mstat msgStats) {
}

func (m mockAsyncLogger) incomingMessage(mstat msgStats) {
}

func (m mockAsyncLogger) Infof(string, ...interface{}) {}

func (m mockAsyncLogger) Warnf(string, ...interface{}) {
	if m.warnCalled != nil {
		*m.warnCalled = true
	}
}

func TestAsyncMessageSent(t *testing.T) {
	a := require.New(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	s.log = mockAsyncLogger{}

	asyncEncoder := messageAsyncEncoder{
		state: &s,
		messageData: sentMessageMetadata{
			message: &transactionBlockMessage{
				Version: txnBlockMessageVersion,
				Round:   1,
			},
			peer: &Peer{},
		},
		roundClock: timers.MakeMonotonicClock(time.Now()),
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

// TestAsyncEncodeAndSendErr Tests response when encodeTransactionGroups doesn't return an error
func TestAsyncEncodeAndSendNonErr(t *testing.T) {
	a := require.New(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	warnCalled := false
	s.log = mockAsyncLogger{warnCalled: &warnCalled}
	sendPeerMessageCalled := false
	s.node = mockAsyncNodeConnector{called: &sendPeerMessageCalled}
	s.messageSendWaitGroup = sync.WaitGroup{}

	txnGrps := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{
				transactions.SignedTxn{
					Txn: transactions.Transaction{
						Type: protocol.AssetConfigTx,
					},
				},
			},
		},
	}

	asyncEncoder := messageAsyncEncoder{
		state: &s,
		messageData: sentMessageMetadata{
			message: &transactionBlockMessage{
				Version: txnBlockMessageVersion,
				Round:   1,
			},
			transactionGroups: txnGrps,
			peer:              &Peer{},
		},
		roundClock: timers.MakeMonotonicClock(time.Now()),
	}

	asyncEncoder.state.messageSendWaitGroup.Add(1)

	err := asyncEncoder.asyncEncodeAndSend(nil)

	a.Nil(err)
	a.False(warnCalled)
	a.True(sendPeerMessageCalled)
}

// TestAsyncEncodeAndSendErr Tests response when encodeTransactionGroups returns an error
func TestAsyncEncodeAndSendErr(t *testing.T) {
	a := require.New(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	warnCalled := false
	s.log = mockAsyncLogger{warnCalled: &warnCalled}
	sendPeerMessageCalled := false
	s.node = mockAsyncNodeConnector{called: &sendPeerMessageCalled}
	s.messageSendWaitGroup = sync.WaitGroup{}

	txnGrps := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{
				transactions.SignedTxn{
					Txn: transactions.Transaction{
						Type: protocol.UnknownTx,
					},
				},
			},
		},
	}

	asyncEncoder := messageAsyncEncoder{
		state: &s,
		messageData: sentMessageMetadata{
			message: &transactionBlockMessage{
				Version: txnBlockMessageVersion,
				Round:   1,
			},
			transactionGroups: txnGrps,
			peer:              &Peer{},
		},
		roundClock: timers.MakeMonotonicClock(time.Now()),
	}

	asyncEncoder.state.messageSendWaitGroup.Add(1)

	err := asyncEncoder.asyncEncodeAndSend(nil)

	a.Nil(err)
	a.True(warnCalled)
	a.True(sendPeerMessageCalled)

}

// TestAsyncEncodeAndSend Tests that SendPeerMessage is called in the node connector
func TestAsyncEncodeAndSend(t *testing.T) {
	a := require.New(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	s.log = mockAsyncLogger{}
	sendPeerMessageCalled := false
	s.node = mockAsyncNodeConnector{called: &sendPeerMessageCalled}
	s.messageSendWaitGroup = sync.WaitGroup{}

	asyncEncoder := messageAsyncEncoder{
		state: &s,
		messageData: sentMessageMetadata{
			message: &transactionBlockMessage{
				Version: txnBlockMessageVersion,
				Round:   1,
			},
			peer: &Peer{},
		},
		roundClock: timers.MakeMonotonicClock(time.Now()),
	}

	asyncEncoder.state.messageSendWaitGroup.Add(1)

	err := asyncEncoder.asyncEncodeAndSend(nil)

	a.Nil(err)
	a.True(sendPeerMessageCalled)

}

// TestAssemblePeerMessage1 Tests assemblePeerMessage with messageConstBloomFilter msgOps
func TestAssemblePeerMessage1(t *testing.T) {
	a := require.New(t)

	s := syncState{clock: timers.MakeMonotonicClock(time.Now())}

	s.profiler = makeProfiler(1*time.Millisecond, s.clock, s.log, 1*time.Millisecond)

	peer := Peer{}

	pendingTransactions := pendingTransactionGroupsSnapshot{
		pendingTransactionsGroups: []transactions.SignedTxGroup{
			transactions.SignedTxGroup{},
		},
	}

	peer.setLocalRequestParams(111, 222)
	peer.lastReceivedMessageTimestamp = 100
	peer.lastReceivedMessageLocalRound = s.round

	expectedFilter := s.makeBloomFilter(requestParams{Offset: 111, Modulator: 222}, pendingTransactions.pendingTransactionsGroups, &s.lastBloomFilter)

	s.isRelay = true
	peer.isOutgoing = true
	peer.state = peerStateLateBloom

	metaMessage := s.assemblePeerMessage(&peer, &pendingTransactions)

	a.Equal(metaMessage.message.UpdatedRequestParams.Modulator, byte(222))
	a.Equal(metaMessage.message.UpdatedRequestParams.Offset, byte(111))
	a.Equal(metaMessage.peer, &peer)
	a.Equal(metaMessage.message.Version, int32(txnBlockMessageVersion))
	a.Equal(metaMessage.message.Round, s.round)
	a.True(metaMessage.message.MsgSync.ResponseElapsedTime != 0)
	a.Equal(s.lastBloomFilter, expectedFilter)
}

// TestAssemblePeerMessage2 Tests assemblePeerMessage with messageConstNextMinDelay | messageConstUpdateRequestParams msgOps
func TestAssemblePeerMessage2(t *testing.T) {

	a := require.New(t)

	s := syncState{clock: timers.MakeMonotonicClock(time.Now())}

	s.profiler = makeProfiler(1*time.Millisecond, s.clock, s.log, 1*time.Millisecond)

	peer := Peer{}

	pendingTransactions := pendingTransactionGroupsSnapshot{}

	peer.setLocalRequestParams(111, 222)
	peer.lastReceivedMessageTimestamp = 100
	peer.lastReceivedMessageLocalRound = s.round

	s.isRelay = true
	s.lastBeta = 123 * time.Nanosecond

	metaMessage := s.assemblePeerMessage(&peer, &pendingTransactions)

	a.Equal(metaMessage.message.UpdatedRequestParams.Modulator, byte(222))
	a.Equal(metaMessage.message.UpdatedRequestParams.Offset, byte(111))
	a.Equal(metaMessage.peer, &peer)
	a.Equal(metaMessage.message.Version, int32(txnBlockMessageVersion))
	a.Equal(metaMessage.message.Round, s.round)
	a.True(metaMessage.message.MsgSync.ResponseElapsedTime != 0)
	a.Equal(metaMessage.message.MsgSync.NextMsgMinDelay, uint64(s.lastBeta.Nanoseconds())*2)

}

// TestAssemblePeerMessage3 Tests assemblePeerMessage messageConstTransactions msgOps
func TestAssemblePeerMessage3(t *testing.T) {
	a := require.New(t)

	s := syncState{clock: timers.MakeMonotonicClock(time.Now())}

	s.profiler = makeProfiler(1*time.Millisecond, s.clock, s.log, 1*time.Millisecond)

	peer := Peer{}

	pendingTransactions := pendingTransactionGroupsSnapshot{
		latestLocallyOriginatedGroupCounter: 1,
		pendingTransactionsGroups: []transactions.SignedTxGroup{
			transactions.SignedTxGroup{
				LocallyOriginated: true,
				EncodedLength:     2,
			},
		},
	}

	peer.setLocalRequestParams(111, 222)
	peer.lastReceivedMessageTimestamp = 100
	peer.lastReceivedMessageLocalRound = s.round
	peer.requestedTransactionsModulator = 2
	peer.recentSentTransactions = makeTransactionCache(5, 10, 20)

	s.isRelay = false
	peer.isOutgoing = true
	peer.state = peerStateHoldsoff

	metaMessage := s.assemblePeerMessage(&peer, &pendingTransactions)

	a.Equal(len(metaMessage.transactionGroups), 1)
	a.True(reflect.DeepEqual(metaMessage.transactionGroups[0], pendingTransactions.pendingTransactionsGroups[0]))

}

func TestLocallyGeneratedTransactions(t *testing.T) {

	a := require.New(t)

	pendingTransactions := &pendingTransactionGroupsSnapshot{}

	s := syncState{}

	pendingTransactions.latestLocallyOriginatedGroupCounter = 1

	a.Equal(s.locallyGeneratedTransactions(pendingTransactions), []transactions.SignedTxGroup{})

	pendingTransactions.pendingTransactionsGroups = []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			LocallyOriginated: true,
			EncodedLength:     2,
		},
		transactions.SignedTxGroup{
			LocallyOriginated: false,
			EncodedLength:     1,
		},
		transactions.SignedTxGroup{
			LocallyOriginated: true,
			EncodedLength:     3,
		},
	}

	pendingTransactions.latestLocallyOriginatedGroupCounter = transactions.InvalidSignedTxGroupCounter

	a.Equal(s.locallyGeneratedTransactions(pendingTransactions), []transactions.SignedTxGroup{})

	pendingTransactions.latestLocallyOriginatedGroupCounter = 1

	expected := []transactions.SignedTxGroup{

		transactions.SignedTxGroup{
			LocallyOriginated: true,
			EncodedLength:     2,
		},

		transactions.SignedTxGroup{
			LocallyOriginated: true,
			EncodedLength:     3,
		},
	}

	a.Equal(s.locallyGeneratedTransactions(pendingTransactions), expected)

}
