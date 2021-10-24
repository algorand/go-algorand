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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/pooldata"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/execpool"
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
	partitiontest.PartitionTest(t)

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
		roundClock:     timers.MakeMonotonicClock(time.Now()),
		sentMessagesCh: s.outgoingMessagesCallbackCh,
	}

	oldTimestamp := asyncEncoder.messageData.sentTimestamp
	a.Equal(asyncEncoder.asyncMessageSent(false, 0), errTransactionSyncOutgoingMessageSendFailed)
	err := asyncEncoder.asyncMessageSent(true, 1337)
	a.Equal(err, errTransactionSyncOutgoingMessageQueueFull)
	a.Equal(asyncEncoder.messageData.sentTimestamp, oldTimestamp)
	a.Equal(asyncEncoder.messageData.sequenceNumber, uint64(1337))

	// Make this buffered for now so we catch the select statement
	asyncEncoder.sentMessagesCh = make(chan sentMessageMetadata, 1)

	err = asyncEncoder.asyncMessageSent(true, 1337)
	a.Nil(err)
	a.Equal(1, len(asyncEncoder.sentMessagesCh))
}

type mockAsyncNodeConnector struct {
	NodeConnector
	called        *bool
	largeTxnGroup bool
}

func (m mockAsyncNodeConnector) Random(rng uint64) uint64 {
	// We need to be deterministic in our "randomness" for the tests
	return 42
}

func (m mockAsyncNodeConnector) SendPeerMessage(netPeer interface{}, msg []byte, callback SendMessageCallback) {
	*m.called = true
}

func (m mockAsyncNodeConnector) GetPendingTransactionGroups() (txGroups []pooldata.SignedTxGroup, latestLocallyOriginatedGroupCounter uint64) {
	if m.largeTxnGroup {
		rval := []pooldata.SignedTxGroup{}
		for i := 0; i < 100000; i++ {
			// Because we use this with non-relay nodes, the syncState will
			// use the locallyGeneratedTransactions() function.
			// To make sure we fill the values appropriately, we are going to
			// set every value here to be locally originated
			// Additionally, we want the encoded length to be 1000 (or something rather large)
			// to make sure that we can attain partial messages (see TestSendMessageLoop test)
			rval = append(rval, pooldata.SignedTxGroup{EncodedLength: 1000, LocallyOriginated: true})
		}

		return rval, 1
	}
	return []pooldata.SignedTxGroup{}, 1
}

// TestAsyncEncodeAndSendErr Tests response when encodeTransactionGroups doesn't return an error
func TestAsyncEncodeAndSendNonErr(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	warnCalled := false
	s.log = mockAsyncLogger{warnCalled: &warnCalled}
	sendPeerMessageCalled := false
	s.node = mockAsyncNodeConnector{called: &sendPeerMessageCalled}
	s.messageSendWaitGroup = sync.WaitGroup{}

	txnGrps := []pooldata.SignedTxGroup{
		pooldata.SignedTxGroup{
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
	a.Nil(asyncEncoder.messageData.transactionGroups)
}

// TestAsyncEncodeAndSendErr Tests response when encodeTransactionGroups returns an error
func TestAsyncEncodeAndSendErr(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var s syncState
	s.clock = timers.MakeMonotonicClock(time.Now())
	warnCalled := false
	s.log = mockAsyncLogger{warnCalled: &warnCalled}
	sendPeerMessageCalled := false
	s.node = mockAsyncNodeConnector{called: &sendPeerMessageCalled}
	s.messageSendWaitGroup = sync.WaitGroup{}

	txnGrps := []pooldata.SignedTxGroup{
		pooldata.SignedTxGroup{
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
	partitiontest.PartitionTest(t)

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
	a.NotZero(asyncEncoder.messageData.sentTimestamp)

}

// TestAssemblePeerMessage_messageConstBloomFilter Tests assemblePeerMessage with messageConstBloomFilter msgOps
func TestAssemblePeerMessage_messageConstBloomFilter(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	s := syncState{
		node:  mockAsyncNodeConnector{},
		clock: timers.MakeMonotonicClock(time.Now()),
	}

	s.profiler = makeProfiler(1*time.Millisecond, s.clock, s.log, 1*time.Millisecond)

	peer := Peer{}

	pendingTransactions := pendingTransactionGroupsSnapshot{
		pendingTransactionsGroups: []pooldata.SignedTxGroup{
			pooldata.SignedTxGroup{},
		},
	}

	peer.setLocalRequestParams(111, 222)
	peer.lastReceivedMessageTimestamp = 100
	peer.lastReceivedMessageLocalRound = s.round

	expectedFilter := s.makeBloomFilter(requestParams{Offset: 111, Modulator: 222}, pendingTransactions.pendingTransactionsGroups, nil, &s.lastBloomFilter)

	s.isRelay = true
	peer.isOutgoing = true
	peer.state = peerStateLateBloom

	metaMessage, _, responseTime := s.assemblePeerMessage(&peer, &pendingTransactions)

	a.Equal(metaMessage.message.UpdatedRequestParams.Modulator, byte(222))
	a.Equal(metaMessage.message.UpdatedRequestParams.Offset, byte(111))
	a.Equal(metaMessage.peer, &peer)
	a.Equal(metaMessage.message.Version, int32(txnBlockMessageVersion))
	a.Equal(metaMessage.message.Round, s.round)
	a.True(responseTime >= 0)
	a.Equal(s.lastBloomFilter, expectedFilter)
}

// TestAssemblePeerMessage_messageConstBloomFilterNonRelay Tests assemblePeerMessage with messageConstBloomFilter msgOps in a non-relay scenario
func TestAssemblePeerMessage_messageConstBloomFilterNonRelay(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	s := syncState{
		node:  mockAsyncNodeConnector{largeTxnGroup: true},
		clock: timers.MakeMonotonicClock(time.Now()),
	}

	s.profiler = makeProfiler(1*time.Millisecond, s.clock, s.log, 1*time.Millisecond)

	peer := Peer{}

	pendingTransactions := pendingTransactionGroupsSnapshot{
		pendingTransactionsGroups: []pooldata.SignedTxGroup{
			pooldata.SignedTxGroup{},
		},
	}

	peer.setLocalRequestParams(111, 222)
	peer.lastReceivedMessageTimestamp = 100
	peer.lastReceivedMessageLocalRound = s.round

	expectedFilter := s.makeBloomFilter(requestParams{Offset: 111, Modulator: 222}, pendingTransactions.pendingTransactionsGroups, nil, &s.lastBloomFilter)

	s.isRelay = false
	s.fetchTransactions = true
	peer.isOutgoing = true
	peer.state = peerStateLateBloom

	metaMessage, _, responseTime := s.assemblePeerMessage(&peer, &pendingTransactions)

	a.Equal(metaMessage.message.UpdatedRequestParams.Modulator, byte(222))
	a.Equal(metaMessage.message.UpdatedRequestParams.Offset, byte(111))
	a.Equal(metaMessage.peer, &peer)
	a.Equal(metaMessage.message.Version, int32(txnBlockMessageVersion))
	a.Equal(metaMessage.message.Round, s.round)
	a.True(responseTime >= 0)
	a.NotEqual(s.lastBloomFilter, expectedFilter)
}

// TestAssemblePeerMessage_messageConstNextMinDelay_messageConstUpdateRequestParams Tests assemblePeerMessage with messageConstNextMinDelay | messageConstUpdateRequestParams msgOps
func TestAssemblePeerMessage_messageConstNextMinDelay_messageConstUpdateRequestParams(t *testing.T) {
	partitiontest.PartitionTest(t)

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

	metaMessage, _, responseTime := s.assemblePeerMessage(&peer, &pendingTransactions)

	a.Equal(metaMessage.message.UpdatedRequestParams.Modulator, byte(222))
	a.Equal(metaMessage.message.UpdatedRequestParams.Offset, byte(111))
	a.Equal(metaMessage.peer, &peer)
	a.Equal(metaMessage.message.Version, int32(txnBlockMessageVersion))
	a.Equal(metaMessage.message.Round, s.round)
	a.True(responseTime >= 0)
	a.Equal(metaMessage.message.MsgSync.NextMsgMinDelay, uint64(s.lastBeta.Nanoseconds())*2)

}

// TestAssemblePeerMessage_messageConstTransactions Tests assemblePeerMessage messageConstTransactions msgOps
func TestAssemblePeerMessage_messageConstTransactions(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	s := syncState{clock: timers.MakeMonotonicClock(time.Now())}

	s.profiler = makeProfiler(1*time.Millisecond, s.clock, s.log, 1*time.Millisecond)

	peer := Peer{}

	pendingTransactions := pendingTransactionGroupsSnapshot{
		latestLocallyOriginatedGroupCounter: 1,
		pendingTransactionsGroups: []pooldata.SignedTxGroup{
			pooldata.SignedTxGroup{
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

	metaMessage, _, _ := s.assemblePeerMessage(&peer, &pendingTransactions)

	a.Equal(len(metaMessage.transactionGroups), 1)
	a.True(reflect.DeepEqual(metaMessage.transactionGroups[0], pendingTransactions.pendingTransactionsGroups[0]))

}

// TestLocallyGeneratedTransactions Separately tests that generating transactions are being
// correctly made given a signed transaction group array.
func TestLocallyGeneratedTransactions(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	pendingTransactions := &pendingTransactionGroupsSnapshot{}

	s := syncState{}

	pendingTransactions.latestLocallyOriginatedGroupCounter = 1

	a.Equal(s.locallyGeneratedTransactions(pendingTransactions), []pooldata.SignedTxGroup{})

	pendingTransactions.pendingTransactionsGroups = []pooldata.SignedTxGroup{
		pooldata.SignedTxGroup{
			LocallyOriginated: true,
			EncodedLength:     2,
		},
		pooldata.SignedTxGroup{
			LocallyOriginated: false,
			EncodedLength:     1,
		},
		pooldata.SignedTxGroup{
			LocallyOriginated: true,
			EncodedLength:     3,
		},
	}

	pendingTransactions.latestLocallyOriginatedGroupCounter = pooldata.InvalidSignedTxGroupCounter

	a.Equal(s.locallyGeneratedTransactions(pendingTransactions), []pooldata.SignedTxGroup{})

	pendingTransactions.latestLocallyOriginatedGroupCounter = 1

	expected := []pooldata.SignedTxGroup{

		pooldata.SignedTxGroup{
			LocallyOriginated: true,
			EncodedLength:     2,
		},

		pooldata.SignedTxGroup{
			LocallyOriginated: true,
			EncodedLength:     3,
		},
	}

	a.Equal(s.locallyGeneratedTransactions(pendingTransactions), expected)

}

type mockBacklogThreadPool struct {
	execpool.BacklogPool
	enqueueCalled *int
}

func (b *mockBacklogThreadPool) EnqueueBacklog(enqueueCtx context.Context, t execpool.ExecFunc, arg interface{}, out chan interface{}) error {
	if b.enqueueCalled != nil {
		*b.enqueueCalled++
	}

	return nil
}

// TestEnqueue directly tests that enqueue will call the Done() function for the messageSendWaitGroup
func TestEnqueue(t *testing.T) {

	partitiontest.PartitionTest(t)

	s := syncState{clock: timers.MakeMonotonicClock(time.Now())}
	s.log = mockAsyncLogger{}
	s.node = &mockNodeConnector{}
	s.threadpool = execpool.MakeBacklog(execpool.MakePool(t), 5, execpool.LowPriority, t)

	prof := makeProfiler(2*time.Millisecond, s.clock, s.log, 3*time.Millisecond)
	s.profiler = prof

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

	asyncEncoder.enqueue()

	// Wait for the enqueued function to return the messageSendWaitGroup
	s.messageSendWaitGroup.Wait()

	// Dummy require to make sure we pass this test...the real value of this test
	// is to make sure that the wait group is appropriately set
	require.True(t, true)

}

// TestSendMessageLoop tests the send message loop
func TestSendMessageLoop(t *testing.T) {

	partitiontest.PartitionTest(t)

	enqueueCalled := 0

	s := syncState{
		clock:     timers.MakeMonotonicClock(time.Now()),
		scheduler: makePeerScheduler(),
	}
	s.log = mockAsyncLogger{}
	// Get a large amount of signed txns with a low data exchange rate
	// to get partial messages to trigger peerOpsClearInterruptible
	s.node = &mockAsyncNodeConnector{largeTxnGroup: true}
	s.threadpool = &mockBacklogThreadPool{enqueueCalled: &enqueueCalled}

	prof := makeProfiler(2*time.Millisecond, s.clock, s.log, 3*time.Millisecond)
	s.profiler = prof
	s.interruptablePeersMap = make(map[*Peer]int)

	peers := []*Peer{
		//  peerOpsReschedule
		&Peer{
			recentSentTransactions:         makeTransactionCache(10, 20, 10),
			requestedTransactionsModulator: 2,
			// Reduced rate to trigger partial messages
			dataExchangeRate: 10,
			// greater than 0 for state machine logic
			nextStateTimestamp: 1 * time.Millisecond,
		},
		&Peer{
			recentSentTransactions:         makeTransactionCache(10, 20, 10),
			requestedTransactionsModulator: 2,
			// Reduced rate to trigger partial messages
			dataExchangeRate: 10,
			// greater than 0 for state machine logic
			nextStateTimestamp: 1 * time.Millisecond,
		},
	}

	// Add the peers to test that peerOpsClearInterruptible removes them

	for _, p := range peers {
		s.interruptablePeers = append(s.interruptablePeers, p)
		s.interruptablePeersMap[p] = len(s.interruptablePeers) - 1
	}

	// The deadline is set to a ridiculously high number to make sure that we cycle through all our peers
	// and not break
	s.sendMessageLoop(s.clock.Since(), s.clock.DeadlineMonitorAt(s.clock.Since()+5*time.Minute), peers)

	require.Equal(t, 2, enqueueCalled)
	require.Equal(t, 0, len(s.interruptablePeersMap))

}

// TestEvaluateOutgoingMessage tests the evaluateOutgoingMessage function of syncState
func TestEvaluateOutgoingMessage(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	s := syncState{clock: timers.MakeMonotonicClock(time.Now())}
	s.log = mockAsyncLogger{}

	peer := Peer{
		recentSentTransactions: makeTransactionCache(10, 20, 10),
	}

	sentMessage := sentMessageMetadata{
		sentTimestamp:           time.Duration(time.Millisecond * 1234),
		message:                 &transactionBlockMessage{Round: 3},
		sequenceNumber:          42,
		projectedSequenceNumber: 44,
		encodedMessageSize:      23,
		peer:                    &peer,
	}

	s.evaluateOutgoingMessage(sentMessage)
	// This should be zero because sequenceNumber and projectedSequenceNumber are not equal
	a.Equal(peer.lastSentMessageTimestamp, 0*time.Millisecond)

	a.Equal(peer.lastSentMessageSequenceNumber, uint64(42))
	a.Equal(peer.lastSentMessageRound, basics.Round(3))
	a.Equal(peer.lastSentMessageSize, 23)

	sentMessage.sequenceNumber = sentMessage.projectedSequenceNumber

	s.evaluateOutgoingMessage(sentMessage)
	a.Equal(peer.lastSentMessageTimestamp, 1234*time.Millisecond)

	a.Equal(peer.lastSentMessageSequenceNumber, uint64(44))
	a.Equal(peer.lastSentMessageRound, basics.Round(3))
	a.Equal(peer.lastSentMessageSize, 23)
}
