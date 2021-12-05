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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/pooldata"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type incomingLogger struct {
	logging.Logger
	lastLogged string
}

func (ml *incomingLogger) Debugf(format string, args ...interface{}) {
	ml.lastLogged = fmt.Sprintf(format, args...)
}

func (ml *incomingLogger) Infof(format string, args ...interface{}) {
	ml.lastLogged = fmt.Sprintf(format, args...)
}

func TestAsyncIncomingMessageHandlerAndErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	message := transactionBlockMessage{Version: 1}
	messageBytes := message.MarshalMsg(nil)
	sequenceNumber := uint64(1)
	incLogger := incomingLogger{}

	cfg := config.GetDefaultLocal()
	mNodeConnector := &mockNodeConnector{transactionPoolSize: 3}
	s := syncState{
		log:               wrapLogger(&incLogger, &cfg),
		node:              mNodeConnector,
		clock:             mNodeConnector.Clock(),
		incomingMessagesQ: makeIncomingMessageQueue(),
	}

	// expect UnmarshalMsg error
	messageBytes[0] = 0
	err := s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber, 0)
	msgpe := msgp.TypeError{}
	require.True(t, errors.As(err, &msgpe))

	// expect wrong version error
	message = transactionBlockMessage{Version: -3}
	messageBytes = message.MarshalMsg(nil)
	err = s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber, 0)
	require.Equal(t, errUnsupportedTransactionSyncMessageVersion, err)

	// expect error decoding bloomFilter
	message.Version = 1
	message.TxnBloomFilter.BloomFilterType = byte(multiHashBloomFilter)
	messageBytes = message.MarshalMsg(nil)
	err = s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber, 0)
	require.Equal(t, errInvalidBloomFilter, err)

	// error decoding transaction groups
	message.TxnBloomFilter.BloomFilterType = byte(xorBloomFilter32)
	bf, _ := filterFactoryXor32(1, &s)
	bf.Set([]byte("aoeu1234aoeu1234"))
	message.TxnBloomFilter.BloomFilter, err = bf.MarshalBinary()
	require.NoError(t, err)
	message.TransactionGroups = packedTransactionGroups{Bytes: []byte{1}}
	messageBytes = message.MarshalMsg(nil)
	err = s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber, 0)
	require.Equal(t, errDecodingReceivedTransactionGroupsFailed, err)
	s.incomingMessagesQ.shutdown()

	peer := Peer{networkPeer: &s}

	// error queue full
	message.TransactionGroups = packedTransactionGroups{}
	messageBytes = message.MarshalMsg(nil)
	s.incomingMessagesQ = makeIncomingMessageQueue()
	s.incomingMessagesQ.fillMessageQueue(incomingMessage{peer: &peer, networkPeer: &s.incomingMessagesQ})
	mNodeConnector.peers = append(mNodeConnector.peers, PeerInfo{TxnSyncPeer: &peer, NetworkPeer: &s.incomingMessagesQ})
	err = s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber, 0)
	require.Equal(t, errTransactionSyncIncomingMessageQueueFull, err)
	s.incomingMessagesQ.shutdown()

	// Success where peer == nil
	s.incomingMessagesQ = makeIncomingMessageQueue()
	err = s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber, 0)
	require.NoError(t, err)
	s.incomingMessagesQ.shutdown()

	// error when placing the peer message on the main queue (incomingMessages cannot accept messages)
	s.incomingMessagesQ = makeIncomingMessageQueue()
	s.incomingMessagesQ.fillMessageQueue(incomingMessage{peer: nil, networkPeer: &s})
	mNodeConnector.peers = append(mNodeConnector.peers, PeerInfo{NetworkPeer: &s})

	err = s.asyncIncomingMessageHandler(nil, &peer, messageBytes, sequenceNumber, 0)
	require.Equal(t, errTransactionSyncIncomingMessageQueueFull, err)
	s.incomingMessagesQ.shutdown()

	s.incomingMessagesQ = makeIncomingMessageQueue()
	err = nil
	// fill up the incoming message queue (one was already added)
	for x := 1; x <= messageOrderingHeapLimit; x++ {
		require.NoError(t, err)
		err = s.asyncIncomingMessageHandler(nil, &peer, messageBytes, sequenceNumber, 0)
	}
	require.Equal(t, errHeapReachedCapacity, err)
	s.incomingMessagesQ.shutdown()
}

func TestEvaluateIncomingMessagePart1(t *testing.T) {
	partitiontest.PartitionTest(t)

	message := incomingMessage{}
	cfg := config.GetDefaultLocal()
	peer := &Peer{}

	incLogger := incomingLogger{}

	mNodeConnector := &mockNodeConnector{}
	mNodeConnector.peerInfo = PeerInfo{}
	s := syncState{
		node:  mNodeConnector,
		log:   wrapLogger(&incLogger, &cfg),
		clock: mNodeConnector.Clock()}

	// Test the cases inside the peer == nil condition

	// the message.networkPeer isn't a valid unicast peer
	s.evaluateIncomingMessage(message)

	// peer was already created
	mNodeConnector.peerInfo.NetworkPeer = peer

	s.evaluateIncomingMessage(message)
	// no TxnSyncPeer in peerInfo
	require.True(t, mNodeConnector.updatingPeers)
	mNodeConnector.updatingPeers = false

	s.incomingMessagesQ = makeIncomingMessageQueue()
	defer s.incomingMessagesQ.shutdown()
	message.peer = peer
	require.True(t, s.incomingMessagesQ.enqueue(message))
	mNodeConnector.peerInfo.TxnSyncPeer = peer
	peer.incomingMessages = messageOrderingHeap{}
	// TxnSyncPeer in peerInfo
	s.evaluateIncomingMessage(message)
	require.False(t, mNodeConnector.updatingPeers)
	<-s.incomingMessagesQ.getIncomingMessageChannel()
	_, found := s.incomingMessagesQ.enqueuedPeersMap[peer]
	require.False(t, found)

	// fill the heap with messageOrderingHeapLimit elements so that the incomingMessages enqueue fails
	message.networkPeer = &s
	message.peer = nil
	for x := 0; x < messageOrderingHeapLimit; x++ {
		err := peer.incomingMessages.enqueue(message)
		require.NoError(t, err)
	}
	mNodeConnector.peers = []PeerInfo{{TxnSyncPeer: peer, NetworkPeer: &s}}
	// TxnSyncPeer in peerInfo
	s.evaluateIncomingMessage(message)
	require.False(t, mNodeConnector.updatingPeers)
}

func TestEvaluateIncomingMessagePart2(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.EnableVerbosedTransactionSyncLogging = true
	peer := &Peer{}

	incLogger := incomingLogger{}

	mNodeConnector := &mockNodeConnector{transactionPoolSize: 3}
	mNodeConnector.peerInfo = PeerInfo{NetworkPeer: peer}

	s := syncState{
		node:  mNodeConnector,
		log:   wrapLogger(&incLogger, &cfg),
		clock: mNodeConnector.Clock()}

	// Test the branches in the for loop

	mNodeConnector.peerInfo.TxnSyncPeer = peer
	peer.incomingMessages = messageOrderingHeap{}

	// txnsync messages with proposalData
	err := peer.incomingMessages.enqueue(
		incomingMessage{
			sequenceNumber: 0,
			message: transactionBlockMessage{
				RelayedProposal: relayedProposal{Content: 10}}})
	require.NoError(t, err)

	// update the round number
	err = peer.incomingMessages.enqueue(
		incomingMessage{
			sequenceNumber: 1,
			message:        transactionBlockMessage{Round: 4}})
	require.NoError(t, err)

	// peer sent a message for an older round, *after* a new round
	err = peer.incomingMessages.enqueue(
		incomingMessage{
			sequenceNumber: 2,
			message:        transactionBlockMessage{Round: 2}})
	require.NoError(t, err)

	// peer sends a bloom filter
	err = peer.incomingMessages.enqueue(
		incomingMessage{
			sequenceNumber: 3,
			bloomFilter:    &testableBloomFilter{encodingParams: requestParams{Offset: 8}},
			message:        transactionBlockMessage{Round: 4}})
	require.NoError(t, err)

	// message with a transaction group
	err = peer.incomingMessages.enqueue(
		incomingMessage{
			sequenceNumber: 4,
			transactionGroups: []pooldata.SignedTxGroup{
				pooldata.SignedTxGroup{
					Transactions: []transactions.SignedTxn{
						transactions.SignedTxn{}}}},
			message: transactionBlockMessage{Round: 4}})
	require.NoError(t, err)
	peer.recentSentTransactions = makeTransactionCache(5, 10, 20)

	// receive a message not in order
	s.evaluateIncomingMessage(incomingMessage{sequenceNumber: 11})
	require.Equal(t, "received message out of order; seq = 11, expecting seq = 5\n", incLogger.lastLogged)
	require.Equal(t, uint8(8), peer.recentIncomingBloomFilters[0].filter.encodingParams.Offset)

	// currentTransactionPoolSize is -1
	peer.incomingMessages = messageOrderingHeap{}
	mNodeConnector.transactionPoolSize = -1
	s.evaluateIncomingMessage(incomingMessage{
		sequenceNumber: 5,
		message:        transactionBlockMessage{Round: 5},
		transactionGroups: []pooldata.SignedTxGroup{
			pooldata.SignedTxGroup{
				Transactions: []transactions.SignedTxn{
					transactions.SignedTxn{}}}},
	})
	require.Equal(t, "Incoming Txsync #5 round 5 transactions 1 request [0/0] bloom 0 nextTS 0 from ''", incLogger.lastLogged)

}

func TestEvaluateIncomingMessagePart3(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.EnableVerbosedTransactionSyncLogging = true
	peer := &Peer{isOutgoing: true, lastReceivedMessageNextMsgMinDelay: time.Duration(3)}

	incLogger := incomingLogger{}

	mNodeConnector := &mockNodeConnector{}
	mNodeConnector.peerInfo = PeerInfo{NetworkPeer: peer}
	mNodeConnector.peerInfo.TxnSyncPeer = peer

	s := syncState{
		node:      mNodeConnector,
		log:       wrapLogger(&incLogger, &cfg),
		clock:     mNodeConnector.Clock(),
		round:     1,
		config:    cfg,
		isRelay:   true,
		scheduler: makePeerScheduler(),
	}

	// the peer will be added to s.scheduler
	s.evaluateIncomingMessage(incomingMessage{
		sequenceNumber: 0,
		message: transactionBlockMessage{
			MsgSync: timingParams{
				NextMsgMinDelay: 3}}})
	require.Equal(t, 1, len(s.scheduler.peers))

	s.round = 3
	s.evaluateIncomingMessage(incomingMessage{
		sequenceNumber: 1,
		message: transactionBlockMessage{
			MsgSync: timingParams{
				NextMsgMinDelay: 3}}})

	require.Equal(t, "Incoming Txsync #1 late round 0", incLogger.lastLogged)
}

func TestEvaluateIncomingMessageAccumulatedTransactionsCount(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.EnableVerbosedTransactionSyncLogging = true
	peer := &Peer{}
	peer.recentSentTransactions = makeTransactionCache(5, 10, 20)
	incLogger := incomingLogger{}

	mNodeConnector := &mockNodeConnector{transactionPoolSize: 3}
	mNodeConnector.peerInfo = PeerInfo{NetworkPeer: peer}

	s := syncState{
		node:  mNodeConnector,
		log:   wrapLogger(&incLogger, &cfg),
		clock: mNodeConnector.Clock()}

	mNodeConnector.peerInfo.TxnSyncPeer = peer
	peer.incomingMessages = messageOrderingHeap{}

	genesisID := "gID"
	genesisHash := crypto.Hash([]byte("gh"))
	txnGroups := getTxnGroups(genesisHash, genesisID)

	// test with more than 200 transactions in the txnGroups
	for x := 0; x < 100; x++ {
		t := getTxnGroups(genesisHash, genesisID)
		txnGroups = append(txnGroups, t...)
	}

	ptg, err := s.encodeTransactionGroups(txnGroups, 1000000000)
	require.NoError(t, err)
	txGroups, err := decodeTransactionGroups(ptg, genesisID, genesisHash)
	require.NoError(t, err)

	s.evaluateIncomingMessage(incomingMessage{
		sequenceNumber:    0,
		message:           transactionBlockMessage{Round: 5},
		transactionGroups: txGroups,
	})
	require.Equal(t, time.Duration(115586426), s.lastBeta)
}
