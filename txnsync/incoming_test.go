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
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
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

	message := transactionBlockMessage{Version: 1}
	messageBytes := message.MarshalMsg(nil)
	sequenceNumber := uint64(1)
	incLogger := incomingLogger{}

	cfg := config.GetDefaultLocal()
	s := syncState{
		log: wrapLogger(&incLogger, &cfg)}

	// expect UnmarshalMsg error
	messageBytes[0] = 0
	err := s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber)
	msgpe := msgp.TypeError{}
	require.True(t, errors.As(err, &msgpe))

	// expect wrong version error
	message = transactionBlockMessage{Version: -3}
	messageBytes = message.MarshalMsg(nil)
	err = s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber)
	require.Equal(t, errUnsupportedTransactionSyncMessageVersion, err)

	// expect error decoding bloomFilter
	message.Version = 1
	message.TxnBloomFilter.BloomFilterType = byte(multiHashBloomFilter)
	messageBytes = message.MarshalMsg(nil)
	err = s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber)
	require.Equal(t, errInvalidBloomFilter, err)

	// error decoding transaction groups
	message.TxnBloomFilter.BloomFilterType = byte(xorBloomFilter32)
	message.TransactionGroups = packedTransactionGroups{Bytes: []byte{1}}
	messageBytes = message.MarshalMsg(nil)
	err = s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber)
	require.Equal(t, errDecodingReceivedTransactionGroupsFailed, err)

	// error queue full
	message.TransactionGroups = packedTransactionGroups{}
	messageBytes = message.MarshalMsg(nil)
	err = s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber)
	require.Equal(t, errTransactionSyncIncomingMessageQueueFull, err)

	// Success where peer == nil
	s.incomingMessagesQ = makeIncomingMessageQueue()
	err = s.asyncIncomingMessageHandler(nil, nil, messageBytes, sequenceNumber)
	require.NoError(t, err)

	peer := Peer{}

	// error when placing the peer message on the main queue (incomingMessages cannot accept messages)
	s.incomingMessagesQ = incomingMessageQueue{}
	err = s.asyncIncomingMessageHandler(nil, &peer, messageBytes, sequenceNumber)
	require.Equal(t, errTransactionSyncIncomingMessageQueueFull, err)

	s.incomingMessagesQ = makeIncomingMessageQueue()
	err = nil
	// fill up the incoming message queue (one was already added)
	for x := 1; x <= messageOrderingHeapLimit; x++ {
		require.NoError(t, err)
		err = s.asyncIncomingMessageHandler(nil, &peer, messageBytes, sequenceNumber)
	}
	require.Equal(t, errHeapReachedCapacity, err)
}

func TestEvaluateIncomingMessagePart1(t *testing.T) {

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
	// Add a peer here, and make sure it is cleared
	s.incomingMessagesQ.enqueuedPeers[peer] = struct{}{}
	mNodeConnector.peerInfo.TxnSyncPeer = peer
	peer.incomingMessages = messageOrderingHeap{}
	// TxnSyncPeer in peerInfo
	s.evaluateIncomingMessage(message)
	require.False(t, mNodeConnector.updatingPeers)
	_, found := s.incomingMessagesQ.enqueuedPeers[peer]
	require.False(t, found)

	// fill the hip with messageOrderingHeapLimit elements so that the incomingMessages enqueue fails
	for x := 0; x < messageOrderingHeapLimit; x++ {
		err := peer.incomingMessages.enqueue(message)
		require.NoError(t, err)
	}
	// Add a peer here, and make sure it is not cleared after the error
	s.incomingMessagesQ.enqueuedPeers[peer] = struct{}{}
	// TxnSyncPeer in peerInfo
	s.evaluateIncomingMessage(message)
	require.False(t, mNodeConnector.updatingPeers)
	_, found = s.incomingMessagesQ.enqueuedPeers[peer]
	require.True(t, found)
}

func TestEvaluateIncomingMessagePart2(t *testing.T) {

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
			bloomFilter:    bloomFilter{filterType: xorBloomFilter32},
			message:        transactionBlockMessage{Round: 4}})
	require.NoError(t, err)

	// message with a transaction group
	err = peer.incomingMessages.enqueue(
		incomingMessage{
			sequenceNumber: 4,
			transactionGroups: []transactions.SignedTxGroup{
				transactions.SignedTxGroup{
					Transactions: []transactions.SignedTxn{
						transactions.SignedTxn{}}}},
			message: transactionBlockMessage{Round: 4}})
	require.NoError(t, err)
	peer.recentSentTransactions = makeTransactionCache(5, 10, 20)

	// receive a message not in order
	s.evaluateIncomingMessage(incomingMessage{sequenceNumber: 11})
	require.Equal(t, "received message out of order; seq = 11, expecting seq = 5\n", incLogger.lastLogged)
	require.Equal(t, xorBloomFilter32, peer.recentIncomingBloomFilters[0].filter.filterType)

}

func TestEvaluateIncomingMessagePart3(t *testing.T) {

	cfg := config.GetDefaultLocal()
	cfg.EnableVerbosedTransactionSyncLogging = true
	peer := &Peer{isOutgoing: true, lastReceivedMessageNextMsgMinDelay: time.Duration(3)}

	incLogger := incomingLogger{}

	mNodeConnector := &mockNodeConnector{}
	mNodeConnector.peerInfo = PeerInfo{NetworkPeer: peer}
	mNodeConnector.peerInfo.TxnSyncPeer = peer

	s := syncState{
		node:    mNodeConnector,
		log:     wrapLogger(&incLogger, &cfg),
		clock:   mNodeConnector.Clock(),
		round:   1,
		config:  cfg,
		isRelay: true}

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
