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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/util/timers"
)

//msgp:ignore eventType
type eventType int

const (
	transactionPoolChangedEvent eventType = 1
	newRoundEvent               eventType = 2
)

// RoundSettings is used to communicate the transaction syncer setting for a specific round
type RoundSettings struct {
	Round             basics.Round
	FetchTransactions bool // for non-relays that has no participation keys, there is no need to request transactions
}

// Event is an external triggering event
type Event struct {
	eventType

	transactionPoolSize int
	roundSettings       RoundSettings
}

// IncomingMessageHandler is the signature of the incoming message handler used by the transaction sync to receive network messages
type IncomingMessageHandler func(networkPeer interface{}, peer *Peer, message []byte, sequenceNumber uint64) error

// SendMessageCallback define a message sent feedback for performing message tracking
type SendMessageCallback func(enqueued bool, sequenceNumber uint64) error

// PeerInfo describes a single peer returned by GetPeers or GetPeer
type PeerInfo struct {
	TxnSyncPeer *Peer
	NetworkPeer interface{}
	IsOutgoing  bool
}

// networkPeerAddress is a subset of the network package HTTPPeer and UnicastPeer interface that
// provides feedback for the destination address. It's used for logging out packet's destination addresses.
type networkPeerAddress interface {
	GetAddress() string
}

// NodeConnector is used by the transaction sync for communicating with components external to the txnsync package.
type NodeConnector interface {
	Events() <-chan Event
	GetCurrentRoundSettings() RoundSettings // return the current round settings from the node
	Clock() timers.WallClock
	Random(uint64) uint64
	GetPeers() []PeerInfo
	GetPeer(interface{}) PeerInfo // get a single peer given a network peer opaque interface
	UpdatePeers([]*Peer, []interface{})
	SendPeerMessage(netPeer interface{}, msg []byte, callback SendMessageCallback)
	// GetPendingTransactionGroups is called by the transaction sync when it needs to look into the transaction
	// pool and get the updated set of pending transactions. The second returned argument is the latest group counter
	// within the given transaction groups list. If there is no group that is locally originated, the expected value is
	// InvalidSignedTxGroupCounter.
	GetPendingTransactionGroups() (txGroups []transactions.SignedTxGroup, latestLocallyOriginatedGroupCounter uint64)
	// IncomingTransactionGroups is called by the transaction sync when transactions have been received and need
	// to be stored in the transaction pool
	IncomingTransactionGroups(interface{}, []transactions.SignedTxGroup) (transactionPoolSize int)
	NotifyMonitor() chan struct{}
}

// MakeTranscationPoolChangeEvent creates an event for when a txn pool size has changed.
func MakeTranscationPoolChangeEvent(transactionPoolSize int) Event {
	return Event{
		eventType:           transactionPoolChangedEvent,
		transactionPoolSize: transactionPoolSize,
	}
}

// MakeNewRoundEvent creates an event for when a new round starts
func MakeNewRoundEvent(roundNumber basics.Round, fetchTransactions bool) Event {
	return Event{
		eventType: newRoundEvent,
		roundSettings: RoundSettings{
			Round:             roundNumber,
			FetchTransactions: fetchTransactions,
		},
	}
}
