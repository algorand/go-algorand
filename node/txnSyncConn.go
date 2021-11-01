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

// Package node is the Algorand node itself, with functions exposed to the frontend
package node

import (
	"context"
	"time"

	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/pooldata"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/txnsync"
	"github.com/algorand/go-algorand/util/timers"
)

// txnsyncPeerDataKey is the key name by which we're going to store the
// transaction sync internal data object inside the network peer.
const txnsyncPeerDataKey = "txsync"

// transactionSyncNodeConnector implements the txnsync.NodeConnector interface, allowing the
// transaction sync communicate with the node and it's child objects.
type transactionSyncNodeConnector struct {
	node           *AlgorandFullNode
	eventsCh       chan txnsync.Event
	clock          timers.WallClock
	messageHandler txnsync.IncomingMessageHandler
	txHandler      data.SolicitedAsyncTxHandler
	openStateCh    chan struct{}
}

func makeTransactionSyncNodeConnector(node *AlgorandFullNode) *transactionSyncNodeConnector {
	return &transactionSyncNodeConnector{
		node:        node,
		eventsCh:    make(chan txnsync.Event, 1),
		clock:       timers.MakeMonotonicClock(time.Now()),
		txHandler:   node.txHandler.SolicitedAsyncTxHandler(),
		openStateCh: make(chan struct{}),
	}
}

func (tsnc *transactionSyncNodeConnector) Events() <-chan txnsync.Event {
	return tsnc.eventsCh
}

// GetCurrentRoundSettings is called when the txsync is starting up, proving
// round information.
func (tsnc *transactionSyncNodeConnector) GetCurrentRoundSettings() txnsync.RoundSettings {
	round := tsnc.node.ledger.Latest()
	return txnsync.RoundSettings{
		Round:             round,
		FetchTransactions: tsnc.node.config.ForceFetchTransactions || tsnc.node.accountManager.HasLiveKeys(round, round),
	}
}

// NotifyMonitor is used for testing purposes only, and can remain(almost) empty on production code.
func (tsnc *transactionSyncNodeConnector) NotifyMonitor() chan struct{} {
	return tsnc.openStateCh
}

func (tsnc *transactionSyncNodeConnector) Random(upperBound uint64) uint64 {
	return tsnc.node.Uint64() % upperBound
}

func (tsnc *transactionSyncNodeConnector) Clock() timers.WallClock {
	return tsnc.clock
}

func (tsnc *transactionSyncNodeConnector) GetPeer(networkPeer interface{}) txnsync.PeerInfo {
	unicastPeer := networkPeer.(network.UnicastPeer)
	if unicastPeer == nil {
		return txnsync.PeerInfo{}
	}

	peerData := tsnc.node.net.GetPeerData(networkPeer, txnsyncPeerDataKey)
	if peerData == nil {
		return txnsync.PeerInfo{
			IsOutgoing:  unicastPeer.IsOutgoing(),
			NetworkPeer: unicastPeer,
		}
	}
	return txnsync.PeerInfo{
		IsOutgoing:  unicastPeer.IsOutgoing(),
		NetworkPeer: unicastPeer,
		TxnSyncPeer: peerData.(*txnsync.Peer),
	}
}

func (tsnc *transactionSyncNodeConnector) GetPeers() (peersInfo []txnsync.PeerInfo) {
	networkPeers := tsnc.node.net.GetPeers(network.PeersConnectedOut, network.PeersConnectedIn)
	peersInfo = make([]txnsync.PeerInfo, len(networkPeers))
	k := 0
	for i := range networkPeers {
		unicastPeer := networkPeers[i].(network.UnicastPeer)
		if unicastPeer == nil {
			continue
		}
		// check version.
		if unicastPeer.Version() != "3.0" {
			continue
		}
		peersInfo[k].IsOutgoing = unicastPeer.IsOutgoing()
		peersInfo[k].NetworkPeer = networkPeers[i]
		peerData := tsnc.node.net.GetPeerData(networkPeers[i], txnsyncPeerDataKey)
		if peerData != nil {
			peersInfo[k].TxnSyncPeer = peerData.(*txnsync.Peer)
		}
		k++
	}

	return peersInfo[:k]
}

func (tsnc *transactionSyncNodeConnector) UpdatePeers(txnsyncPeers []*txnsync.Peer, netPeers []interface{}, averageDataExchangeRate uint64) {
	for i, netPeer := range netPeers {
		tsnc.node.net.SetPeerData(netPeer, txnsyncPeerDataKey, txnsyncPeers[i])
	}
	// The average peers data exchange rate has been updated.
	if averageDataExchangeRate > 0 {
		// update the transaction pool with the latest peers data exchange rate.
		tsnc.node.transactionPool.SetDataExchangeRate(averageDataExchangeRate)
	}
}

func (tsnc *transactionSyncNodeConnector) SendPeerMessage(netPeer interface{}, msg []byte, callback txnsync.SendMessageCallback) {
	unicastPeer := netPeer.(network.UnicastPeer)
	if unicastPeer == nil {
		return
	}

	// this might return an error to the network package callback routine. Returning an error signal the network package
	// that we want to disconnect from this peer. This aligns with the transaction sync txnsync.SendMessageCallback function
	// behaviour.
	if err := unicastPeer.Unicast(context.Background(), msg, protocol.Txn2Tag, network.UnicastWebsocketMessageStateCallback(callback)); err != nil {
		if callbackErr := callback(false, 0); callbackErr != nil {
			// disconnect from peer - the transaction sync wasn't able to process message sending confirmation
			tsnc.node.net.Disconnect(unicastPeer)
		}
	}
}

// GetPendingTransactionGroups is called by the transaction sync when it needs to look into the transaction
// pool and get the updated set of pending transactions. The second returned argument is the latest locally originated
// group counter within the given transaction groups list. If there is no group that is locally originated, the expected
// value is InvalidSignedTxGroupCounter.
func (tsnc *transactionSyncNodeConnector) GetPendingTransactionGroups() ([]pooldata.SignedTxGroup, uint64) {
	return tsnc.node.transactionPool.PendingTxGroups()
}

func (tsnc *transactionSyncNodeConnector) onNewTransactionPoolEntry(transactionPoolSize int) {
	select {
	case tsnc.eventsCh <- txnsync.MakeTransactionPoolChangeEvent(transactionPoolSize, false):
	default:
	}
}

// OnNewBlock receives a notification that we've moved to a new round from the ledger.
// This notification would be received before the transaction pool get a similar notification, due
// the ordering of the block notifier registration.
func (tsnc *transactionSyncNodeConnector) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	blkRound := block.Round()

	fetchTransactions := tsnc.node.config.ForceFetchTransactions || tsnc.node.accountManager.HasLiveKeys(blkRound, blkRound)
	// if this is a relay, then we always want to fetch transactions, regardless if we have participation keys.
	if tsnc.node.config.NetAddress != "" {
		fetchTransactions = true
	}

	select {
	case tsnc.eventsCh <- txnsync.MakeNewRoundEvent(blkRound, fetchTransactions):
	default:
	}

}

func (tsnc *transactionSyncNodeConnector) start() {
	tsnc.txHandler.Start()
	tsnc.messageHandler = tsnc.node.txnSyncService.GetIncomingMessageHandler()
	handlers := []network.TaggedMessageHandler{
		{Tag: protocol.Txn2Tag, MessageHandler: tsnc},
	}
	tsnc.node.net.RegisterHandlers(handlers)
}

func (tsnc *transactionSyncNodeConnector) Handle(raw network.IncomingMessage) network.OutgoingMessage {
	unicastPeer := raw.Sender.(network.UnicastPeer)
	if unicastPeer != nil {
		// check version.
		if unicastPeer.Version() != "3.0" {
			return network.OutgoingMessage{
				Action: network.Ignore,
			}
		}
	}
	var peer *txnsync.Peer
	peerData := tsnc.node.net.GetPeerData(raw.Sender, txnsyncPeerDataKey)
	if peerData != nil {
		peer = peerData.(*txnsync.Peer)
	}

	err := tsnc.messageHandler(raw.Sender, peer, raw.Data, raw.Sequence)
	if err != nil {
		return network.OutgoingMessage{
			Action: network.Disconnect,
		}
	}
	return network.OutgoingMessage{
		Action: network.Ignore,
	}
}

func (tsnc *transactionSyncNodeConnector) stop() {
	tsnc.txHandler.Stop()
}

func (tsnc *transactionSyncNodeConnector) IncomingTransactionGroups(peer *txnsync.Peer, messageSeq uint64, txGroups []pooldata.SignedTxGroup) (transactionPoolSize int) {
	if tsnc.txHandler.HandleTransactionGroups(peer.GetNetworkPeer(), peer.GetTransactionPoolAckChannel(), messageSeq, txGroups) {
		transactionPoolSize = tsnc.node.transactionPool.PendingCount()
	} else {
		transactionPoolSize = -1
	}
	return
}
