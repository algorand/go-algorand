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
	"time"

	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/txnsync"
	"github.com/algorand/go-algorand/util/timers"
)

// transcationSyncNodeConnector implementes the txnsync.NodeConnector interface, allowing the
// transaction sync communicate with the node and it's child objects.
type transcationSyncNodeConnector struct {
	node           *AlgorandFullNode
	eventsCh       chan txnsync.Event
	clock          timers.WallClock
	messageHandler txnsync.IncomingMessageHandler
	txHandler      data.SolicitedAsyncTxHandler
	openStateCh    chan struct{}
}

func makeTranscationSyncNodeConnector(node *AlgorandFullNode) transcationSyncNodeConnector {
	return transcationSyncNodeConnector{
		node:        node,
		eventsCh:    make(chan txnsync.Event, 1),
		clock:       timers.MakeMonotonicClock(time.Now()),
		txHandler:   node.txHandler.SolicitedAsyncTxHandler(),
		openStateCh: make(chan struct{}),
	}
}

func (tsnc *transcationSyncNodeConnector) Events() <-chan txnsync.Event {
	return tsnc.eventsCh
}

func (tsnc *transcationSyncNodeConnector) GetCurrentRoundSettings() txnsync.RoundSettings {
	round := tsnc.node.ledger.Latest()
	return txnsync.RoundSettings{
		Round:             round,
		FetchTransactions: tsnc.node.accountManager.HasLiveKeys(round, round),
	}
}

// NotifyMonitor is used for testing purposes only, and can remain(almost) empty on production code.
func (tsnc *transcationSyncNodeConnector) NotifyMonitor() chan struct{} {
	return tsnc.openStateCh
}

func (tsnc *transcationSyncNodeConnector) Random(rng uint64) uint64 {
	return tsnc.node.Uint64() % rng
}

func (tsnc *transcationSyncNodeConnector) Clock() timers.WallClock {
	return tsnc.clock
}

func (tsnc *transcationSyncNodeConnector) GetPeer(networkPeer interface{}) txnsync.PeerInfo {
	unicastPeer := networkPeer.(network.UnicastPeer)
	if unicastPeer == nil {
		return txnsync.PeerInfo{}
	}

	peerData := tsnc.node.net.GetPeerData(networkPeer, "txsync")
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

func (tsnc *transcationSyncNodeConnector) GetPeers() (peersInfo []txnsync.PeerInfo) {
	networkPeers := tsnc.node.net.GetPeers(network.PeersConnectedOut, network.PeersConnectedIn)
	peersInfo = make([]txnsync.PeerInfo, len(networkPeers))
	k := 0
	for i := range networkPeers {
		unicastPeer := networkPeers[i].(network.UnicastPeer)
		if unicastPeer == nil {
			continue
		}
		// check version.
		if unicastPeer.Version() != "2.5" {
			continue
		}
		peersInfo[k].IsOutgoing = unicastPeer.IsOutgoing()
		peersInfo[k].NetworkPeer = networkPeers[i]
		peerData := tsnc.node.net.GetPeerData(networkPeers[i], "txsync")
		if peerData != nil {
			peersInfo[k].TxnSyncPeer = peerData.(*txnsync.Peer)
		}
		k++
	}

	return peersInfo[:k]
}

func (tsnc *transcationSyncNodeConnector) UpdatePeers(txsyncPeers []*txnsync.Peer, netPeers []interface{}) {
	for i, netPeer := range netPeers {
		tsnc.node.net.SetPeerData(netPeer, "txsync", txsyncPeers[i])
	}
}

func (tsnc *transcationSyncNodeConnector) SendPeerMessage(netPeer interface{}, msg []byte, callback txnsync.SendMessageCallback) {
	unicastPeer := netPeer.(network.UnicastPeer)
	if unicastPeer == nil {
		return
	}
	if err := unicastPeer.Unicast(msg, protocol.Txn2Tag, func(enqueued bool, sequenceNumber uint64) {
		callback(enqueued, sequenceNumber)
	}); err != nil {
		callback(false, 0)
		return
	}
}

// TODO : add description.
func (tsnc *transcationSyncNodeConnector) GetPendingTransactionGroups() ([]transactions.SignedTxGroup, uint64) {
	return tsnc.node.transactionPool.PendingTxGroups()
}

func (tsnc *transcationSyncNodeConnector) onNewTransactionPoolEntry(transcationPoolSize int) {
	select {
	case tsnc.eventsCh <- txnsync.MakeTranscationPoolChangeEvent(transcationPoolSize):
	default:
	}
}

func (tsnc *transcationSyncNodeConnector) onNewRound(round basics.Round, hasParticipationKeys bool) {
	// if this is a relay, then we always want to fetch transactions, regardless if we have participation keys.
	fetchTransactions := hasParticipationKeys
	if tsnc.node.config.NetAddress != "" {
		fetchTransactions = true
	}

	select {
	case tsnc.eventsCh <- txnsync.MakeNewRoundEvent(round, fetchTransactions):
	default:
	}
}

func (tsnc *transcationSyncNodeConnector) start() {
	tsnc.messageHandler = tsnc.node.txnSyncService.GetIncomingMessageHandler()
	handlers := []network.TaggedMessageHandler{
		{Tag: protocol.Txn2Tag, MessageHandler: tsnc},
	}
	tsnc.node.net.RegisterHandlers(handlers)
	tsnc.txHandler.Start()
}

func (tsnc *transcationSyncNodeConnector) Handle(raw network.IncomingMessage) network.OutgoingMessage {
	unicastPeer := raw.Sender.(network.UnicastPeer)
	if unicastPeer != nil {
		// check version.
		if unicastPeer.Version() != "2.5" {
			return network.OutgoingMessage{
				Action: network.Ignore,
			}
		}
	}
	var peer *txnsync.Peer
	peerData := tsnc.node.net.GetPeerData(raw.Sender, "txsync")
	if peerData != nil {
		peer = peerData.(*txnsync.Peer)
	}

	err := tsnc.messageHandler(raw.Sender, peer, raw.Data, raw.Sequence)
	if err == nil {
		return network.OutgoingMessage{
			Action: network.Ignore,
		}
	}
	return network.OutgoingMessage{
		Action: network.Disconnect,
	}
}

func (tsnc *transcationSyncNodeConnector) stop() {
	tsnc.txHandler.Stop()
}

func (tsnc *transcationSyncNodeConnector) IncomingTransactionGroups(networkPeer interface{}, txGroups []transactions.SignedTxGroup) (transactionPoolSize int) {
	// count the transactions that we are adding.
	txCount := 0
	for _, txGroup := range txGroups {
		txCount += len(txGroup.Transactions)
	}
	tsnc.txHandler.HandleTransactionGroups(networkPeer, txGroups)
	return tsnc.node.transactionPool.PendingCount() + txCount
}
