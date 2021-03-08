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
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/util/timers"
)

type queuedSentMessageCallback struct {
	callback SendMessageCallback
	seq      uint64
}
type queuedMessage struct {
	bytes   []byte
	readyAt time.Duration
}
type networkPeer struct {
	peer                 *Peer
	uploadSpeed          uint64
	downloadSpeed        uint64
	isOutgoing           bool
	outSeq               uint64
	inSeq                uint64
	target               int
	messageQ             []queuedMessage // incoming message queue
	lockCh               chan struct{}
	deferredSentMessages []queuedSentMessageCallback // outgoing messages callback queue
}

// emulatedNode implements the NodeConnector interface
type emulatedNode struct {
	externalEvents     chan Event
	emulator           *emulator
	peers              map[int]*networkPeer
	nodeIndex          int
	expiredTx          []transactions.SignedTxGroup
	txpoolEntries      []transactions.SignedTxGroup
	txpoolIds          map[transactions.Txid]bool
	name               string
	blocked            chan struct{}
	lockCh             chan struct{}
	txpoolGroupCounter uint64
	blockingEnabled    bool
	nodeBlocked        chan struct{} // channel is closed when node is blocked.
	nodeRunning        chan struct{} // channel is closed when node is running.
}

func makeEmulatedNode(emulator *emulator, nodeIdx int) *emulatedNode {
	en := &emulatedNode{
		emulator:        emulator,
		peers:           make(map[int]*networkPeer),
		externalEvents:  make(chan Event, 10000),
		nodeIndex:       nodeIdx,
		txpoolIds:       make(map[transactions.Txid]bool),
		name:            emulator.scenario.netConfig.nodes[nodeIdx].name,
		blockingEnabled: true,
		nodeBlocked:     make(chan struct{}, 1),
		nodeRunning:     make(chan struct{}, 1),
		lockCh:          make(chan struct{}, 1),
	}
	close(en.nodeRunning)

	// add outgoing connections
	for _, conn := range emulator.scenario.netConfig.nodes[nodeIdx].outgoingConnections {
		en.peers[conn.target] = &networkPeer{
			uploadSpeed:   conn.uploadSpeed,
			downloadSpeed: conn.downloadSpeed,
			isOutgoing:    true,
			target:        conn.target,
			lockCh:        make(chan struct{}, 1),
		}
	}
	// add incoming connections
	for nodeID, nodeConfig := range emulator.scenario.netConfig.nodes {
		if nodeID == nodeIdx {
			continue
		}
		for _, conn := range nodeConfig.outgoingConnections {
			if conn.target != nodeIdx {
				continue
			}
			// the upload & download speeds are in reverse. This isn't a bug since we want the incoming
			// connection to be the opposite side of the connection.
			en.peers[nodeID] = &networkPeer{
				uploadSpeed:   conn.downloadSpeed,
				downloadSpeed: conn.uploadSpeed,
				isOutgoing:    false,
				target:        nodeID,
				lockCh:        make(chan struct{}, 1),
			}
		}
	}
	return en
}

func (n *emulatedNode) Events() <-chan Event {
	return n.externalEvents
}

func (n *emulatedNode) NotifyMonitor() chan struct{} {
	var c chan struct{}
	n.lock()
	if n.blockingEnabled {
		c = make(chan struct{})
		n.blocked = c
		close(n.nodeBlocked)
		n.nodeRunning = make(chan struct{}, 1)
		n.unlock()
		<-c
		n.lock()
		close(n.nodeRunning)
		n.nodeBlocked = make(chan struct{}, 1)
		n.unlock()
		// return a closed channel.
		return c
	}
	n.unlock()
	// return an open channel
	return make(chan struct{})
}
func (n *emulatedNode) disableBlocking() {
	n.lock()
	n.blockingEnabled = false
	n.unlock()
	n.unblock()
}
func (n *emulatedNode) unblock() {
	n.lock()
	// wait until the state chages to StateMachineRunning
	select {
	case <-n.nodeBlocked:
		// we're blocked.
		if n.blocked != nil {
			close(n.blocked)
			n.blocked = nil
		}
		runningCh := n.nodeRunning
		n.unlock()
		<-runningCh
		return
	default:
	}
	n.unlock()
}

func (n *emulatedNode) waitBlocked() {
	n.lock()
	select {
	case <-n.nodeRunning:
		blockedCh := n.nodeBlocked
		n.unlock()
		<-blockedCh
		return
	default:
	}
	n.unlock()
}

func (n *emulatedNode) GetCurrentRoundSettings() RoundSettings {
	return RoundSettings{
		Round:             n.emulator.currentRound,
		FetchTransactions: true,
	}

}
func (n *emulatedNode) Clock() timers.WallClock {
	return n.emulator.clock.Zero().(timers.WallClock)
}

func (n *emulatedNode) Random(x uint64) (out uint64) {
	limit := x
	x += uint64(n.nodeIndex) * 997
	x += uint64(n.emulator.currentRound) * 797
	x += uint64(n.emulator.lastRandom) * 797
	bytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		bytes[i] = byte(x >> (i * 8))
	}
	digest := crypto.Hash(bytes)
	out = 0
	for i := 0; i < 8; i++ {
		out = out << 8
		out += uint64(digest[i])
	}
	out = out % limit
	n.emulator.lastRandom ^= out
	return out
}

func (n *emulatedNode) orderedPeers() (out []*networkPeer) {
	peerToIndex := make(map[*networkPeer]int)
	for idx, peer := range n.peers {
		out = append(out, peer)
		peerToIndex[peer] = idx
	}
	// sort the peers, which we need in order to make the test deterministic.
	sort.Slice(out, func(i, j int) bool {
		netPeer1 := out[i]
		netPeer2 := out[j]
		return peerToIndex[netPeer1] < peerToIndex[netPeer2]
	})
	return
}

func (n *emulatedNode) GetPeers() (out []PeerInfo) {
	for _, peer := range n.orderedPeers() {
		out = append(out, PeerInfo{TxnSyncPeer: peer.peer, NetworkPeer: peer, IsOutgoing: peer.isOutgoing})
	}
	return out
}

func (n *emulatedNode) GetPeer(p interface{}) PeerInfo {
	netPeer := p.(*networkPeer)
	return PeerInfo{
		TxnSyncPeer: netPeer.peer,
		IsOutgoing:  netPeer.isOutgoing,
		NetworkPeer: p,
	}
}

func (n *emulatedNode) UpdatePeers(txPeers []*Peer, netPeers []interface{}) {
	for i, peer := range netPeers {
		netPeer := peer.(*networkPeer)
		netPeer.peer = txPeers[i]
	}
}

func (n *emulatedNode) enqueueMessage(from int, msg queuedMessage) {
	n.peers[from].lock()
	baseTime := n.emulator.clock.Since()
	if len(n.peers[from].messageQ) > 0 {
		if n.peers[from].messageQ[len(n.peers[from].messageQ)-1].readyAt > baseTime {
			baseTime = n.peers[from].messageQ[len(n.peers[from].messageQ)-1].readyAt
		}
	}
	n.peers[from].messageQ = append(n.peers[from].messageQ, queuedMessage{bytes: msg.bytes, readyAt: baseTime + msg.readyAt})
	n.peers[from].unlock()
}

func (n *emulatedNode) SendPeerMessage(netPeer interface{}, msg []byte, callback SendMessageCallback) {
	peer := netPeer.(*networkPeer)
	otherNode := n.emulator.nodes[peer.target]
	sendTime := time.Duration(len(msg)) * time.Second / time.Duration(peer.uploadSpeed)
	otherNode.enqueueMessage(n.nodeIndex, queuedMessage{bytes: msg, readyAt: sendTime})

	peer.deferredSentMessages = append(peer.deferredSentMessages, queuedSentMessageCallback{callback: callback, seq: peer.outSeq})
	peer.outSeq++
}

func (n *emulatedNode) GetPendingTransactionGroups() []transactions.SignedTxGroup {
	return n.txpoolEntries
}

func (n *emulatedNode) IncomingTransactionGroups(peer interface{}, groups []transactions.SignedTxGroup) (transactionPoolSize int) {
	// add to transaction pool.
	duplicateMessage := 0
	duplicateMessageSize := 0
	for _, group := range groups {
		if group.Transactions[0].Txn.LastValid < n.emulator.currentRound {
			continue
		}
		txID := group.Transactions[0].ID()
		if n.txpoolIds[txID] {
			duplicateMessage++
			duplicateMessageSize += len(group.Transactions[0].Txn.Note)
			continue
		}
		n.txpoolIds[txID] = true
		group.GroupCounter = n.txpoolGroupCounter
		n.txpoolGroupCounter++
		group.FirstTransactionID = txID
		n.txpoolEntries = append(n.txpoolEntries, group)
	}
	if duplicateMessage > 0 {
		fmt.Printf("%s : %d duplicate messages recieved\n", n.name, duplicateMessage)
	}
	atomic.AddUint64(&n.emulator.totalDuplicateTransactions, uint64(duplicateMessage))
	atomic.AddUint64(&n.emulator.totalDuplicateTransactionSize, uint64(duplicateMessageSize))
	return len(n.txpoolEntries)
}

func (n *emulatedNode) step() {
	msgHandler := n.emulator.syncers[n.nodeIndex].GetIncomingMessageHandler()
	now := n.emulator.clock.Since()
	// check if we have any pending network messages and forward them.

	for _, peer := range n.orderedPeers() {
		peer.lock()

		for i := len(peer.deferredSentMessages); i > 0; i-- {
			dm := peer.deferredSentMessages[0]
			peer.deferredSentMessages = peer.deferredSentMessages[1:]
			peer.unlock()
			dm.callback(true, dm.seq)
			n.unblock()
			n.waitBlocked()
			peer.lock()
		}

		for i := len(peer.messageQ); i > 0; i-- {
			if peer.messageQ[0].readyAt > now {
				break
			}

			msgBytes := peer.messageQ[0].bytes
			msgInSeq := peer.inSeq

			peer.inSeq++
			peer.messageQ = peer.messageQ[1:]

			peer.unlock()

			msgHandler(peer, peer.peer, msgBytes, msgInSeq)
			n.unblock()
			n.waitBlocked()
			peer.lock()

		}
		peer.unlock()
	}

}
func (n *emulatedNode) onNewRound(round basics.Round, hasParticipationKeys bool) {
	// if this is a relay, then we always want to fetch transactions, regardless if we have participation keys.
	fetchTransactions := hasParticipationKeys
	if n.emulator.scenario.netConfig.nodes[n.nodeIndex].isRelay {
		fetchTransactions = true
	}

	for i := len(n.txpoolEntries) - 1; i >= 0; i-- {
		if n.txpoolEntries[i].Transactions[0].Txn.LastValid < round {
			delete(n.txpoolIds, n.txpoolEntries[i].Transactions[0].ID())
			n.expiredTx = append(n.expiredTx, n.txpoolEntries[i])
			n.txpoolEntries = append(n.txpoolEntries[0:i], n.txpoolEntries[i+1:]...)
		}
	}

	n.externalEvents <- MakeNewRoundEvent(round, fetchTransactions)
}

func (n *emulatedNode) onNewTransactionPoolEntry() {
	n.externalEvents <- MakeTranscationPoolChangeEvent(len(n.txpoolEntries))
}

func (n *emulatedNode) lock() {
	n.lockCh <- struct{}{}
}

func (n *emulatedNode) unlock() {
	<-n.lockCh
}

func (p *networkPeer) GetAddress() string {
	return fmt.Sprintf("%d", p.target)
}

func (p *networkPeer) lock() {
	p.lockCh <- struct{}{}
}

func (p *networkPeer) unlock() {
	<-p.lockCh
}
