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
	"github.com/algorand/msgp/msgp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/pooldata"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
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
	peer          *Peer
	uploadSpeed   uint64
	downloadSpeed uint64
	isOutgoing    bool
	outSeq        uint64
	inSeq         uint64
	target        int

	messageQ []queuedMessage // incoming message queue

	mu sync.Mutex `algofix:"allow sync.Mutex"`

	deferredSentMessages []queuedSentMessageCallback // outgoing messages callback queue
}

// emulatedNode implements the NodeConnector interface
type emulatedNode struct {
	externalEvents                      chan Event
	emulator                            *emulator
	peers                               map[int]*networkPeer
	nodeIndex                           int
	expiredTx                           []pooldata.SignedTxGroup
	txpoolEntries                       []pooldata.SignedTxGroup
	txpoolIds                           map[transactions.Txid]bool
	proposals                           []*proposalCache
	latestLocallyOriginatedGroupCounter uint64
	name                                string
	blocked                             chan struct{}
	mu                                  sync.Mutex `algofix:"allow sync.Mutex"`
	txpoolGroupCounter                  uint64
	blockingEnabled                     bool
	nodeBlocked                         chan struct{} // channel is closed when node is blocked.
	nodeRunning                         chan struct{} // channel is closed when node is running.
}

type proposalData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	ProposalBytes []byte              `codec:"b,allocbound=maxNumProposalBytes"`
	TxGroupIds    []transactions.Txid `codec:"h,allocbound=maxNumTxGroupHashesBytes"` // TODO: make this []byte
}

const maxNumProposalBytes = 30000       // sizeof(block header)
const maxNumTxGroupHashesBytes = 320000 // 10K * 32

// MarshalMsg implements msgp.Marshaler
func (z *proposalData) MarshalMsg(b []byte) (o []byte) {
	o = msgp.Require(b, z.Msgsize())
	// omitempty: check for empty values
	zb0002Len := uint32(2)
	var zb0002Mask uint8 /* 3 bits */
	if len((*z).ProposalBytes) == 0 {
		zb0002Len--
		zb0002Mask |= 0x2
	}
	if len((*z).TxGroupIds) == 0 {
		zb0002Len--
		zb0002Mask |= 0x4
	}
	// variable map header, size zb0002Len
	o = append(o, 0x80|uint8(zb0002Len))
	if zb0002Len != 0 {
		if (zb0002Mask & 0x2) == 0 { // if not empty
			// string "b"
			o = append(o, 0xa1, 0x62)
			o = msgp.AppendBytes(o, (*z).ProposalBytes)
		}
		if (zb0002Mask & 0x4) == 0 { // if not empty
			// string "h"
			o = append(o, 0xa1, 0x68)
			if (*z).TxGroupIds == nil {
				o = msgp.AppendNil(o)
			} else {
				o = msgp.AppendArrayHeader(o, uint32(len((*z).TxGroupIds)))
			}
			for zb0001 := range (*z).TxGroupIds {
				o = (*z).TxGroupIds[zb0001].MarshalMsg(o)
			}
		}
	}
	return
}

func (_ *proposalData) CanMarshalMsg(z interface{}) bool {
	_, ok := (z).(*proposalData)
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *proposalData) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0002 int
	var zb0003 bool
	zb0002, zb0003, bts, err = msgp.ReadMapHeaderBytes(bts)
	if _, ok := err.(msgp.TypeError); ok {
		zb0002, zb0003, bts, err = msgp.ReadArrayHeaderBytes(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		if zb0002 > 0 {
			zb0002--
			var zb0004 int
			zb0004, err = msgp.ReadBytesBytesHeader(bts)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "ProposalBytes")
				return
			}
			if zb0004 > maxNumProposalBytes {
				err = msgp.ErrOverflow(uint64(zb0004), uint64(maxNumProposalBytes))
				return
			}
			(*z).ProposalBytes, bts, err = msgp.ReadBytesBytes(bts, (*z).ProposalBytes)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "ProposalBytes")
				return
			}
		}
		if zb0002 > 0 {
			zb0002--
			var zb0005 int
			var zb0006 bool
			zb0005, zb0006, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "TxGroupIds")
				return
			}
			if zb0005 > maxNumTxGroupHashesBytes {
				err = msgp.ErrOverflow(uint64(zb0005), uint64(maxNumTxGroupHashesBytes))
				err = msgp.WrapError(err, "struct-from-array", "TxGroupIds")
				return
			}
			if zb0006 {
				(*z).TxGroupIds = nil
			} else if (*z).TxGroupIds != nil && cap((*z).TxGroupIds) >= zb0005 {
				(*z).TxGroupIds = ((*z).TxGroupIds)[:zb0005]
			} else {
				(*z).TxGroupIds = make([]transactions.Txid, zb0005)
			}
			for zb0001 := range (*z).TxGroupIds {
				bts, err = (*z).TxGroupIds[zb0001].UnmarshalMsg(bts)
				if err != nil {
					err = msgp.WrapError(err, "struct-from-array", "TxGroupIds", zb0001)
					return
				}
			}
		}
		if zb0002 > 0 {
			err = msgp.ErrTooManyArrayFields(zb0002)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array")
				return
			}
		}
	} else {
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		if zb0003 {
			(*z) = proposalData{}
		}
		for zb0002 > 0 {
			zb0002--
			field, bts, err = msgp.ReadMapKeyZC(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
			switch string(field) {
			case "b":
				var zb0007 int
				zb0007, err = msgp.ReadBytesBytesHeader(bts)
				if err != nil {
					err = msgp.WrapError(err, "ProposalBytes")
					return
				}
				if zb0007 > maxNumProposalBytes {
					err = msgp.ErrOverflow(uint64(zb0007), uint64(maxNumProposalBytes))
					return
				}
				(*z).ProposalBytes, bts, err = msgp.ReadBytesBytes(bts, (*z).ProposalBytes)
				if err != nil {
					err = msgp.WrapError(err, "ProposalBytes")
					return
				}
			case "h":
				var zb0008 int
				var zb0009 bool
				zb0008, zb0009, bts, err = msgp.ReadArrayHeaderBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "TxGroupIds")
					return
				}
				if zb0008 > maxNumTxGroupHashesBytes {
					err = msgp.ErrOverflow(uint64(zb0008), uint64(maxNumTxGroupHashesBytes))
					err = msgp.WrapError(err, "TxGroupIds")
					return
				}
				if zb0009 {
					(*z).TxGroupIds = nil
				} else if (*z).TxGroupIds != nil && cap((*z).TxGroupIds) >= zb0008 {
					(*z).TxGroupIds = ((*z).TxGroupIds)[:zb0008]
				} else {
					(*z).TxGroupIds = make([]transactions.Txid, zb0008)
				}
				for zb0001 := range (*z).TxGroupIds {
					bts, err = (*z).TxGroupIds[zb0001].UnmarshalMsg(bts)
					if err != nil {
						err = msgp.WrapError(err, "TxGroupIds", zb0001)
						return
					}
				}
			default:
				err = msgp.ErrNoField(string(field))
				if err != nil {
					err = msgp.WrapError(err)
					return
				}
			}
		}
	}
	o = bts
	return
}

func (_ *proposalData) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*proposalData)
	return ok
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *proposalData) Msgsize() (s int) {
	s = 1 + 2 + msgp.BytesPrefixSize + len((*z).ProposalBytes) + 2 + msgp.ArrayHeaderSize
	for zb0001 := range (*z).TxGroupIds {
		s += (*z).TxGroupIds[zb0001].Msgsize()
	}
	return
}

// MsgIsZero returns whether this is a zero value
func (z *proposalData) MsgIsZero() bool {
	return (len((*z).ProposalBytes) == 0) && (len((*z).TxGroupIds) == 0)
}

// cache used by the peer to keep track of which proposals not to send
type proposalCache struct {
	proposalData

	txGroupIDIndex      map[transactions.Txid]int
	txGroups            []pooldata.SignedTxGroup
	numTxGroupsReceived int
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
	}
	close(en.nodeRunning)

	// add outgoing connections
	for _, conn := range emulator.scenario.netConfig.nodes[nodeIdx].outgoingConnections {
		en.peers[conn.target] = &networkPeer{
			uploadSpeed:   conn.uploadSpeed,
			downloadSpeed: conn.downloadSpeed,
			isOutgoing:    true,
			target:        conn.target,
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
	n.mu.Lock()
	if n.blockingEnabled {
		c = make(chan struct{})
		n.blocked = c
		close(n.nodeBlocked)
		n.nodeRunning = make(chan struct{}, 1)
		n.mu.Unlock()
		<-c
		n.mu.Lock()
		close(n.nodeRunning)
		n.nodeBlocked = make(chan struct{}, 1)
		n.mu.Unlock()
		// return a closed channel.
		return c
	}
	n.mu.Unlock()
	// return an open channel
	return make(chan struct{})
}
func (n *emulatedNode) disableBlocking() {
	n.mu.Lock()
	n.blockingEnabled = false
	n.mu.Unlock()
	n.unblock()
}
func (n *emulatedNode) unblock() {
	n.mu.Lock()
	// wait until the state changes to StateMachineRunning
	select {
	case <-n.nodeBlocked:
		// we're blocked.
		if n.blocked != nil {
			close(n.blocked)
			n.blocked = nil
		}
		runningCh := n.nodeRunning
		n.mu.Unlock()
		<-runningCh
		return
	default:
	}
	n.mu.Unlock()
}

func (n *emulatedNode) waitBlocked() {
	n.mu.Lock()
	select {
	case <-n.nodeRunning:
		blockedCh := n.nodeBlocked
		n.mu.Unlock()
		<-blockedCh
		return
	default:
	}
	n.mu.Unlock()
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

func (n *emulatedNode) UpdatePeers(txPeers []*Peer, netPeers []interface{}, _ uint64) {
	for i, peer := range netPeers {
		netPeer := peer.(*networkPeer)
		netPeer.peer = txPeers[i]
	}
}

func (n *emulatedNode) enqueueMessage(from int, msg queuedMessage) {
	n.peers[from].mu.Lock()
	baseTime := n.emulator.clock.Since()
	if len(n.peers[from].messageQ) > 0 {
		if n.peers[from].messageQ[len(n.peers[from].messageQ)-1].readyAt > baseTime {
			baseTime = n.peers[from].messageQ[len(n.peers[from].messageQ)-1].readyAt
		}
	}
	// the message bytes need to be copied, so that the originating bytes could be safely deleted.
	msgBytes := make([]byte, len(msg.bytes))
	copy(msgBytes[:], msg.bytes[:])
	n.peers[from].messageQ = append(n.peers[from].messageQ, queuedMessage{bytes: msgBytes, readyAt: baseTime + msg.readyAt})
	n.peers[from].mu.Unlock()
}

func (n *emulatedNode) SendPeerMessage(netPeer interface{}, msg []byte, callback SendMessageCallback) {
	peer := netPeer.(*networkPeer)
	otherNode := n.emulator.nodes[peer.target]
	sendTime := time.Duration(len(msg)) * time.Second / time.Duration(peer.uploadSpeed)
	otherNode.enqueueMessage(n.nodeIndex, queuedMessage{bytes: msg, readyAt: sendTime})

	peer.deferredSentMessages = append(peer.deferredSentMessages, queuedSentMessageCallback{callback: callback, seq: peer.outSeq})
	peer.outSeq++
}

func (n *emulatedNode) GetPendingTransactionGroups() ([]pooldata.SignedTxGroup, uint64) {
	return n.txpoolEntries, n.latestLocallyOriginatedGroupCounter
}

func (n *emulatedNode) IncomingTransactionGroups(peer *Peer, messageSeq uint64, txGroups []pooldata.SignedTxGroup) (transactionPoolSize int) {
	// add to transaction pool.

	duplicateMessage := 0
	duplicateMessageSize := 0
	encodingBuf := protocol.GetEncodingBuf()
	transactionPoolSize = len(n.txpoolEntries)
	for _, group := range txGroups {
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
		group.GroupTransactionID = group.Transactions.ID()
		for _, txn := range group.Transactions {
			encodingBuf = encodingBuf[:0]
			group.EncodedLength += len(txn.MarshalMsg(encodingBuf))
		}
		n.txpoolEntries = append(n.txpoolEntries, group)
	}
	protocol.PutEncodingBuf(encodingBuf)
	if duplicateMessage > 0 {
		fmt.Printf("%s : %d duplicate messages recieved\n", n.name, duplicateMessage)
	}
	atomic.AddUint64(&n.emulator.totalDuplicateTransactions, uint64(duplicateMessage))
	atomic.AddUint64(&n.emulator.totalDuplicateTransactionSize, uint64(duplicateMessageSize))
	select {
	case peer.GetTransactionPoolAckChannel() <- messageSeq:
	default:
		panic(errors.New("IncomingTransactionGroups was unable to write messageSeq to the ack channel"))
	}
	return
}

func (n *emulatedNode) step() {
	msgHandler := n.emulator.syncers[n.nodeIndex].GetIncomingMessageHandler()
	now := n.emulator.clock.Since()
	// check if we have any pending network messages and forward them.

	for _, peer := range n.orderedPeers() {
		peer.mu.Lock()

		for i := len(peer.deferredSentMessages); i > 0; i-- {
			dm := peer.deferredSentMessages[0]
			peer.deferredSentMessages = peer.deferredSentMessages[1:]
			peer.mu.Unlock()
			err := dm.callback(true, dm.seq)
			if err != nil {
				panic(err)
			}
			n.unblock()
			n.waitBlocked()
			peer.mu.Lock()
		}

		for i := len(peer.messageQ); i > 0; i-- {
			if peer.messageQ[0].readyAt > now {
				break
			}

			msgBytes := peer.messageQ[0].bytes
			msgInSeq := peer.inSeq

			peer.inSeq++
			peer.messageQ = peer.messageQ[1:]

			peer.mu.Unlock()

			msgHandler(peer, peer.peer, msgBytes, msgInSeq)
			n.unblock()
			n.waitBlocked()
			peer.mu.Lock()

		}
		peer.mu.Unlock()
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
	n.externalEvents <- MakeTransactionPoolChangeEvent(len(n.txpoolEntries), false)
}

func (p *networkPeer) GetAddress() string {
	return fmt.Sprintf("%d", p.target)
}

func (n *emulatedNode) RelayProposal(proposalBytes []byte, txGroups []pooldata.SignedTxGroup) {
	data := proposalData{
		ProposalBytes: proposalBytes,
		TxGroupIds:    make([]transactions.Txid, len(txGroups)),
	}

	for i, txGroup := range txGroups {
		data.TxGroupIds[i] = txGroup.GroupTransactionID
	}

	n.proposals = append(n.proposals, &proposalCache{proposalData: data, txGroups: txGroups, numTxGroupsReceived: len(txGroups)})

	n.externalEvents <- MakeBroadcastProposalRequestEvent(protocol.Encode(&data), txGroups)
}

func (n *emulatedNode) HandleProposalMessage(proposalDataBytes []byte, txGroups []pooldata.SignedTxGroup, peer *Peer) []byte {
	var data proposalData
	var pc *proposalCache
	protocol.Decode(proposalDataBytes, &data)

	if proposalDataBytes != nil {
		pc = &proposalCache{
			proposalData:   data,
			txGroupIDIndex: make(map[transactions.Txid]int, len(data.TxGroupIds)),
			txGroups:       make([]pooldata.SignedTxGroup, len(data.TxGroupIds)),
		}
		n.proposals = append(n.proposals, pc)
		for i, txid := range pc.TxGroupIds {
			pc.txGroupIDIndex[txid] = i
		}
	} else {
		pc = n.proposals[len(n.proposals)-1]
	}
	// TODO attempt to fill receivedTxns with txpool

	for _, txGroup := range txGroups {
		if index, found := pc.txGroupIDIndex[txGroup.Transactions.ID()]; found && pc.txGroups[index].Transactions == nil {
			pc.txGroups[index] = txGroup
			pc.numTxGroupsReceived++
		}
	}

	if pc.numTxGroupsReceived == len(pc.txGroups) {
		// TODO send proposal to agreement
		return protocol.Encode(&pc.proposalData)
	}
	return nil
}
