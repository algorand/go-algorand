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

package fuzzer

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/protocol"
)

type NodeShuffleConfig struct {
	SendShuffleSize    int
	ReceiveShuffleSize int
	MaxRetension       time.Duration
}
type MessageReorderingFilterConfig struct {
	NodesShuffleConfig map[int]NodeShuffleConfig // map each node to it's desired configuration
}

type PendingMessage struct {
	sourceNode int
	targetNode int
	tag        protocol.Tag
	data       []byte
	sendTick   int32
}

type MessageReorderingFilter struct {
	NetworkFilter

	upstream        UpstreamFilter
	downstream      DownstreamFilter
	fuzzer          *Fuzzer
	nodeConfig      NodeShuffleConfig
	ticksRetension  int
	currentTick     int32
	pendingSends    []PendingMessage
	pendingReceives []PendingMessage
	sendRnd         *rand.Rand
	receiveRnd      *rand.Rand
	sendMu          deadlock.Mutex
	receiveMu       deadlock.Mutex
	debugMessages   bool
	nodeID          int

	NetworkFilterFactory
	config *MessageReorderingFilterConfig
}

func (n *MessageReorderingFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	if n.nodeConfig.SendShuffleSize == 0 {
		n.downstream.SendMessage(sourceNode, targetNode, tag, data)
		return
	}
	msg := PendingMessage{
		sourceNode: sourceNode,
		targetNode: targetNode,
		tag:        tag,
		data:       data,
		sendTick:   atomic.LoadInt32(&n.currentTick),
	}
	n.sendMu.Lock()
	n.pendingSends = append(n.pendingSends, msg)
	if len(n.pendingSends) > n.nodeConfig.SendShuffleSize {
		p := n.sendRnd.Intn(len(n.pendingSends))
		msg = n.pendingSends[p]
		n.pendingSends = append(n.pendingSends[0:p], n.pendingSends[p+1:]...)
		if n.debugMessages {
			fmt.Printf("Node %d SendMessage called, forwarding randomally a message out of a %d messages message pool\n", n.nodeID, len(n.pendingSends)+1)
		}
		n.sendMu.Unlock()
		n.downstream.SendMessage(msg.sourceNode, msg.targetNode, msg.tag, msg.data)
	} else {
		if n.debugMessages {
			fmt.Printf("Node %d SendMessage called, storing message into pool. Pool length = %d\n", n.nodeID, len(n.pendingSends))
		}
		n.sendMu.Unlock()
	}
}

func (n *MessageReorderingFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

func (n *MessageReorderingFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	if n.nodeConfig.ReceiveShuffleSize == 0 {
		n.upstream.ReceiveMessage(sourceNode, tag, data)
		return
	}
	msg := PendingMessage{
		sourceNode: sourceNode,
		tag:        tag,
		data:       data,
		sendTick:   atomic.LoadInt32(&n.currentTick),
	}
	n.receiveMu.Lock()
	n.pendingReceives = append(n.pendingReceives, msg)
	if len(n.pendingReceives) > n.nodeConfig.ReceiveShuffleSize {
		p := n.receiveRnd.Intn(len(n.pendingReceives))
		msg = n.pendingReceives[p]
		n.pendingReceives = append(n.pendingReceives[0:p], n.pendingReceives[p+1:]...)
		n.receiveMu.Unlock()
		n.upstream.ReceiveMessage(msg.sourceNode, msg.tag, msg.data)
	} else {
		n.receiveMu.Unlock()
	}
}

func (n *MessageReorderingFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *MessageReorderingFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *MessageReorderingFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	filter := &MessageReorderingFilter{
		config:        n.config,
		fuzzer:        fuzzer,
		nodeID:        nodeID,
		debugMessages: false,
	}
	if nodeConfig, has := n.config.NodesShuffleConfig[nodeID]; has {
		filter.nodeConfig = nodeConfig
		filter.ticksRetension = int(nodeConfig.MaxRetension / fuzzer.tickGranularity)
	} else {
		// generate a default config.
		filter.nodeConfig = NodeShuffleConfig{
			SendShuffleSize:    0,
			ReceiveShuffleSize: 0,
		}
	}
	filter.sendRnd = rand.New(rand.NewSource(int64(nodeID)))
	filter.receiveRnd = rand.New(rand.NewSource(-int64(nodeID)))
	return filter
}

func (n *MessageReorderingFilter) sendExpiredMessages() bool {
	n.sendMu.Lock()
	expiredMessages := []PendingMessage{}
	expiredMessageIndices := []int{}

	sent := false
	for i, m := range n.pendingSends {
		if m.sendTick+int32(n.ticksRetension) < atomic.LoadInt32(&n.currentTick) {
			// this message has expired.
			expiredMessages = append(expiredMessages, m)
			expiredMessageIndices = append([]int{i}, expiredMessageIndices...)
		}
	}
	for _, i := range expiredMessageIndices {
		n.pendingSends = append(n.pendingSends[0:i], n.pendingSends[i+1:]...)
	}
	if n.debugMessages && len(expiredMessages) > 0 {
		fmt.Printf("Node %d Tick called, sending %d expired messages from pool. %d messages remains in message pool\n", n.nodeID, len(expiredMessages), len(n.pendingSends)+1)
	}
	n.sendMu.Unlock()
	for _, msg := range expiredMessages {
		n.downstream.SendMessage(msg.sourceNode, msg.targetNode, msg.tag, msg.data)
		sent = true
	}
	return sent
}

func (n *MessageReorderingFilter) recieveExpiredMessages() bool {
	n.receiveMu.Lock()
	expiredMessages := []PendingMessage{}
	expiredMessageIndices := []int{}
	receieved := false
	for i, m := range n.pendingReceives {
		if m.sendTick+int32(n.ticksRetension) < atomic.LoadInt32(&n.currentTick) {
			// this message has expired.
			expiredMessages = append(expiredMessages, m)
			expiredMessageIndices = append([]int{i}, expiredMessageIndices...)
		}
	}
	for _, i := range expiredMessageIndices {
		n.pendingReceives = append(n.pendingReceives[0:i], n.pendingReceives[i+1:]...)
	}
	n.receiveMu.Unlock()
	for _, msg := range expiredMessages {
		n.upstream.ReceiveMessage(msg.sourceNode, msg.tag, msg.data)
		receieved = true
	}
	return receieved
}

func (n *MessageReorderingFilter) Tick(newClockTime int) bool {
	atomic.StoreInt32(&n.currentTick, int32(newClockTime))
	sent := n.sendExpiredMessages()
	received := n.recieveExpiredMessages()
	return n.upstream.Tick(newClockTime) || sent || received
}

func MakeMessageReorderingFilter(config MessageReorderingFilterConfig) *MessageReorderingFilter {
	return &MessageReorderingFilter{
		config: &config,
	}
}

// Unmarshall MessageReorderingFilter
func (n *MessageReorderingFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type messageReorderingFilterJSON struct {
		Name string
		MessageReorderingFilterConfig
	}

	var jsonConfig messageReorderingFilterJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "MessageReorderingFilter" {
		return nil
	}
	return &MessageReorderingFilter{
		config: &jsonConfig.MessageReorderingFilterConfig,
	}
}

// register MessageReorderingFilter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &MessageReorderingFilter{})
}
