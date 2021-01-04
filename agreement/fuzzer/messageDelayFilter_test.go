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
	"container/heap"
	"encoding/json"
	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/protocol"
)

// Limit messages by bandwidth/tic
type MessageDelayFilter struct {
	NetworkFilter
	NetworkFilterFactory

	upstream   UpstreamFilter
	downstream DownstreamFilter

	nodeID              int
	upStreamTickDelay   map[int]map[string]int
	downStreamTickDelay map[int]map[string]int

	upMutex                deadlock.Mutex
	downMutex              deadlock.Mutex
	upStreamMessageQueue   PriorityQueue
	downStreamMessageQueue PriorityQueue
	currentTick            int
}

func (n *MessageDelayFilter) Init() {
	heap.Init(&n.upStreamMessageQueue)
	heap.Init(&n.downStreamMessageQueue)
}

func MakeMessageDelayFilter(upStreamTickDelay map[int]map[string]int, downStreamTickDelay map[int]map[string]int) *MessageDelayFilter {
	return &MessageDelayFilter{
		upStreamTickDelay:   upStreamTickDelay,
		downStreamTickDelay: downStreamTickDelay,
	}
}

// Return a Queue Item for pushing to the queue
func (n *MessageDelayFilter) MakeQueueItem(tic int, sourceNode, targetNode int, tag protocol.Tag, data []byte) (mqi *QueueItem) {

	return &QueueItem{
		priority: tic,
		message: AlgoMessage{
			sourceNode: sourceNode,
			targetNode: targetNode,
			tag:        tag,
			data:       data,
		},
	}
}

// If there is a downstream delay for the node, then compute the release tick and add to downstream message queue
func (n *MessageDelayFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {

	tickDelay := 0
	if ticDelayTagMap, hasNode := n.downStreamTickDelay[n.nodeID]; hasNode {
		if delay, hasTag := ticDelayTagMap[string(tag)]; hasTag {
			tickDelay = delay
		} else if delay, hasAny := ticDelayTagMap["*"]; hasAny {
			tickDelay = delay
		}
	}
	if tickDelay != 0 {
		newTick := n.currentTick + tickDelay
		//fmt.Printf("currentTick: %d node: %d tag: %s delaying downstream message by %d, new tick %d\n", n.currentTick, n.nodeID, tag, tickDelay, newTick)
		n.downMutex.Lock()
		heap.Push(&n.downStreamMessageQueue, n.MakeQueueItem(newTick, sourceNode, targetNode, tag, data))
		n.downMutex.Unlock()
	} else {
		n.downstream.SendMessage(sourceNode, targetNode, tag, data)
	}
}

func (n *MessageDelayFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

// if there is an upstream delay for the node, then compute the release tick and add to upstream message queue
func (n *MessageDelayFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	tickDelay := 0
	if ticDelayTagMap, hasNode := n.upStreamTickDelay[n.nodeID]; hasNode {
		if delay, hasTag := ticDelayTagMap[string(tag)]; hasTag {
			tickDelay = delay
		} else if delay, hasAny := ticDelayTagMap["*"]; hasAny {
			tickDelay = delay
		}
	}
	if tickDelay != 0 {
		newTick := n.currentTick + tickDelay
		//fmt.Printf("currentTick: %d node: %d tag: %s delaying upstream message by %d, new tick %d\n", n.currentTick, n.nodeID, tag, tickDelay, newTick)
		n.upMutex.Lock()
		heap.Push(&n.upStreamMessageQueue, n.MakeQueueItem(newTick, sourceNode, 0, tag, data))
		n.upMutex.Unlock()
	} else {
		n.upstream.ReceiveMessage(sourceNode, tag, data)
	}
}

func (n *MessageDelayFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *MessageDelayFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *MessageDelayFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	networkFilter := MessageDelayFilter{
		nodeID:                 nodeID,
		upStreamTickDelay:      n.upStreamTickDelay,
		downStreamMessageQueue: n.downStreamMessageQueue,
	}
	networkFilter.Init()
	return &networkFilter
}

func (n *MessageDelayFilter) Tick(newClockTime int) bool {
	// update the current tick
	n.currentTick = newClockTime
	// process messages in buffer
	sent := n.processDownstreamBuffer()
	received := n.processUpstreamBuffer()
	// forward the tick
	return n.upstream.Tick(newClockTime) || received || sent
}

// check for messages ready to send on downstream and upstream queues
func (n *MessageDelayFilter) processDownstreamBuffer() bool {
	n.downMutex.Lock()
	defer n.downMutex.Unlock()
	sent := false
	for n.downStreamMessageQueue.Len() > 0 {
		item := heap.Pop(&n.downStreamMessageQueue).(*QueueItem)
		if item.priority <= n.currentTick {
			// time on queue has expired, send the message
			n.downstream.SendMessage(item.message.sourceNode, item.message.targetNode, item.message.tag, item.message.data)
			//fmt.Printf("currentTick: %d node: %d releasing downstream message with tag %s and tick %d\n", n.currentTick,n.nodeID, item.message.tag, item.priority )
			sent = true
		} else {
			// we have gone beyond current time, push the message back to the queue and break
			heap.Push(&n.downStreamMessageQueue, item)
			//fmt.Printf("currentTick: %d node: %d pushing back downstream message with tick %d\n",n.currentTick,n.nodeID, item.priority )
			break
		}
	}
	return sent
}

func (n *MessageDelayFilter) processUpstreamBuffer() bool {
	n.upMutex.Lock()
	defer n.upMutex.Unlock()
	received := false
	for n.upStreamMessageQueue.Len() > 0 {
		item := heap.Pop(&n.upStreamMessageQueue).(*QueueItem)
		if item.priority <= n.currentTick {
			// time on queue has expired, receive the message
			n.upstream.ReceiveMessage(item.message.sourceNode, item.message.tag, item.message.data)
			//fmt.Printf("currentTick: %d node: %d releasing upstream message with tag %s and tick %d\n",n.currentTick, n.nodeID, item.message.tag, item.priority)
			received = true
		} else {
			// we have gone beyond current time, push the message back to the queue and break
			//heap.Push(&n.upStreamMessageQueue, item)
			heap.Push(&n.upStreamMessageQueue, item)
			//fmt.Printf("currentTick: %d node: %d pushing back upstream message with tick %d\n",n.currentTick, n.nodeID, item.priority)
			break
		}
	}
	return received
}

// Unmarshall MessageDelayFilter
func (n *MessageDelayFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type messageDelayFilterJSON struct {
		Name                string
		UpStreamTickDelay   map[int]map[string]int
		DownStreamTickDelay map[int]map[string]int
	}

	var jsonConfig messageDelayFilterJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "MessageDelayFilter" {
		return nil
	}
	return &MessageDelayFilter{
		upStreamTickDelay:   jsonConfig.UpStreamTickDelay,
		downStreamTickDelay: jsonConfig.DownStreamTickDelay,
	}
}

// register MessageDelayFilter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &MessageDelayFilter{})
}
