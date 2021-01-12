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

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-deadlock"
)

// Simulate a 2 way mirror where messages are passed through and also reflected back to sender with a delay
type MessageReflectionFilter struct {
	NetworkFilter
	NetworkFilterFactory
	nodeID int

	upstream   UpstreamFilter
	downstream DownstreamFilter

	// reflection filter is a node id map, whose value is a map of tags and their associated reflection delay
	upStreamReflection   map[int]map[string]int
	downStreamReflection map[int]map[string]int

	upMutex                deadlock.Mutex
	downMutex              deadlock.Mutex
	upStreamMessageQueue   PriorityQueue
	downStreamMessageQueue PriorityQueue
	currentTick            int
}

func (n *MessageReflectionFilter) Init() {
	heap.Init(&n.upStreamMessageQueue)
	heap.Init(&n.downStreamMessageQueue)
}

func MakeMessageReflectionFilter(upStreamReflection map[int]map[string]int, downStreamReflection map[int]map[string]int) *MessageReflectionFilter {
	return &MessageReflectionFilter{
		upStreamReflection:   upStreamReflection,
		downStreamReflection: downStreamReflection,
	}
}

// Return a Queue Item for pushing to the queue
func (n *MessageReflectionFilter) MakeQueueItem(tic int, sourceNode, targetNode int, tag protocol.Tag, data []byte) (mqi *QueueItem) {

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

// If there is a downstream reflection for the node, then compute the release tick for the reflected message and add to upstream message queue
func (n *MessageReflectionFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {

	tickDelay := -1
	if ticDelayTagMap, hasNode := n.downStreamReflection[n.nodeID]; hasNode {
		if delay, hasTag := ticDelayTagMap[string(tag)]; hasTag {
			tickDelay = delay
		} else if delay, hasAny := ticDelayTagMap["*"]; hasAny {
			tickDelay = delay
		}
	}
	if tickDelay != -1 {
		newTick := n.currentTick + tickDelay
		tempSourceNode := targetNode
		if tempSourceNode == -1 {
			tempSourceNode = 0
		}

		//fmt.Printf("currentTick: %d node: %d tag: %s reflecting message to upstream  with source: %d and target %d, by %d, new tick %d\n", n.currentTick, n.nodeID, tempSourceNode, 0, tickDelay, newTick)
		n.upMutex.Lock()
		heap.Push(&n.upStreamMessageQueue, n.MakeQueueItem(newTick, tempSourceNode, 0, tag, data))
		n.upMutex.Unlock()
	}
	n.downstream.SendMessage(sourceNode, targetNode, tag, data)
}

func (n *MessageReflectionFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

// if there is an upstream reflector for the node, then compute the release tick for the reflected message and add to downstream message queue
func (n *MessageReflectionFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	tickDelay := -1
	if ticDelayTagMap, hasNode := n.upStreamReflection[n.nodeID]; hasNode {
		if delay, hasTag := ticDelayTagMap[string(tag)]; hasTag {
			tickDelay = delay
		} else if delay, hasAny := ticDelayTagMap["*"]; hasAny {
			tickDelay = delay
		}
	}
	if tickDelay != -1 {
		newTick := n.currentTick + tickDelay

		//fmt.Printf("currentTick: %d node: %d tag: %s reflecting upstream message with source: %d and target %d, by %d, new tick %d\n", n.currentTick, n.nodeID, tag,n.nodeID, sourceNode, tickDelay, newTick)
		n.downMutex.Lock()
		heap.Push(&n.downStreamMessageQueue, n.MakeQueueItem(newTick, n.nodeID, sourceNode, tag, data))
		n.downMutex.Unlock()
	}
	n.upstream.ReceiveMessage(sourceNode, tag, data)
}

func (n *MessageReflectionFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

func (n *MessageReflectionFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

func (n *MessageReflectionFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	networkFilter := MessageReflectionFilter{
		nodeID:               nodeID,
		upStreamReflection:   n.upStreamReflection,
		downStreamReflection: n.downStreamReflection,
	}
	networkFilter.Init()
	return &networkFilter
}

func (n *MessageReflectionFilter) Tick(newClockTime int) bool {
	// update the current tick
	n.currentTick = newClockTime
	// process messages in buffer
	sent := n.processDownstreamBuffer()
	received := n.processUpstreamBuffer()
	// forward the tick
	return n.upstream.Tick(newClockTime) || sent || received
}

// check for messages ready to send on downstream and upstream queues
func (n *MessageReflectionFilter) processDownstreamBuffer() bool {
	n.downMutex.Lock()
	defer n.downMutex.Unlock()
	sent := false
	for n.downStreamMessageQueue.Len() > 0 {
		item := heap.Pop(&n.downStreamMessageQueue).(*QueueItem)
		if item.priority <= n.currentTick {
			// time on queue has expired, send the message
			n.downstream.SendMessage(item.message.sourceNode, item.message.targetNode, item.message.tag, item.message.data)
			//fmt.Printf("currentTick: %d node: %d releasing reflected downstream message with tag %s and tick %d\n", n.currentTick, n.nodeID, item.message.tag, item.priority)
			sent = true
		} else {
			// we have gone beyond current time, push the message back to the queue and break
			heap.Push(&n.downStreamMessageQueue, item)
			//fmt.Printf("currentTick: %d node: %d pushing back reflected downstream message with tick %d\n", n.currentTick, n.nodeID, item.priority)
			break
		}
	}
	return sent
}

func (n *MessageReflectionFilter) processUpstreamBuffer() bool {
	n.upMutex.Lock()
	defer n.upMutex.Unlock()
	received := false
	for n.upStreamMessageQueue.Len() > 0 {
		item := heap.Pop(&n.upStreamMessageQueue).(*QueueItem)
		if item.priority <= n.currentTick {
			// time on queue has expired, receive the message
			n.upstream.ReceiveMessage(item.message.sourceNode, item.message.tag, item.message.data)
			//fmt.Printf("currentTick: %d node: %d releasing reflected upstream message with tag %s and tick %d\n", n.currentTick, n.nodeID, item.message.tag, item.priority)
			received = true
		} else {
			// we have gone beyond current time, push the message back to the queue and break
			heap.Push(&n.upStreamMessageQueue, item)
			//fmt.Printf("currentTick: %d node: %d pushing back reflected upstream message with tick %d\n", n.currentTick, n.nodeID, item.priority)
			break
		}
	}
	return received
}

// Unmarshall MessageReflectionFilter
func (n *MessageReflectionFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type messageReflectionFilterJSON struct {
		Name                 string
		UpStreamReflection   map[int]map[string]int
		DownStreamReflection map[int]map[string]int
	}

	var jsonConfig messageReflectionFilterJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "MessageReflectionFilter" {
		return nil
	}
	return &MessageReflectionFilter{
		upStreamReflection:   jsonConfig.UpStreamReflection,
		downStreamReflection: jsonConfig.DownStreamReflection,
	}
}

// register MessageReflectionFilter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &MessageReflectionFilter{})
}
