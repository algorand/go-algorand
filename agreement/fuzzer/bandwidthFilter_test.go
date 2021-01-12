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
	"container/list"
	"encoding/json"
	"fmt"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/protocol"
)

// BandwidthFilter limits message flow by bandwidth/tic with buffering
type BandwidthFilter struct {
	NetworkFilter
	NetworkFilterFactory
	fuzzer *Fuzzer

	upstream   UpstreamFilter
	downstream DownstreamFilter

	nodeID              int
	upStreamBandwidth   map[int]int
	downStreamBandwidth map[int]int
	upstreamDataSize    int
	downstreamDataSize  int
	mutex               deadlock.Mutex // protect the access to upstreamDataSize / downstreamDataSize
	upstreamQueue       *list.List
	downstreamQueue     *list.List
	upstreamMutex       deadlock.Mutex // protect the access to the upstreamQueue
	downstreamMutex     deadlock.Mutex
	currentTick         int
	debugMessageLevel   int // 0 == none, 1 == some, 2 = more
}

// Initialize the bandwidth filter, setup up/down stream buffers, and network
func (n *BandwidthFilter) Init(fuzzer *Fuzzer) {
	n.upstreamQueue = list.New()
	n.downstreamQueue = list.New()
	n.fuzzer = fuzzer
}

// Factory method for BandwidthFilter
func MakeBandwidthFilter(upStreamBandwidth map[int]int, downStreamBandwidth map[int]int) *BandwidthFilter {
	return &BandwidthFilter{
		upStreamBandwidth:   upStreamBandwidth,
		downStreamBandwidth: downStreamBandwidth,
		debugMessageLevel:   0,
	}
}

// Forward downstream messages while there is downstream bandwidth available, buffer the remaining
func (n *BandwidthFilter) SendMessage(sourceNode, targetNode int, tag protocol.Tag, data []byte) {
	bandwidth, has := n.downStreamBandwidth[n.nodeID]
	if !has || bandwidth == 0 {
		// infinite bandwidth node.
		n.downstream.SendMessage(sourceNode, targetNode, tag, data)
		return
	}
	start := 0
	end := n.fuzzer.nodesCount
	if targetNode != -1 {
		start = targetNode
		end = start + 1
	}
	for i := start; i < end; i++ {
		if i == n.nodeID {
			continue
		}
		n.mutex.Lock()
		n.downstreamMutex.Lock()
		if n.debugMessageLevel >= 1 {
			fmt.Printf("node: %d, tick: %d, queuing downstream data size: %d/%d\n", n.nodeID, n.currentTick, n.downstreamDataSize, bandwidth)
		}
		n.downstreamQueue.PushBack(&AlgoMessage{
			sourceNode: sourceNode,
			targetNode: i,
			tag:        tag,
			data:       data,
		})
		n.downstreamMutex.Unlock()
		n.mutex.Unlock()
	}

	n.processQueuedDownstreamMessages()
}

// Return the downstream filter
func (n *BandwidthFilter) GetDownstreamFilter() DownstreamFilter {
	return n.downstream
}

// Forward downstream messages while there is upstream bandwidth available, buffer the remaining
func (n *BandwidthFilter) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	bandwidth, has := n.upStreamBandwidth[n.nodeID]
	if !has || bandwidth == 0 {
		n.upstream.ReceiveMessage(sourceNode, tag, data)
		return
	}
	n.mutex.Lock()
	n.upstreamMutex.Lock()

	if n.debugMessageLevel >= 1 {
		fmt.Printf("node: %d, tick: %d, queuing upstream data size: %d/%d/%d\n", n.nodeID, n.currentTick, n.upstreamDataSize, len(data), bandwidth)
	}
	n.upstreamQueue.PushBack(&AlgoMessage{
		sourceNode: sourceNode,
		targetNode: 0,
		tag:        tag,
		data:       data,
	})
	n.upstreamMutex.Unlock()
	n.mutex.Unlock()

	n.processQueuedUpstreamMessages()
}

// Connect downstream filter
func (n *BandwidthFilter) SetDownstreamFilter(f DownstreamFilter) {
	n.downstream = f
}

// Connect upstream filter
func (n *BandwidthFilter) SetUpstreamFilter(f UpstreamFilter) {
	n.upstream = f
}

// Implement create filter method
func (n *BandwidthFilter) CreateFilter(nodeID int, fuzzer *Fuzzer) NetworkFilter {
	bandwidthFilter := BandwidthFilter{
		nodeID:              nodeID,
		upStreamBandwidth:   n.upStreamBandwidth,
		downStreamBandwidth: n.downStreamBandwidth,
		debugMessageLevel:   n.debugMessageLevel,
	}
	bandwidthFilter.Init(fuzzer)
	return &bandwidthFilter
}

// Process clock tick
func (n *BandwidthFilter) Tick(newClockTime int) bool {
	// Adjust the data size accumulators, process messages in queues, and pass along upstream tick
	if n.debugMessageLevel >= 2 {
		fmt.Printf("node: %d, tick: %d, current downstream: %d/%d upstream: %d/%d\n", n.nodeID, n.currentTick, n.downstreamDataSize, n.downStreamBandwidth[n.nodeID], n.upstreamDataSize, n.upStreamBandwidth[n.nodeID])
	}
	n.adjustAvailableDataSize(newClockTime)

	sent := n.processQueuedDownstreamMessages()

	// adjust the upstream size.
	n.downstreamMutex.Lock()
	if n.downstreamDataSize < 0 && n.downstreamQueue.Len() == 0 {
		if n.debugMessageLevel >= 1 {
			fmt.Printf("node: %d, tick: %d, reseting queued downstream capacity %d -> 0\n", n.nodeID, n.currentTick, n.upstreamDataSize)
		}
		n.downstreamDataSize = 0
	}
	n.downstreamMutex.Unlock()

	received := n.processQueuedUpstreamMessages()

	n.upstreamMutex.Lock()
	// adjust the upstream size.
	if n.upstreamDataSize < 0 && n.upstreamQueue.Len() == 0 {
		if n.debugMessageLevel >= 1 {
			fmt.Printf("node: %d, tick: %d, reseting queued upstream capacity %d -> 0\n", n.nodeID, n.currentTick, n.upstreamDataSize)
		}
		n.upstreamDataSize = 0
	}
	n.upstreamMutex.Unlock()

	return n.upstream.Tick(newClockTime) || sent || received
}

// Adjust downstream size based on number of ticks since last invocation of Tick() method, each tick receives the
// number of bandwidth bytes
func (n *BandwidthFilter) adjustAvailableDataSize(newClockTime int) {
	deltaTicks := newClockTime - n.currentTick
	n.currentTick = newClockTime
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if bandwidth, has := n.downStreamBandwidth[n.nodeID]; has && bandwidth != 0 {
		n.downstreamDataSize += -(bandwidth * (deltaTicks - 1))
		if n.debugMessageLevel >= 2 {
			fmt.Printf("node: %d, tick: %d, delta: %d, current downstream bandwidth: %d/%d\n", n.nodeID, n.currentTick, deltaTicks, n.downstreamDataSize, bandwidth)
		}
	}
	if bandwidth, has := n.upStreamBandwidth[n.nodeID]; has && bandwidth != 0 {
		n.upstreamDataSize += -(bandwidth * (deltaTicks - 1))
		if n.debugMessageLevel >= 2 {
			fmt.Printf("node: %d, tick: %d, delta: %d, current upstream bandwidth: %d/%d\n", n.nodeID, n.currentTick, deltaTicks, n.upstreamDataSize, bandwidth)
		}
	}
}

// Check for messages in the downstream queue and process with available bandwidth.
// While there is more bandwidth, dequeue and send messages.
// Decrement the available bandwidth for each message sent.
func (n *BandwidthFilter) processQueuedDownstreamMessages() bool {
	messageSent := false
	bandwidth, has := n.downStreamBandwidth[n.nodeID]
	if !has {
		return false
	}

	n.mutex.Lock()
	n.downstreamMutex.Lock()
	if n.downstreamDataSize > bandwidth {
		n.downstreamMutex.Unlock()
		n.mutex.Unlock()
		return false
	}
	for n.downstreamQueue.Len() > 0 {
		element := n.downstreamQueue.Front() // First element
		message := element.Value.(*AlgoMessage)
		dataLen := len(message.data)
		if dataLen+n.downstreamDataSize <= bandwidth {
			n.downstreamQueue.Remove(element)
			n.downstreamDataSize += dataLen
			n.downstreamMutex.Unlock()
			n.mutex.Unlock()
			n.downstream.SendMessage(message.sourceNode, message.targetNode, message.tag, message.data)
			n.mutex.Lock()
			n.downstreamMutex.Lock()
			messageSent = true
			if n.debugMessageLevel >= 1 {
				fmt.Printf("node: %d, tick: %d, forwarding queued downstream message bandwidth %d/%d\n", n.nodeID, n.currentTick, n.downstreamDataSize, n.downStreamBandwidth[n.nodeID])
			}
		} else {
			break
		}
	}
	n.downstreamMutex.Unlock()
	n.mutex.Unlock()
	return messageSent
}

// Check for messages in the upstream queue and process with available bandwidth.
func (n *BandwidthFilter) processQueuedUpstreamMessages() bool {
	messageReceived := false
	bandwidth, has := n.upStreamBandwidth[n.nodeID]
	if !has {
		return false
	}

	n.mutex.Lock()
	n.upstreamMutex.Lock()
	if n.upstreamDataSize > bandwidth {
		n.upstreamMutex.Unlock()
		n.mutex.Unlock()
		return false
	}
	for n.upstreamQueue.Len() > 0 {
		element := n.upstreamQueue.Front() // First element
		message := element.Value.(*AlgoMessage)
		dataLen := len(message.data)
		if dataLen+n.upstreamDataSize <= bandwidth {
			n.upstreamQueue.Remove(element)
			n.upstreamDataSize += dataLen
			n.upstreamMutex.Unlock()
			n.mutex.Unlock()
			n.upstream.ReceiveMessage(message.sourceNode, message.tag, message.data)
			n.mutex.Lock()
			n.upstreamMutex.Lock()
			messageReceived = true

			if n.debugMessageLevel >= 1 {
				fmt.Printf("node: %d, tick: %d, forwarding queued upstream message %d bandwidth %d/%d\n", n.nodeID, n.currentTick, dataLen, n.upstreamDataSize, n.upStreamBandwidth[n.nodeID])
			}
		} else {
			break
		}
	}

	n.upstreamMutex.Unlock()
	n.mutex.Unlock()

	return messageReceived
}

// Un marshall FilterFactory
func (n *BandwidthFilter) Unmarshal(b []byte) NetworkFilterFactory {
	type bandwidthFilterJSON struct {
		Name                string
		UpstreamBandwidth   map[int]int
		DownstreamBandwidth map[int]int
	}

	var jsonConfig bandwidthFilterJSON
	if err := json.Unmarshal(b, &jsonConfig); err != nil {
		return nil
	}
	if jsonConfig.Name != "BandwidthFilter" {
		return nil
	}
	return MakeBandwidthFilter(jsonConfig.UpstreamBandwidth, jsonConfig.DownstreamBandwidth)
}

// register BandwidthFilter filter
func init() {
	registeredFilterFactories = append(registeredFilterFactories, &BandwidthFilter{})
}
