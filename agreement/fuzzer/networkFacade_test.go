// Copyright (C) 2019-2025 Algorand, Inc.
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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"
	"reflect"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/timers"
)

var maxEventQueueWait = time.Second * 3

type NetworkFacadeMessage struct {
	tag    protocol.Tag
	data   []byte
	source int
}

// NetworkFacade is the "stub" that is applied between the agreement service gossip network implementation and the fuzzer network.
type NetworkFacade struct {
	network.GossipNode
	NetworkFilter
	timers.Clock[agreement.TimeoutType]
	nodeID                         int
	mux                            *network.Multiplexer
	fuzzer                         *Fuzzer
	downstream                     DownstreamFilter
	downstreamMu                   deadlock.Mutex
	clockSync                      deadlock.Mutex
	zeroClock                      int
	clocks                         map[int]chan time.Time
	pendingOutgoingMsg             []NetworkFacadeMessage
	pendingOutgoingMsgMu           deadlock.Mutex
	pendingIncomingMsg             []NetworkFacadeMessage
	pendingIncomingMsgMu           deadlock.Mutex
	pendingOutgoingMsgNotification context.CancelFunc
	debugMessages                  bool
	eventsQueues                   map[string]int
	eventsQueuesMu                 deadlock.Mutex
	eventsQueuesCh                 chan int
	rand                           *rand.Rand
	timeoutAtInitOnce              sync.Once
	timeoutAtInitWait              sync.WaitGroup
	peerToNode                     map[*facadePeer]int
}

type facadePeer struct {
	id  int
	net network.GossipNode
}

func (p *facadePeer) GetNetwork() network.GossipNode { return p.net }
func (p *facadePeer) RoutingAddr() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(p.id))
	return buf
}

// MakeNetworkFacade creates a facade with a given nodeID.
func MakeNetworkFacade(fuzzer *Fuzzer, nodeID int) *NetworkFacade {
	n := &NetworkFacade{
		fuzzer:         fuzzer,
		nodeID:         nodeID,
		mux:            network.MakeMultiplexer(),
		clocks:         make(map[int]chan time.Time),
		eventsQueues:   make(map[string]int),
		eventsQueuesCh: make(chan int, 1000),
		rand:           rand.New(rand.NewSource(int64(nodeID))),
		peerToNode:     make(map[*facadePeer]int, fuzzer.nodesCount),
		debugMessages:  false,
	}
	n.timeoutAtInitWait.Add(1)
	for i := 0; i < fuzzer.nodesCount; i++ {
		n.peerToNode[&facadePeer{id: i, net: n}] = i
	}
	return n
}

func (n *NetworkFacade) WaitForTimeoutAt() {
	n.timeoutAtInitWait.Wait()
}

func (n *NetworkFacade) ResetWaitForTimeoutAt() {
	n.timeoutAtInitWait = sync.WaitGroup{}
	n.timeoutAtInitWait.Add(1)
	n.timeoutAtInitOnce = sync.Once{}
}

func (n *NetworkFacade) UpdateEventsQueue(queueName string, queueLength int) {
	n.eventsQueuesMu.Lock()
	n.eventsQueues[queueName] = queueLength
	sum := 0
	for _, v := range n.eventsQueues {
		sum += v
	}
	n.eventsQueuesMu.Unlock()
	n.eventsQueuesCh <- sum
}

func (n *NetworkFacade) DumpQueues() {
	queues := "----------------------\n"
	n.eventsQueuesMu.Lock()
	for k, v := range n.eventsQueues {
		queues += fmt.Sprintf("Queue %s has %d items\n", k, v)
	}
	n.eventsQueuesMu.Unlock()
	queues += "----------------------\n"
	fmt.Print(queues)
}

func (n *NetworkFacade) WaitForEventsQueue(cleared bool) {
	ledger := n.fuzzer.ledgers[n.nodeID]
	if cleared {
		// wait until we get a zero from the event channel.
		maxWait := time.After(maxEventQueueWait)
		for {

			select {
			case v := <-n.eventsQueuesCh:
				if v == 0 {
					return
				}
			case <-ledger.GetEnsuringDigestCh(true):
				if n.debugMessages {
					fmt.Printf("NetworkFacade service-%v entered ensuring digest mode\n", n.nodeID)
				}
				// ensure digest started.
				if ledger.TryEnsuringDigest() == true {
					// we've tried and failed to sync the ledger from other nodes/
					return
				}
				// keep waiting, as we've just update the ledger from another node.
			case <-maxWait:
				n.DumpQueues()
				//panic("Waiting for event processing for 0 took too long")
				pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
				panic(fmt.Sprintf("maxWait %d sec exceeded", maxEventQueueWait/time.Second))
			}

		}
	} else {
		if ledger.IsEnsuringDigest() {
			return
		}
		// wait until we get a non-zero from the event channel.
		maxWait := time.After(maxEventQueueWait)
		for {
			select {
			case v := <-n.eventsQueuesCh:
				if v != 0 {
					return
				}
			case <-maxWait:
				n.DumpQueues()
				panic("Waiting for event processing for non zero took too long")
			}
		}
	}
}

// Broadcast
func (n *NetworkFacade) Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, exclude network.Peer) error {
	excludeNode := -1
	if exclude != nil {
		excludeNode = n.peerToNode[exclude.(*facadePeer)]
	}
	return n.broadcast(tag, data, excludeNode, "NetworkFacade service-%v Broadcast %v %v\n")
}

// Relay
func (n *NetworkFacade) Relay(ctx context.Context, tag protocol.Tag, data []byte, wait bool, exclude network.Peer) error {
	return n.Broadcast(ctx, tag, data, wait, exclude)
}

func (n *NetworkFacade) broadcast(tag protocol.Tag, data []byte, exclude int, debugMsg string) error {
	n.pendingOutgoingMsgMu.Lock()
	defer n.pendingOutgoingMsgMu.Unlock()
	n.pendingOutgoingMsg = append(n.pendingOutgoingMsg, NetworkFacadeMessage{tag, data, exclude})
	if len(n.pendingOutgoingMsg) == 1 && n.pendingOutgoingMsgNotification != nil {
		n.pendingOutgoingMsgNotification()
		n.pendingOutgoingMsgNotification = nil
	}
	if n.debugMessages {
		fmt.Printf(debugMsg, n.nodeID, tag, data[:6])
	}
	return nil
}

// push the queued message downstream.
func (n *NetworkFacade) PushDownstreamMessage(newMsg context.CancelFunc) bool {
	n.pendingOutgoingMsgMu.Lock()

	if len(n.pendingOutgoingMsg) == 0 {
		if newMsg != nil {
			n.pendingOutgoingMsgNotification = newMsg
		}
		n.pendingOutgoingMsgMu.Unlock()
		return false
	}
	msg := n.pendingOutgoingMsg[0]
	n.pendingOutgoingMsg = n.pendingOutgoingMsg[1:]
	if len(n.pendingOutgoingMsg) == 0 && newMsg != nil {
		n.pendingOutgoingMsgNotification = newMsg
	}
	n.pendingOutgoingMsgMu.Unlock()
	if n.debugMessages {
		fmt.Printf("NetworkFacade service-%v SendMessage %v %v\n", n.nodeID, msg.tag, msg.data[:6])
	}
	if msg.source == -1 {
		n.GetDownstreamFilter().SendMessage(n.nodeID, -1, msg.tag, msg.data)
	} else {
		for i := 0; i < n.fuzzer.nodesCount; i++ {
			if i == n.nodeID || i == msg.source {
				continue
			}
			n.GetDownstreamFilter().SendMessage(n.nodeID, i, msg.tag, msg.data)
		}
	}
	return true
}

// Address - unused function
func (n *NetworkFacade) Address() (string, bool) { return "mock network", true }

// Start - unused function
func (n *NetworkFacade) Start() error { return nil }

// Stop - unused function
func (n *NetworkFacade) Stop() {}

// Ready - always ready
func (n *NetworkFacade) Ready() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// RegisterHandlers
func (n *NetworkFacade) RegisterHandlers(dispatch []network.TaggedMessageHandler) {
	n.mux.RegisterHandlers(dispatch)
}

// ClearHandlers
func (n *NetworkFacade) ClearHandlers() {
	n.mux.ClearHandlers([]network.Tag{})
}

// SetDownstreamFilter sets the downstream filter.
func (n *NetworkFacade) SetDownstreamFilter(f DownstreamFilter) {
	n.downstreamMu.Lock()
	defer n.downstreamMu.Unlock()
	n.downstream = f
}

// GetDownstreamFilter retreives the downsteam filter
func (n *NetworkFacade) GetDownstreamFilter() DownstreamFilter {
	n.downstreamMu.Lock()
	defer n.downstreamMu.Unlock()
	return n.downstream
}

func (n *NetworkFacade) pushPendingReceivedMessage() bool {
	if len(n.pendingIncomingMsg) == 0 {
		return false
	}

	if n.fuzzer.ledgers[n.nodeID].IsEnsuringDigest() {
		return false
	}
	storedMsg := n.pendingIncomingMsg[0]
	n.pendingIncomingMsg = n.pendingIncomingMsg[1:]
	msg := network.IncomingMessage{
		Tag:  storedMsg.tag,
		Data: storedMsg.data,
	}
	for peer, nodeID := range n.peerToNode {
		if nodeID == storedMsg.source {
			msg.Sender = peer
			break
		}
	}
	if n.debugMessages {
		fmt.Printf("NetworkFacade service-%v ReceiveMessage %v %v\n", n.nodeID, storedMsg.tag, storedMsg.data[:6])
	}
	outMsg := n.mux.Handle(msg)
	func() {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("panic : NetworkFacade service-%v ReceiveMessage %v %v\n", n.nodeID, storedMsg.tag, storedMsg.data[:6])
				panic(err)
			}
		}()
		n.WaitForEventsQueue(false)      // wait for non-zero.
		defer n.WaitForEventsQueue(true) // wait for zero.

	}()

	switch outMsg.Action {
	case network.Disconnect:
		n.fuzzer.Disconnect(n.nodeID, storedMsg.source)
	case network.Ignore:
		// nothing to do.
	case network.Broadcast:
		n.broadcast(storedMsg.tag, storedMsg.data, -1, "NetworkFacade service-%v Broadcast-Action %v %v\n")
	default:
		panic(fmt.Sprintf("unhandled network action %v", outMsg.Action))
	}

	if n.debugMessages {
		fmt.Printf("NetworkFacade service-%v ReceiveMessage done %v %v\n", n.nodeID, storedMsg.tag, storedMsg.data[:6])
	}

	if len(n.pendingIncomingMsg) > 0 {
		n.pushPendingReceivedMessage()
	}
	return true
}

// ReceiveMessage dispatches the message received.
func (n *NetworkFacade) ReceiveMessage(sourceNode int, tag protocol.Tag, data []byte) {
	//fmt.Printf("Node %v received a message %v from %v\n", n.nodeID, tag, sourceNode)
	n.pendingIncomingMsg = append(n.pendingIncomingMsg, NetworkFacadeMessage{tag, data, sourceNode})

	n.pushPendingReceivedMessage()
}

func (n *NetworkFacade) Disconnect(sender network.DisconnectablePeer) {
	sourceNode := n.peerToNode[sender.(*facadePeer)]
	n.fuzzer.Disconnect(n.nodeID, sourceNode)
}

func (n *NetworkFacade) Zero() timers.Clock[agreement.TimeoutType] {
	n.clockSync.Lock()
	defer n.clockSync.Unlock()

	n.zeroClock = n.fuzzer.WallClock()

	// we don't want to expire all the pending clocks here.
	// this callback is coming *only* from the agreement service.
	// it also means that we're not in the demux loop, so no one is blocking
	// on any of the clocks.

	n.clocks = make(map[int]chan time.Time)
	if n.debugMessages {
		fmt.Printf("NetworkFacade service-%v zero clock = %d\n", n.nodeID, n.zeroClock)
	}

	return n
}
func (n *NetworkFacade) Rezero() {
	n.clockSync.Lock()
	defer n.clockSync.Unlock()
	n.zeroClock = n.fuzzer.WallClock()
	if n.debugMessages {
		fmt.Printf("NetworkFacade service-%v rezero clock = %d\n", n.nodeID, n.zeroClock)
	}
}

// Since implements the Clock interface.
func (n *NetworkFacade) Since() time.Duration { return 0 }

func (n *NetworkFacade) TimeoutAt(d time.Duration, timeoutType agreement.TimeoutType) <-chan time.Time {
	defer n.timeoutAtInitOnce.Do(func() {
		n.timeoutAtInitWait.Done()
	})
	n.clockSync.Lock()
	defer n.clockSync.Unlock()

	targetTick := int(d / n.fuzzer.tickGranularity)
	ch, have := n.clocks[targetTick]
	if have {
		return ch
	}

	ch = make(chan time.Time)
	if targetTick == 0 {
		close(ch)
	} else {
		n.clocks[targetTick] = ch
	}
	if n.debugMessages {
		fmt.Printf("NetworkFacade service-%v TimeoutAt %d+%d=%d\n", n.nodeID, n.zeroClock, targetTick, targetTick+n.zeroClock)
	}

	return ch
}

func (n *NetworkFacade) Encode() []byte {
	n.clockSync.Lock()
	defer n.clockSync.Unlock()

	buf := new(bytes.Buffer)
	wallClock := int32(n.fuzzer.WallClock())
	binary.Write(buf, binary.LittleEndian, wallClock)
	for targetTick := range n.clocks {
		binary.Write(buf, binary.LittleEndian, int32(targetTick))
	}
	return buf.Bytes()
}

func (n *NetworkFacade) Decode(in []byte) (timers.Clock[agreement.TimeoutType], error) {
	n.clockSync.Lock()
	defer n.clockSync.Unlock()

	n.clocks = make(map[int]chan time.Time)
	buf := bytes.NewReader(in)
	var encodedZero int32

	if err := binary.Read(buf, binary.LittleEndian, &encodedZero); err != nil {
		if err != io.EOF {
			return nil, err
		}
		return n, fmt.Errorf("invalid recovery clock data")
	}
	n.zeroClock = int(encodedZero)
	for {
		var targetTick int32
		if err := binary.Read(buf, binary.LittleEndian, &targetTick); err != nil {
			if err == io.EOF {
				// no more events.
				break
			}
			return nil, err
		}
		n.clocks[int(targetTick)] = make(chan time.Time)
	}
	return n, nil
}

func (n *NetworkFacade) Tick(newClockTime int) bool {
	if n.fuzzer.ledgers[n.nodeID].IsEnsuringDigest() {
		if n.debugMessages {
			fmt.Printf("NetworkFacade service-%v Tick(%d), change false, blocking ensure digest\n", n.nodeID, newClockTime)
		}
		return false
	}
	msgSent := n.pushPendingReceivedMessage()

	if n.fuzzer.ledgers[n.nodeID].IsEnsuringDigest() {
		if n.debugMessages {
			fmt.Printf("NetworkFacade service-%v Tick(%d), change %v, blocking ensure digest after receive message\n", n.nodeID, newClockTime, msgSent)
		}
		return msgSent
	}

	n.clockSync.Lock()
	defer n.clockSync.Unlock()
	expiredClocks := []int{}
	nextTimeoutTick := -1
	// check to see if any of the clocks have expired.
	for targetTick := range n.clocks {
		if (targetTick + n.zeroClock) <= (newClockTime) {
			// this one has expired.
			expiredClocks = append(expiredClocks, targetTick)
			continue
		}
		if nextTimeoutTick == -1 || nextTimeoutTick > targetTick+n.zeroClock {
			nextTimeoutTick = targetTick + n.zeroClock
		}
	}
	if n.debugMessages {
		if nextTimeoutTick >= 0 {
			fmt.Printf("NetworkFacade service-%v Tick(%d), change %v/%v next timeout %d+%d=%d\n", n.nodeID, newClockTime, len(expiredClocks) > 0, msgSent, n.zeroClock, nextTimeoutTick-n.zeroClock, nextTimeoutTick)
		} else {
			fmt.Printf("NetworkFacade service-%v Tick(%d), change %v/%v\n", n.nodeID, newClockTime, len(expiredClocks) > 0, msgSent)
		}
	}
	for _, targetTick := range expiredClocks {
		close(n.clocks[targetTick])
		delete(n.clocks, targetTick)
		//fmt.Printf("Node %v clock %v reached\n", n.nodeID, targetTick)
	}
	const NumberOfDemuxClocks = 2
	if len(expiredClocks) > 0 && len(n.clocks) < NumberOfDemuxClocks {
		func() {
			n.clockSync.Unlock()
			defer n.clockSync.Lock()
			n.WaitForEventsQueue(false) // wait for non-zero.
			n.WaitForEventsQueue(true)  // wait for zero.
		}()
		if len(n.clocks) > 0 {
			func() {
				n.clockSync.Unlock()
				defer n.clockSync.Lock()
				n.Tick(newClockTime)
			}()
		}

	}
	return len(expiredClocks) > 0 || msgSent
}

func (n *NetworkFacade) GetFilterByType(filterType reflect.Type) interface{} {
	currentFilter := n.GetDownstreamFilter()
	for {
		if currentFilter == nil || currentFilter == n.fuzzer.router.GetDownstreamFilter() {
			return nil
		}
		if reflect.TypeOf(currentFilter) == filterType {
			return currentFilter
		}
		currentFilter = currentFilter.GetDownstreamFilter()
	}
}

// Uint64 disable the randomness, which is a good thing for our test
func (n *NetworkFacade) Uint64() uint64 {
	return n.rand.Uint64()
}
