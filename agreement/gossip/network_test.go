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

package gossip

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network"
	"github.com/algorand/go-algorand/protocol"
)

type sentMessage struct {
	Tag    network.Tag
	Data   []byte
	Sender uint32
	To     uint32
}

type whiteholeDomain struct {
	messages     []sentMessage
	messagesMu   deadlock.Mutex
	messagesCond *sync.Cond
	peerIdx      uint32
	log          logging.Logger
}

type whiteholeNetwork struct {
	network.GossipNode
	peer         uint32
	lastMsgRead  uint32
	mux          *network.Multiplexer
	quit         chan struct{}
	domain       *whiteholeDomain
	disconnected map[uint32]bool
	log          logging.Logger
}

func (d *whiteholeDomain) syncNetwork(networks ...*whiteholeNetwork) {
	// find the greatest network.
	d.messagesMu.Lock()
	targetMsg := uint32(len(d.messages))
	d.messagesMu.Unlock()
	for _, w := range networks {
		for {
			currentMsg := atomic.LoadUint32(&w.lastMsgRead)
			if targetMsg <= currentMsg {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (d *whiteholeDomain) reconnectNetwork(networks ...*whiteholeNetwork) {
	// find the greatest network.
	d.messagesMu.Lock()
	defer d.messagesMu.Unlock()
	for _, w := range networks {
		w.disconnected = make(map[uint32]bool)
	}
}

// RegisterHandlers registers the set of given message handlers.
func (w *whiteholeNetwork) RegisterHandlers(dispatch []network.TaggedMessageHandler) {
	w.mux.RegisterHandlers(dispatch)
}

// ClearHandlers deregisters all the existing message handlers.
func (w *whiteholeNetwork) ClearHandlers() {
	w.mux.ClearHandlers([]network.Tag{})
}

func (w *whiteholeNetwork) Address() (string, bool) {
	return "", false
}

func (w *whiteholeNetwork) placeMsg(msg sentMessage) {
	w.domain.messagesMu.Lock()
	defer w.domain.messagesMu.Unlock()
	w.domain.messages = append(w.domain.messages, msg)
	atomic.AddUint32(&w.lastMsgRead, 1)
	w.domain.messagesCond.Broadcast()
}

func (w *whiteholeNetwork) innerBroadcast(tag network.Tag, data []byte) {
	msg := sentMessage{
		Tag:    tag,
		Data:   data,
		Sender: w.peer,
	}
	w.placeMsg(msg)
	return
}

func (w *whiteholeNetwork) Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except network.Peer) error {
	if wait == true {
		w.innerBroadcast(tag, data)
	} else {
		go w.innerBroadcast(tag, data)
	}
	return nil
}

func (w *whiteholeNetwork) Relay(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except network.Peer) error {
	return w.Broadcast(ctx, tag, data, wait, except)
}

// BroadcastSimple uses a default context and blocks and sends to all peers.
func (w *whiteholeNetwork) BroadcastSimple(tag protocol.Tag, data []byte) error {
	return w.Broadcast(context.Background(), tag, data, true, nil)
}
func (w *whiteholeNetwork) Disconnect(badnode network.Peer) {
	return
}
func (w *whiteholeNetwork) DisconnectPeers() {
	return
}
func (w *whiteholeNetwork) Ready() chan struct{} {
	return make(chan struct{})
}
func (w *whiteholeNetwork) RegisterRPCName(name string, rcvr interface{}) {
	return
}
func (w *whiteholeNetwork) RequestConnectOutgoing(replace bool, quit <-chan struct{}) {
	return
}
func (w *whiteholeNetwork) GetPeers(options ...network.PeerOption) []network.Peer {
	return nil
}
func (w *whiteholeNetwork) RegisterHTTPHandler(path string, handler http.Handler) {
}
func (w *whiteholeNetwork) GetHTTPRequestConnection(request *http.Request) (conn net.Conn) {
	return nil
}

func (w *whiteholeNetwork) Start() {
	w.quit = make(chan struct{})
	go func(w *whiteholeNetwork) {
		w.domain.messagesMu.Lock()
		defer w.domain.messagesMu.Unlock()
		for {
			// wait for the message to appear in the array.
			for atomic.LoadUint32(&w.lastMsgRead) >= uint32(len(w.domain.messages)) {
				w.domain.messagesCond.Wait()
			}
			select {
			case <-w.quit:
				return
			default:
			}

			// get the message.
			var msg sentMessage
			for {
				msgIdx := int(atomic.LoadUint32(&w.lastMsgRead))
				msg = w.domain.messages[msgIdx]

				if (msg.To == 0 || msg.To == w.peer) && (!w.disconnected[msg.Sender]) {
					// message is for us !
					break
				}
				atomic.AddUint32(&w.lastMsgRead, 1)
				if atomic.LoadUint32(&w.lastMsgRead) >= uint32(len(w.domain.messages)) {
					// no new messages for us.
					break
				}
			}

			if msg.Tag == "" {
				continue
			}
			incomingMessage := network.IncomingMessage{
				Tag:  msg.Tag,
				Data: msg.Data,
			}
			outMsg := w.mux.Handle(incomingMessage)
			switch outMsg.Action {
			case network.Broadcast:
				w.domain.messagesMu.Unlock()
				w.BroadcastSimple(outMsg.Tag, outMsg.Payload)
				w.domain.messagesMu.Lock()
			case network.Disconnect:
				if msg.Sender != 0 {
					w.disconnected[msg.Sender] = true
				}
			case network.Ignore:
			default:
			}
			atomic.AddUint32(&w.lastMsgRead, 1)
		}
	}(w)
	return
}
func (w *whiteholeNetwork) getMux() *network.Multiplexer {
	return w.mux
}

func (w *whiteholeNetwork) Stop() {
	close(w.quit)
	w.domain.messagesCond.Broadcast()
}

type messageCounter struct {
	votes, proposals, bundles uint32
	quit                      chan struct{}
}

func (m *messageCounter) waitForValue(t *testing.T, expectedValue uint32, val *uint32, valName string) bool {
	deadline := time.Now().Add(3 * time.Second)
	lastValue := atomic.LoadUint32(val)
	if expectedValue == lastValue {
		return true
	} else if expectedValue < lastValue {
		return assert.Equalf(t, expectedValue, lastValue, "%s", valName)
	}
	for {
		time.Sleep(50 * time.Millisecond)
		currentValue := atomic.LoadUint32(val)

		if expectedValue == currentValue {
			break
		}

		// if the value was updated, extend the deadline.
		if currentValue > lastValue {
			lastValue = currentValue
			deadline = time.Now().Add(2 * time.Second)
			continue
		}

		if time.Now().After(deadline) {
			// we have exceeded the timelimit.
			return assert.Equalf(t, expectedValue, atomic.LoadUint32(val), "%s", valName)
		}
	}
	return true
}

func (m *messageCounter) verify(t *testing.T, expectedVotes, expectedProposals, expectedBundles uint32) bool {

	if !m.waitForValue(t, expectedVotes, &m.votes, "votes") {
		return false
	}
	if !m.waitForValue(t, expectedProposals, &m.proposals, "proposals") {
		return false
	}
	if !m.waitForValue(t, expectedBundles, &m.bundles, "bundles") {
		return false
	}

	atomic.StoreUint32(&m.votes, 0)
	atomic.StoreUint32(&m.proposals, 0)
	atomic.StoreUint32(&m.bundles, 0)
	return true
}

func startMessageCounter(n *networkImpl) *messageCounter {
	m := &messageCounter{
		quit: make(chan struct{}),
	}
	go func(m *messageCounter, n *networkImpl) {
		votesChan := n.Messages(protocol.AgreementVoteTag)
		payloadChan := n.Messages(protocol.ProposalPayloadTag)
		bundlesChan := n.Messages(protocol.VoteBundleTag)
		for {
			select {
			case <-m.quit:
				return
			case msg := <-votesChan:
				atomic.AddUint32(&m.votes, 1)
				buf := msg.Data
				if len(buf) > 1 {
					n.Broadcast(protocol.ProposalPayloadTag, buf[1:])
				}
			case msg := <-payloadChan:
				proposals := atomic.AddUint32(&m.proposals, 1)
				buf := msg.Data
				if len(buf) > 1 && proposals > 1 {
					n.Disconnect(msg.MessageHandle)
				}
			case <-bundlesChan:
				atomic.AddUint32(&m.bundles, 1)
			}
		}
	}(m, n)
	return m
}

func (m *messageCounter) stop() {
	close(m.quit)
}

func makewhiteholeNetwork(domain *whiteholeDomain) *whiteholeNetwork {
	domain.messagesMu.Lock()
	defer domain.messagesMu.Unlock()
	w := &whiteholeNetwork{
		peer:         atomic.AddUint32(&domain.peerIdx, 1),
		lastMsgRead:  uint32(len(domain.messages)),
		mux:          network.MakeMultiplexer(domain.log),
		domain:       domain,
		disconnected: make(map[uint32]bool),
	}
	return w
}

func spinNetworkImpl(domain *whiteholeDomain) (whiteholeNet *whiteholeNetwork, counter *messageCounter) {
	whiteholeNet = makewhiteholeNetwork(domain)
	netImpl := WrapNetwork(whiteholeNet, logging.Base()).(*networkImpl)
	counter = startMessageCounter(netImpl)
	whiteholeNet.Start()
	netImpl.Start()
	return
}

func TestNetworkImpl(t *testing.T) {
	t.Parallel()

	domain := &whiteholeDomain{
		messages: make([]sentMessage, 0),
		peerIdx:  uint32(0),
		log:      logging.TestingLog(t),
	}
	domain.messagesCond = sync.NewCond(&domain.messagesMu)

	net1, counter1 := spinNetworkImpl(domain)
	net2, counter2 := spinNetworkImpl(domain)
	net3, counter3 := spinNetworkImpl(domain)
	defer counter1.stop()
	defer counter2.stop()
	defer counter3.stop()
	defer net1.Stop()
	defer net2.Stop()
	defer net3.Stop()

	net1.BroadcastSimple(protocol.AgreementVoteTag, []byte{1})
	domain.syncNetwork(net1, net2, net3)
	counter1.verify(t, 0, 0, 0)
	counter2.verify(t, 1, 0, 0)
	counter3.verify(t, 1, 0, 0)
	domain.reconnectNetwork(net1, net2, net3)

	net2.BroadcastSimple(protocol.ProposalPayloadTag, []byte{4})
	domain.syncNetwork(net1, net2, net3)
	counter1.verify(t, 0, 1, 0)
	counter2.verify(t, 0, 0, 0)
	counter3.verify(t, 0, 1, 0)
	domain.reconnectNetwork(net1, net2, net3)

	net3.BroadcastSimple(protocol.VoteBundleTag, []byte{7})
	domain.syncNetwork(net1, net2, net3)
	counter1.verify(t, 0, 0, 1)
	counter2.verify(t, 0, 0, 1)
	counter3.verify(t, 0, 0, 0)
	domain.reconnectNetwork(net1, net2, net3)

	net1.BroadcastSimple(protocol.AgreementVoteTag, []byte{1, 2, 3})
	domain.syncNetwork(net1, net2, net3)
	counter1.verify(t, 0, 2, 0)
	counter2.verify(t, 1, 1, 0)
	counter3.verify(t, 1, 1, 0)
	domain.reconnectNetwork(net1, net2, net3)

	net1.BroadcastSimple(protocol.ProposalPayloadTag, []byte{1, 2, 3, 4, 5})
	domain.syncNetwork(net1, net2, net3)
	counter1.verify(t, 0, 0, 0)
	counter2.verify(t, 0, 1, 0)
	counter3.verify(t, 0, 1, 0)
	domain.reconnectNetwork(net1, net2, net3)

	net1.BroadcastSimple(protocol.VoteBundleTag, []byte{1, 2, 3})
	domain.syncNetwork(net1, net2, net3)
	counter1.verify(t, 0, 0, 0)
	counter2.verify(t, 0, 0, 1)
	counter3.verify(t, 0, 0, 1)
	domain.reconnectNetwork(net1, net2, net3)

}
