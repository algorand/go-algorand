// Copyright (C) 2019 Algorand, Inc.
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

package network

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/algorand/websocket"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
)

const maxMessageLength = 4 * 1024 * 1024 // Currently the biggest message is VB vote bundles. TODO: per message type size limit?

// This parameter controls how many messages from a single peer can be
// queued up in the global wsNetwork.readBuffer at a time.  Making this
// too large will allow a small number of peers to flood the global read
// buffer and starve messages from other peers.
const msgsInReadBufferPerPeer = 10

var networkSentBytesTotal = metrics.MakeCounter(metrics.NetworkSentBytesTotal)
var networkReceivedBytesTotal = metrics.MakeCounter(metrics.NetworkReceivedBytesTotal)

var networkMessageReceivedTotal = metrics.MakeCounter(metrics.NetworkMessageReceivedTotal)
var networkMessageSentTotal = metrics.MakeCounter(metrics.NetworkMessageSentTotal)
var networkConnectionsDroppedTotal = metrics.MakeCounter(metrics.NetworkConnectionsDroppedTotal)
var networkMessageQueueMicrosTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_message_sent_queue_micros_total", Description: "Total microseconds message spent waiting in queue to be sent"})

var duplicateNetworkMessageReceivedTotal = metrics.MakeCounter(metrics.DuplicateNetworkMessageReceivedTotal)
var duplicateNetworkMessageReceivedBytesTotal = metrics.MakeCounter(metrics.DuplicateNetworkMessageReceivedBytesTotal)
var outgoingNetworkMessageFilteredOutTotal = metrics.MakeCounter(metrics.OutgoingNetworkMessageFilteredOutTotal)
var outgoingNetworkMessageFilteredOutBytesTotal = metrics.MakeCounter(metrics.OutgoingNetworkMessageFilteredOutBytesTotal)

// interface allows substituting debug implementation for *websocket.Conn
type wsPeerWebsocketConn interface {
	RemoteAddr() net.Addr
	NextReader() (int, io.Reader, error)
	WriteMessage(int, []byte) error
	WriteControl(int, []byte, time.Time) error
	SetReadLimit(int64)
	CloseWithoutFlush() error
}

type sendMessage struct {
	data         []byte
	enqueued     time.Time // the time at which the message was first generated
	peerEnqueued time.Time // the time at which the peer was attempting to enqueue the message
}

// wsPeerCore also works for non-connected peers we want to do HTTP GET from
type wsPeerCore struct {
	net           *WebsocketNetwork
	rootURL       string
	originAddress string
	client        http.Client
}

type disconnectReason string

const disconnectBadData disconnectReason = "BadData"
const disconnectTooSlow disconnectReason = "TooSlow"
const disconnectReadError disconnectReason = "ReadError"
const disconnectWriteError disconnectReason = "WriteError"
const disconnectIdleConn disconnectReason = "IdleConnection"
const disconnectSlowConn disconnectReason = "SlowConnection"

type wsPeer struct {
	// lastPacketTime contains the UnixNano at the last time a successfull communication was made with the peer.
	// "successfull communication" above refers to either reading from or writing to a connection without receiving any
	// error.
	// we want this to be a 64-bit aligned for atomics.
	lastPacketTime int64

	// intermittentOutgoingMessageEnqueueTime contains the UnixNano of the message's enqueue time that is currently being written to the
	// peer, or zero if no message is being written.
	intermittentOutgoingMessageEnqueueTime int64

	wsPeerCore

	// conn will be *websocket.Conn (except in testing)
	conn wsPeerWebsocketConn

	// we started this connection; otherwise it was inbound
	outgoing bool

	closing chan struct{}

	sendBufferHighPrio chan sendMessage
	sendBufferBulk     chan sendMessage

	wg sync.WaitGroup

	didSignalClose int32
	didInnerClose  int32

	TelemetryGUID string
	InstanceName  string

	incomingMsgFilter *messageFilter
	outgoingMsgFilter *messageFilter

	processed chan struct{}

	pingLock              deadlock.Mutex
	pingSent              time.Time
	pingData              []byte
	pingInFlight          bool
	lastPingRoundTripTime time.Duration

	// Hint about position in wn.peers.  Definitely valid if the peer
	// is present in wn.peers.
	peerIndex int

	// Challenge sent to the peer on an incoming connection
	prioChallenge string

	prioAddress basics.Address
	prioWeight  uint64

	// createTime is the time at which the connection was established with the peer.
	createTime time.Time
}

// HTTPPeer is what the opaque Peer might be.
// If you get an opaque Peer handle from a GossipNode, maybe try a .(HTTPPeer) type assertion on it.
type HTTPPeer interface {
	GetAddress() string
	GetHTTPClient() *http.Client

	// PrepareURL takes a URL that may have substitution parameters in it and returns a URL with those parameters filled in.
	// E.g. /v1/{genesisID}/gossip -> /v1/1234/gossip
	PrepareURL(string) string
}

// UnicastPeer is another possible interface for the opaque Peer.
// It is possible that we can only initiate a connection to a peer over websockets.
type UnicastPeer interface {
	GetAddress() string
	// Unicast sends the given bytes to this specific peer. Does not wait for message to be sent.
	Unicast(ctx context.Context, data []byte, tag protocol.Tag) error
}

// GetAddress returns the root url to use to connect to this peer.
// TODO: should GetAddress be added to Peer interface?
func (wp *wsPeerCore) GetAddress() string {
	return wp.rootURL
}

// GetHTTPClient returns a client for this peer.
// http.Client will maintain a cache of connections with some keepalive.
func (wp *wsPeerCore) GetHTTPClient() *http.Client {
	return &wp.client
}

// PrepareURL substitutes placeholders like "{genesisID}" for their values.
func (wp *wsPeerCore) PrepareURL(rawURL string) string {
	return strings.Replace(rawURL, "{genesisID}", wp.net.GenesisID, -1)
}

// 	Unicast sends the given bytes to this specific peer. Does not wait for message to be sent.
// (Implements UnicastPeer)
func (wp *wsPeer) Unicast(ctx context.Context, msg []byte, tag protocol.Tag) error {
	var err error

	tbytes := []byte(tag)
	mbytes := make([]byte, len(tbytes)+len(msg))
	copy(mbytes, tbytes)
	copy(mbytes[len(tbytes):], msg)
	var digest crypto.Digest
	if tag != protocol.MsgSkipTag && len(msg) >= messageFilterSize {
		digest = crypto.Hash(mbytes)
	}

	ok := wp.writeNonBlock(mbytes, false, digest, time.Now())
	if !ok {
		networkBroadcastsDropped.Inc(nil)
		err = fmt.Errorf("wsPeer failed to unicast: %v", wp.GetAddress())
	}

	return err
}

// setup values not trivially assigned
func (wp *wsPeer) init(config config.Local, sendBufferLength int) {
	wp.net.log.Debugf("wsPeer init outgoing=%v %#v", wp.outgoing, wp.rootURL)
	wp.closing = make(chan struct{})
	wp.sendBufferHighPrio = make(chan sendMessage, sendBufferLength)
	wp.sendBufferBulk = make(chan sendMessage, sendBufferLength)
	atomic.StoreInt64(&wp.lastPacketTime, time.Now().UnixNano())

	// processed is a channel that messageHandlerThread writes to
	// when it's done with one of our messages, so that we can queue
	// another one onto wp.net.readBuffer.  Prime it with dummy
	// values so that we can write to readBuffer initially.
	wp.processed = make(chan struct{}, msgsInReadBufferPerPeer)
	for i := 0; i < msgsInReadBufferPerPeer; i++ {
		wp.processed <- struct{}{}
	}

	if config.EnableOutgoingNetworkMessageFiltering {
		wp.outgoingMsgFilter = makeMessageFilter(config.OutgoingMessageFilterBucketCount, config.OutgoingMessageFilterBucketSize)
	}

	wp.wg.Add(2)
	go wp.readLoop()
	go wp.writeLoop()
}

// returns the originating address of an incoming connection. For outgoing connection this function returns an empty string.
func (wp *wsPeer) OriginAddress() string {
	return wp.originAddress
}

func (wp *wsPeer) reportReadErr(err error) {
	// only report error if we haven't already closed the peer
	if atomic.LoadInt32(&wp.didInnerClose) == 0 {
		_, _, line, _ := runtime.Caller(1)
		wp.net.log.Warnf("peer[%s] line=%d read err: %s", wp.conn.RemoteAddr().String(), line, err)
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "reader err"})
	}
}

func dedupSafeTag(t protocol.Tag) bool {
	// Votes and Transactions are the only thing we're sure it's safe to de-dup on receipt.
	return t == protocol.AgreementVoteTag || t == protocol.TxnTag
}

func (wp *wsPeer) readLoop() {
	defer wp.readLoopCleanup()
	wp.conn.SetReadLimit(maxMessageLength)
	slurper := LimitedReaderSlurper{Limit: maxMessageLength}
	for {
		msg := IncomingMessage{}
		mtype, reader, err := wp.conn.NextReader()
		if err != nil {
			if ce, ok := err.(*websocket.CloseError); ok {
				switch ce.Code {
				case websocket.CloseNormalClosure, websocket.CloseGoingAway:
					// deliberate close, no error
					return
				default:
					// fall through to reportReadErr
				}
			}
			wp.reportReadErr(err)
			return
		}
		if mtype != websocket.BinaryMessage {
			wp.net.log.Errorf("peer sent non websocket-binary message: %#v", mtype)
			networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "protocol"})
			return
		}
		var tag [2]byte
		_, err = io.ReadFull(reader, tag[:])
		if err != nil {
			wp.reportReadErr(err)
			return
		}
		msg.Tag = Tag(string(tag[:]))
		slurper.Reset()
		err = slurper.Read(reader)
		if err != nil {
			wp.reportReadErr(err)
			return
		}
		msg.processing = wp.processed
		msg.Received = time.Now().UnixNano()
		msg.Data = slurper.Bytes()
		msg.Net = wp.net
		atomic.StoreInt64(&wp.lastPacketTime, msg.Received)
		networkReceivedBytesTotal.AddUint64(uint64(len(msg.Data)+2), nil)
		networkMessageReceivedTotal.AddUint64(1, nil)
		msg.Sender = wp
		if msg.Tag == protocol.MsgSkipTag {
			// network maintenance message handled immediately instead of handing off to general handlers
			wp.handleFilterMessage(msg)
			continue
		}
		if len(msg.Data) > 0 && wp.incomingMsgFilter != nil && dedupSafeTag(msg.Tag) {
			if wp.incomingMsgFilter.CheckIncomingMessage(msg.Tag, msg.Data, true, true) {
				//wp.net.log.Debugf("dropped incoming duplicate %s(%d)", msg.Tag, len(msg.Data))
				duplicateNetworkMessageReceivedTotal.Inc(nil)
				duplicateNetworkMessageReceivedBytesTotal.AddUint64(uint64(len(msg.Data)+len(msg.Tag)), nil)
				// drop message, skip adding it to queue
				continue
			}
		}
		//wp.net.log.Debugf("got msg %d bytes from %s", len(msg.Data), wp.conn.RemoteAddr().String())

		// Wait for a previous message from this peer to be processed,
		// to achieve fairness in wp.net.readBuffer.
		select {
		case <-wp.processed:
		case <-wp.closing:
			wp.net.log.Debugf("peer closing %s", wp.conn.RemoteAddr().String())
			return
		}

		select {
		case wp.net.readBuffer <- msg:
		case <-wp.closing:
			wp.net.log.Debugf("peer closing %s", wp.conn.RemoteAddr().String())
			return
		}
	}
}

func (wp *wsPeer) readLoopCleanup() {
	wp.internalClose(disconnectReadError)
	wp.wg.Done()
}

// a peer is telling us not to send messages with some hash
func (wp *wsPeer) handleFilterMessage(msg IncomingMessage) {
	if wp.outgoingMsgFilter == nil {
		return
	}
	if len(msg.Data) != crypto.DigestSize {
		wp.net.log.Warnf("bad filter message size %d", len(msg.Data))
		return
	}
	var digest crypto.Digest
	copy(digest[:], msg.Data)
	//wp.net.log.Debugf("add filter %v", digest)
	wp.outgoingMsgFilter.CheckDigest(digest, true, true)
}

func (wp *wsPeer) writeLoopSend(msg sendMessage) (exit bool) {
	if len(msg.data) > maxMessageLength {
		wp.net.log.Errorf("trying to send a message longer than we would recieve: %d > %d tag=%#v", len(msg.data), maxMessageLength, string(msg.data[0:2]))
		// just drop it, don't break the connection
		return false
	}
	// check if this message was waiting in the queue for too long. If this is the case, return "true" to indicate that we want to close the connection.
	msgWaitDuration := time.Now().Sub(msg.enqueued)
	if msgWaitDuration > maxMessageQueueDuration {
		wp.net.log.Warnf("peer stale enqueued message %dms", msgWaitDuration.Nanoseconds()/1000000)
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "stale message"})
		return true
	}
	atomic.StoreInt64(&wp.intermittentOutgoingMessageEnqueueTime, msg.enqueued.UnixNano())
	defer atomic.StoreInt64(&wp.intermittentOutgoingMessageEnqueueTime, 0)
	err := wp.conn.WriteMessage(websocket.BinaryMessage, msg.data)
	if err != nil {
		if atomic.LoadInt32(&wp.didInnerClose) == 0 {
			wp.net.log.Warn("peer write error ", err)
			networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "write err"})
		}
		return true
	}
	atomic.StoreInt64(&wp.lastPacketTime, time.Now().UnixNano())
	networkSentBytesTotal.AddUint64(uint64(len(msg.data)), nil)
	networkMessageSentTotal.AddUint64(1, nil)
	networkMessageQueueMicrosTotal.AddUint64(uint64(time.Now().Sub(msg.peerEnqueued).Nanoseconds()/1000), nil)
	return false
}

func (wp *wsPeer) writeLoop() {
	defer wp.writeLoopCleanup()
	for {
		// send from high prio channel as long as we can
		select {
		case data := <-wp.sendBufferHighPrio:
			if wp.writeLoopSend(data) {
				return
			}
			continue
		default:
		}
		// if nothing high prio, send anything
		select {
		case <-wp.closing:
			return
		case data := <-wp.sendBufferHighPrio:
			if wp.writeLoopSend(data) {
				return
			}
		case data := <-wp.sendBufferBulk:
			if wp.writeLoopSend(data) {
				return
			}
		}
	}
}
func (wp *wsPeer) writeLoopCleanup() {
	wp.internalClose(disconnectWriteError)
	wp.wg.Done()
}

// return true if enqueued/sent
func (wp *wsPeer) writeNonBlock(data []byte, highPrio bool, digest crypto.Digest, msgEnqueueTime time.Time) bool {
	if wp.outgoingMsgFilter != nil && len(data) > messageFilterSize && wp.outgoingMsgFilter.CheckDigest(digest, false, false) {
		//wp.net.log.Debugf("msg drop as outbound dup %s(%d) %v", string(data[:2]), len(data)-2, digest)
		// peer has notified us it doesn't need this message
		outgoingNetworkMessageFilteredOutTotal.Inc(nil)
		outgoingNetworkMessageFilteredOutBytesTotal.AddUint64(uint64(len(data)), nil)
		// returning true because it is as good as sent, the peer already has it.
		return true
	}
	var outchan chan sendMessage
	if highPrio {
		outchan = wp.sendBufferHighPrio
	} else {
		outchan = wp.sendBufferBulk
	}
	select {
	case outchan <- sendMessage{data: data, enqueued: msgEnqueueTime, peerEnqueued: time.Now()}:
		return true
	default:
	}
	return false
}

const pingLength = 8
const maxPingWait = 60 * time.Second

// sendPing sends a ping block to the peer.
// return true if either a ping request was enqueued or there is already ping request in flight in the past maxPingWait time.
func (wp *wsPeer) sendPing() bool {
	wp.pingLock.Lock()
	defer wp.pingLock.Unlock()
	now := time.Now()
	if wp.pingInFlight && (now.Sub(wp.pingSent) < maxPingWait) {
		return true
	}

	tagBytes := []byte(protocol.PingTag)
	mbytes := make([]byte, len(tagBytes)+pingLength)
	copy(mbytes, tagBytes)
	rand.Read(mbytes[len(tagBytes):])
	wp.pingData = mbytes[len(tagBytes):]
	sent := wp.writeNonBlock(mbytes, false, crypto.Digest{}, time.Now())

	if sent {
		wp.pingInFlight = true
		wp.pingSent = now
	}
	return sent
}

// get some times out of the peer while observing the ping data lock
func (wp *wsPeer) pingTimes() (lastPingSent time.Time, lastPingRoundTripTime time.Duration) {
	wp.pingLock.Lock()
	defer wp.pingLock.Unlock()
	lastPingSent = wp.pingSent
	lastPingRoundTripTime = wp.lastPingRoundTripTime
	return
}

// called when the connection had an error or closed remotely
func (wp *wsPeer) internalClose(reason disconnectReason) {
	if atomic.CompareAndSwapInt32(&wp.didSignalClose, 0, 1) {
		wp.net.peerRemoteClose(wp, reason)
	}
	wp.Close()
}

// called either here or from above enclosing node logic
func (wp *wsPeer) Close() {
	atomic.StoreInt32(&wp.didSignalClose, 1)
	if atomic.CompareAndSwapInt32(&wp.didInnerClose, 0, 1) {
		close(wp.closing)
		wp.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(5*time.Second))
		wp.conn.CloseWithoutFlush()
	}
}

// CloseAndWait internally calls Close() then waits for all peer activity to stop
func (wp *wsPeer) CloseAndWait() {
	wp.Close()
	wp.wg.Wait()
}

func (wp *wsPeer) GetLastPacketTime() int64 {
	return atomic.LoadInt64(&wp.lastPacketTime)
}

func (wp *wsPeer) CheckSlowWritingPeer(now time.Time) bool {
	ongoingMessageTime := atomic.LoadInt64(&wp.intermittentOutgoingMessageEnqueueTime)
	if ongoingMessageTime == 0 {
		return false
	}
	timeSinceMessageCreated := now.Sub(time.Unix(0, ongoingMessageTime))
	return timeSinceMessageCreated > maxMessageQueueDuration
}
