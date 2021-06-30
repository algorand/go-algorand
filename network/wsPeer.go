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

package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
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
const averageMessageLength = 2 * 1024    // Most of the messages are smaller than this size, which makes it into a good base allocation.

// This parameter controls how many messages from a single peer can be
// queued up in the global wsNetwork.readBuffer at a time.  Making this
// too large will allow a small number of peers to flood the global read
// buffer and starve messages from other peers.
const msgsInReadBufferPerPeer = 10

var networkSentBytesTotal = metrics.MakeCounter(metrics.NetworkSentBytesTotal)
var networkSentBytesByTag = metrics.NewTagCounter("algod_network_sent_bytes_{TAG}", "Number of bytes that were sent over the network per message tag")
var networkReceivedBytesTotal = metrics.MakeCounter(metrics.NetworkReceivedBytesTotal)
var networkReceivedBytesByTag = metrics.NewTagCounter("algod_network_received_bytes_{TAG}", "Number of bytes that were received from the network per message tag")

var networkMessageReceivedTotal = metrics.MakeCounter(metrics.NetworkMessageReceivedTotal)
var networkMessageReceivedByTag = metrics.NewTagCounter("algod_network_message_received_{TAG}", "Number of complete messages that were received from the network per message tag")
var networkMessageSentTotal = metrics.MakeCounter(metrics.NetworkMessageSentTotal)
var networkMessageSentByTag = metrics.NewTagCounter("algod_network_message_sent_{TAG}", "Number of complete messages that were sent to the network per message tag")

var networkConnectionsDroppedTotal = metrics.MakeCounter(metrics.NetworkConnectionsDroppedTotal)
var networkMessageQueueMicrosTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_message_sent_queue_micros_total", Description: "Total microseconds message spent waiting in queue to be sent"})

var duplicateNetworkMessageReceivedTotal = metrics.MakeCounter(metrics.DuplicateNetworkMessageReceivedTotal)
var duplicateNetworkMessageReceivedBytesTotal = metrics.MakeCounter(metrics.DuplicateNetworkMessageReceivedBytesTotal)
var outgoingNetworkMessageFilteredOutTotal = metrics.MakeCounter(metrics.OutgoingNetworkMessageFilteredOutTotal)
var outgoingNetworkMessageFilteredOutBytesTotal = metrics.MakeCounter(metrics.OutgoingNetworkMessageFilteredOutBytesTotal)

// defaultSendMessageTags is the default list of messages which a peer would
// allow to be sent without receiving any explicit request.
var defaultSendMessageTags = map[protocol.Tag]bool{
	protocol.AgreementVoteTag:   true,
	protocol.MsgDigestSkipTag:   true,
	protocol.NetPrioResponseTag: true,
	protocol.PingTag:            true,
	protocol.PingReplyTag:       true,
	protocol.ProposalPayloadTag: true,
	protocol.TopicMsgRespTag:    true,
	protocol.MsgOfInterestTag:   true,
	protocol.UniCatchupReqTag:   true,
	protocol.UniEnsBlockReqTag:  true,
	protocol.VoteBundleTag:      true,
	protocol.Txn2Tag:            true,
}

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
	enqueued     time.Time                            // the time at which the message was first generated
	peerEnqueued time.Time                            // the time at which the peer was attempting to enqueue the message
	msgTags      map[protocol.Tag]bool                // when msgTags is speficied ( i.e. non-nil ), the send goroutine is to replace the message tag filter with this one. No data would be accompanied to this message.
	callback     UnicastWebsocketMessageStateCallback // when non-nil, the callback function would be called after entry would be placed on the outgoing websocket queue
	ctx          context.Context
}

// wsPeerCore also works for non-connected peers we want to do HTTP GET from
type wsPeerCore struct {
	net           *WebsocketNetwork
	rootURL       string
	originAddress string // incoming connection remote host
	client        http.Client
}

type disconnectReason string

const disconnectReasonNone disconnectReason = ""
const disconnectBadData disconnectReason = "BadData"
const disconnectTooSlow disconnectReason = "TooSlow"
const disconnectReadError disconnectReason = "ReadError"
const disconnectWriteError disconnectReason = "WriteError"
const disconnectIdleConn disconnectReason = "IdleConnection"
const disconnectSlowConn disconnectReason = "SlowConnection"
const disconnectLeastPerformingPeer disconnectReason = "LeastPerformingPeer"
const disconnectCliqueResolve disconnectReason = "CliqueResolving"
const disconnectRequestReceived disconnectReason = "DisconnectRequest"
const disconnectStaleWrite disconnectReason = "DisconnectStaleWrite"

// Response is the structure holding the response from the server
type Response struct {
	Topics Topics
}

type sendMessages struct {
	msgs []sendMessage
}

type wsPeer struct {
	// lastPacketTime contains the UnixNano at the last time a successful communication was made with the peer.
	// "successful communication" above refers to either reading from or writing to a connection without receiving any
	// error.
	// we want this to be a 64-bit aligned for atomics.
	lastPacketTime int64

	// intermittentOutgoingMessageEnqueueTime contains the UnixNano of the message's enqueue time that is currently being written to the
	// peer, or zero if no message is being written.
	intermittentOutgoingMessageEnqueueTime int64

	// Nonce used to uniquely identify requests
	requestNonce uint64

	wsPeerCore

	// conn will be *websocket.Conn (except in testing)
	conn wsPeerWebsocketConn

	// we started this connection; otherwise it was inbound
	outgoing bool

	closing chan struct{}

	sendBufferHighPrio chan sendMessages
	sendBufferBulk     chan sendMessages

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

	// peer version ( this is one of the version supported by the current node and listed in SupportedProtocolVersions )
	version string

	// responseChannels used by the client to wait on the response of the request
	responseChannels map[uint64]chan *Response

	// responseChannelsMutex guards the operations of responseChannels
	responseChannelsMutex deadlock.RWMutex

	// sendMessageTag is a map of allowed message to send to a peer. We don't use any synchronization on this map, and the
	// only gurentee is that it's being accessed only during startup and/or by the sending loop go routine.
	sendMessageTag map[protocol.Tag]bool

	// connMonitor used to measure the relative performance of the connection
	// compared to the other outgoing connections. Incoming connections would have this
	// field set to nil.
	connMonitor *connectionPerformanceMonitor

	// peerMessageDelay is calculated by the connection monitor; it's the relative avarage per-message delay.
	peerMessageDelay int64

	// throttledOutgoingConnection determines if this outgoing connection will be throttled bassed on it's
	// performance or not. Throttled connections are more likely to be short-lived connections.
	throttledOutgoingConnection bool

	// clientDataStore is a generic key/value store used to store client-side data entries associated with a particular peer.
	// Locked by clientDataStoreMu.
	clientDataStore map[string]interface{}

	// clientDataStoreMu synchronizes access to clientDataStore
	clientDataStoreMu deadlock.Mutex

	// outgoingMessageCounters counts the number of messages send for each tag. It allows us to use implicit message counting.
	outgoingMessageCounters map[protocol.Tag]uint64
}

// HTTPPeer is what the opaque Peer might be.
// If you get an opaque Peer handle from a GossipNode, maybe try a .(HTTPPeer) type assertion on it.
type HTTPPeer interface {
	GetAddress() string
	GetHTTPClient() *http.Client
}

// UnicastWebsocketMessageStateCallback provide asyncrounious feedback for the sequence number of a message
type UnicastWebsocketMessageStateCallback func(enqueued bool, sequenceNumber uint64)

// UnicastPeer is another possible interface for the opaque Peer.
// It is possible that we can only initiate a connection to a peer over websockets.
type UnicastPeer interface {
	GetAddress() string
	// Unicast sends the given bytes to this specific peer. Does not wait for message to be sent.
	Unicast(ctx context.Context, data []byte, tag protocol.Tag, callback UnicastWebsocketMessageStateCallback) error
	// Version returns the matching version from network.SupportedProtocolVersions
	Version() string
	Request(ctx context.Context, tag Tag, topics Topics) (resp *Response, e error)
	Respond(ctx context.Context, reqMsg IncomingMessage, topics Topics) (e error)
	IsOutgoing() bool
}

// Create a wsPeerCore object
func makePeerCore(net *WebsocketNetwork, rootURL string, roundTripper http.RoundTripper, originAddress string) wsPeerCore {
	return wsPeerCore{
		net:           net,
		rootURL:       rootURL,
		originAddress: originAddress,
		client:        http.Client{Transport: roundTripper},
	}
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

// Version returns the matching version from network.SupportedProtocolVersions
func (wp *wsPeer) Version() string {
	return wp.version
}

// IsOutgoing returns true if the connection is an outgoing connection or false if it the connection
// is an incoming connection.
func (wp *wsPeer) IsOutgoing() bool {
	return wp.outgoing
}

// 	Unicast sends the given bytes to this specific peer. Does not wait for message to be sent.
// (Implements UnicastPeer)
func (wp *wsPeer) Unicast(ctx context.Context, msg []byte, tag protocol.Tag, callback UnicastWebsocketMessageStateCallback) error {
	var err error

	tbytes := []byte(tag)
	mbytes := make([]byte, len(tbytes)+len(msg))
	copy(mbytes, tbytes)
	copy(mbytes[len(tbytes):], msg)
	var digest crypto.Digest
	if tag != protocol.MsgDigestSkipTag && len(msg) >= messageFilterSize {
		digest = crypto.Hash(mbytes)
	}

	ok := wp.writeNonBlock(ctx, mbytes, false, digest, time.Now(), callback)
	if !ok {
		networkBroadcastsDropped.Inc(nil)
		err = fmt.Errorf("wsPeer failed to unicast: %v", wp.GetAddress())
	}

	return err
}

// Respond sends the response of a request message
func (wp *wsPeer) Respond(ctx context.Context, reqMsg IncomingMessage, responseTopics Topics) (e error) {

	// Get the hash/key of the request message
	requestHash := hashTopics(reqMsg.Data)

	// Add the request hash
	requestHashData := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(requestHashData, requestHash)
	responseTopics = append(responseTopics, Topic{key: requestHashKey, data: requestHashData})

	// Serialize the topics
	serializedMsg := responseTopics.MarshallTopics()

	// Send serializedMsg
	msg := make([]sendMessage, 1, 1)
	msg[0] = sendMessage{
		data:         append([]byte(protocol.TopicMsgRespTag), serializedMsg...),
		enqueued:     time.Now(),
		peerEnqueued: time.Now(),
		ctx:          context.Background(),
	}

	select {
	case wp.sendBufferBulk <- sendMessages{msgs: msg}:
	case <-wp.closing:
		wp.net.log.Debugf("peer closing %s", wp.conn.RemoteAddr().String())
		return
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// setup values not trivially assigned
func (wp *wsPeer) init(config config.Local, sendBufferLength int) {
	wp.net.log.Debugf("wsPeer init outgoing=%v %#v", wp.outgoing, wp.rootURL)
	wp.closing = make(chan struct{})
	wp.sendBufferHighPrio = make(chan sendMessages, sendBufferLength)
	wp.sendBufferBulk = make(chan sendMessages, sendBufferLength)
	atomic.StoreInt64(&wp.lastPacketTime, time.Now().UnixNano())
	wp.responseChannels = make(map[uint64]chan *Response)
	wp.sendMessageTag = defaultSendMessageTags
	wp.clientDataStore = make(map[string]interface{})
	wp.outgoingMessageCounters = make(map[protocol.Tag]uint64)

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

	// if we're on an older version, then add the old style transaction message to the send messages tag.
	// once we deprecate old style transaction sending, this part can go away.
	if wp.version != "2.5" {
		txSendMsgTags := make(map[protocol.Tag]bool)
		for tag := range wp.sendMessageTag {
			txSendMsgTags[tag] = true
		}
		txSendMsgTags[protocol.TxnTag] = true
		wp.sendMessageTag = txSendMsgTags
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
	// the cleanupCloseError sets the default error to disconnectReadError; depending on the exit reason, the error might get changed.
	cleanupCloseError := disconnectReadError
	defer func() {
		wp.readLoopCleanup(cleanupCloseError)
	}()
	wp.conn.SetReadLimit(maxMessageLength)
	slurper := MakeLimitedReaderSlurper(averageMessageLength, maxMessageLength)
	sequenceCounters := make(map[protocol.Tag]uint64)
	for {
		msg := IncomingMessage{}
		mtype, reader, err := wp.conn.NextReader()
		if err != nil {
			if ce, ok := err.(*websocket.CloseError); ok {
				switch ce.Code {
				case websocket.CloseNormalClosure, websocket.CloseGoingAway:
					// deliberate close, no error
					cleanupCloseError = disconnectRequestReceived
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
		networkReceivedBytesByTag.Add(string(tag[:]), uint64(len(msg.Data)+2))
		networkMessageReceivedByTag.Add(string(tag[:]), 1)
		msg.Sender = wp
		msg.Sequence = sequenceCounters[msg.Tag]
		sequenceCounters[msg.Tag] = msg.Sequence + 1

		// for outgoing connections, we want to notify the connection monitor that we've received
		// a message. The connection monitor would update it's statistics accordingly.
		if wp.connMonitor != nil {
			wp.connMonitor.Notify(&msg)
		}

		switch msg.Tag {
		case protocol.MsgOfInterestTag:
			// try to decode the message-of-interest
			if wp.handleMessageOfInterest(msg) {
				return
			}
			continue
		case protocol.TopicMsgRespTag: // Handle Topic message
			topics, err := UnmarshallTopics(msg.Data)
			if err != nil {
				wp.net.log.Warnf("wsPeer readLoop: could not read the message from: %s %s", wp.conn.RemoteAddr().String(), err)
				continue
			}
			requestHash, found := topics.GetValue(requestHashKey)
			if !found {
				wp.net.log.Warnf("wsPeer readLoop: message from %s is missing the %s", wp.conn.RemoteAddr().String(), requestHashKey)
				continue
			}
			hashKey, _ := binary.Uvarint(requestHash)
			channel, found := wp.getAndRemoveResponseChannel(hashKey)
			if !found {
				wp.net.log.Warnf("wsPeer readLoop: received a message response from %s for a stale request", wp.conn.RemoteAddr().String())
				continue
			}

			select {
			case channel <- &Response{Topics: topics}:
				// do nothing. writing was successful.
			default:
				wp.net.log.Warnf("wsPeer readLoop: channel blocked. Could not pass the response to the requester", wp.conn.RemoteAddr().String())
			}
			continue
		case protocol.MsgDigestSkipTag:
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

func (wp *wsPeer) handleMessageOfInterest(msg IncomingMessage) (shutdown bool) {
	shutdown = false
	// decode the message, and ensure it's a valid message.
	msgTagsMap, err := unmarshallMessageOfInterest(msg.Data)
	if err != nil {
		wp.net.log.Warnf("wsPeer handleMessageOfInterest: could not unmarshall message from: %s %v", wp.conn.RemoteAddr().String(), err)
		return
	}
	msgs := make([]sendMessage, 1, 1)
	msgs[0] = sendMessage{
		data:         nil,
		enqueued:     time.Now(),
		peerEnqueued: time.Now(),
		msgTags:      msgTagsMap,
		ctx:          context.Background(),
	}
	sm := sendMessages{msgs: msgs}

	// try to send the message to the send loop. The send loop will store the message locally and would use it.
	// the rationale here is that this message is rarely sent, and we would benefit from having it being lock-free.
	select {
	case wp.sendBufferHighPrio <- sm:
		return
	case <-wp.closing:
		wp.net.log.Debugf("peer closing %s", wp.conn.RemoteAddr().String())
		shutdown = true
	default:
	}

	select {
	case wp.sendBufferHighPrio <- sm:
	case wp.sendBufferBulk <- sm:
	case <-wp.closing:
		wp.net.log.Debugf("peer closing %s", wp.conn.RemoteAddr().String())
		shutdown = true
	}
	return
}

func (wp *wsPeer) readLoopCleanup(reason disconnectReason) {
	wp.internalClose(reason)
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

func (wp *wsPeer) writeLoopSend(msgs sendMessages) disconnectReason {
	for _, msg := range msgs.msgs {
		select {
		case <-msg.ctx.Done():
			//logging.Base().Infof("cancelled large send, msg %v out of %v", i, len(msgs.msgs))
			return disconnectReasonNone
		default:
		}

		if err := wp.writeLoopSendMsg(msg); err != disconnectReasonNone {
			return err
		}
	}

	return disconnectReasonNone
}

func (wp *wsPeer) writeLoopSendMsg(msg sendMessage) disconnectReason {
	if len(msg.data) > maxMessageLength {
		wp.net.log.Errorf("trying to send a message longer than we would receive: %d > %d tag=%s", len(msg.data), maxMessageLength, string(msg.data[0:2]))
		// just drop it, don't break the connection
		if msg.callback != nil {
			// let the callback know that the message was not sent.
			msg.callback(false, 0)
		}
		return disconnectReasonNone
	}
	if msg.msgTags != nil {
		// when msg.msgTags is non-nil, the read loop has received a message-of-interest message that we want to apply.
		// in order to avoid any locking, it sent it to this queue so that we could set it as the new outgoing message tag filter.
		wp.sendMessageTag = msg.msgTags
		return disconnectReasonNone
	}
	// the tags are always 2 char long; note that this is safe since it's only being used for messages that we have generated locally.
	tag := protocol.Tag(msg.data[:2])
	if !wp.sendMessageTag[tag] {
		// the peer isn't interested in this message.
		if msg.callback != nil {
			// let the callback know that the message was not sent.
			msg.callback(false, 0)
		}
		return disconnectReasonNone
	}

	// check if this message was waiting in the queue for too long. If this is the case, return "true" to indicate that we want to close the connection.
	msgWaitDuration := time.Now().Sub(msg.enqueued)
	if msgWaitDuration > maxMessageQueueDuration {
		wp.net.log.Warnf("peer stale enqueued message %dms", msgWaitDuration.Nanoseconds()/1000000)
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "stale message"})
		if msg.callback != nil {
			// let the callback know that the message was not sent.
			msg.callback(false, 0)
		}
		return disconnectStaleWrite
	}
	atomic.StoreInt64(&wp.intermittentOutgoingMessageEnqueueTime, msg.enqueued.UnixNano())
	defer atomic.StoreInt64(&wp.intermittentOutgoingMessageEnqueueTime, 0)
	err := wp.conn.WriteMessage(websocket.BinaryMessage, msg.data)
	if err != nil {
		if atomic.LoadInt32(&wp.didInnerClose) == 0 {
			wp.net.log.Warn("peer write error ", err)
			networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "write err"})
		}
		if msg.callback != nil {
			// let the callback know that the message was not sent.
			msg.callback(false, 0)
		}
		return disconnectWriteError
	}
	atomic.StoreInt64(&wp.lastPacketTime, time.Now().UnixNano())
	networkSentBytesTotal.AddUint64(uint64(len(msg.data)), nil)
	networkSentBytesByTag.Add(string(tag), uint64(len(msg.data)))
	networkMessageSentTotal.AddUint64(1, nil)
	networkMessageSentByTag.Add(string(tag), 1)
	networkMessageQueueMicrosTotal.AddUint64(uint64(time.Now().Sub(msg.peerEnqueued).Nanoseconds()/1000), nil)

	if msg.callback != nil {
		// for performance reasons, we count messages only for messages that request a callback. we might want to revisit this
		// in the future.
		seq := wp.outgoingMessageCounters[tag]
		msg.callback(true, seq)
		wp.outgoingMessageCounters[tag] = seq + 1
	}
	return disconnectReasonNone
}

func (wp *wsPeer) writeLoop() {
	// the cleanupCloseError sets the default error to disconnectWriteError; depending on the exit reason, the error might get changed.
	cleanupCloseError := disconnectWriteError
	defer func() {
		wp.writeLoopCleanup(cleanupCloseError)
	}()
	for {
		// send from high prio channel as long as we can
		select {
		case data := <-wp.sendBufferHighPrio:
			if writeErr := wp.writeLoopSend(data); writeErr != disconnectReasonNone {
				cleanupCloseError = writeErr
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
			if writeErr := wp.writeLoopSend(data); writeErr != disconnectReasonNone {
				cleanupCloseError = writeErr
				return
			}
		case data := <-wp.sendBufferBulk:
			if writeErr := wp.writeLoopSend(data); writeErr != disconnectReasonNone {
				cleanupCloseError = writeErr
				return
			}
		}
	}
}
func (wp *wsPeer) writeLoopCleanup(reason disconnectReason) {
	wp.internalClose(reason)
	wp.wg.Done()
}

func (wp *wsPeer) writeNonBlock(ctx context.Context, data []byte, highPrio bool, digest crypto.Digest, msgEnqueueTime time.Time, callback UnicastWebsocketMessageStateCallback) bool {
	msgs := make([][]byte, 1, 1)
	digests := make([]crypto.Digest, 1, 1)
	msgs[0] = data
	digests[0] = digest
	return wp.writeNonBlockMsgs(ctx, msgs, highPrio, digests, msgEnqueueTime, callback)
}

// return true if enqueued/sent
func (wp *wsPeer) writeNonBlockMsgs(ctx context.Context, data [][]byte, highPrio bool, digest []crypto.Digest, msgEnqueueTime time.Time, callback UnicastWebsocketMessageStateCallback) bool {
	includeIndices := make([]int, 0, len(data))
	for i := range data {
		if wp.outgoingMsgFilter != nil && len(data[i]) > messageFilterSize && wp.outgoingMsgFilter.CheckDigest(digest[i], false, false) {
			//wp.net.log.Debugf("msg drop as outbound dup %s(%d) %v", string(data[:2]), len(data)-2, digest)
			// peer has notified us it doesn't need this message
			outgoingNetworkMessageFilteredOutTotal.Inc(nil)
			outgoingNetworkMessageFilteredOutBytesTotal.AddUint64(uint64(len(data)), nil)
		} else {
			includeIndices = append(includeIndices, i)
		}
	}
	if len(includeIndices) == 0 {
		// returning true because it is as good as sent, the peer already has it.
		return true
	}

	var outchan chan sendMessages

	msgs := make([]sendMessage, 0, len(includeIndices))
	enqueueTime := time.Now()
	for _, index := range includeIndices {
		msgs = append(msgs, sendMessage{data: data[index], enqueued: msgEnqueueTime, peerEnqueued: enqueueTime, ctx: ctx, callback: callback})
	}

	if highPrio {
		outchan = wp.sendBufferHighPrio
	} else {
		outchan = wp.sendBufferBulk
	}
	select {
	case outchan <- sendMessages{msgs: msgs}:
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
	crypto.RandBytes(mbytes[len(tagBytes):])
	wp.pingData = mbytes[len(tagBytes):]
	sent := wp.writeNonBlock(context.Background(), mbytes, false, crypto.Digest{}, time.Now(), nil) // todo : we might want to use the callback function to figure a more percise sending time.

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
		err := wp.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(5*time.Second))
		if err != nil {
			wp.net.log.Infof("failed to write CloseMessage to connection for %s", wp.conn.RemoteAddr().String())
		}
		err = wp.conn.CloseWithoutFlush()
		if err != nil {
			wp.net.log.Infof("failed to CloseWithoutFlush to connection for %s", wp.conn.RemoteAddr().String())
		}
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

// getRequestNonce returns the byte representation of ever increasing uint64
// The value is stored on wsPeer
func (wp *wsPeer) getRequestNonce() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, atomic.AddUint64(&wp.requestNonce, 1))
	return buf
}

// Request submits the request to the server, waits for a response
func (wp *wsPeer) Request(ctx context.Context, tag Tag, topics Topics) (resp *Response, e error) {

	// Add nonce as a topic
	nonce := wp.getRequestNonce()
	topics = append(topics, Topic{key: "nonce", data: nonce})

	// serialize the topics
	serializedMsg := topics.MarshallTopics()

	// Get the topics' hash
	hash := hashTopics(serializedMsg)

	// Make a response channel to wait on the server response
	responseChannel := wp.makeResponseChannel(hash)
	defer wp.getAndRemoveResponseChannel(hash)

	// Send serializedMsg
	msg := make([]sendMessage, 1, 1)
	msg[0] = sendMessage{
		data:         append([]byte(tag), serializedMsg...),
		enqueued:     time.Now(),
		peerEnqueued: time.Now(),
		ctx:          context.Background()}
	select {
	case wp.sendBufferBulk <- sendMessages{msgs: msg}:
	case <-wp.closing:
		e = fmt.Errorf("peer closing %s", wp.conn.RemoteAddr().String())
		return
	case <-ctx.Done():
		return resp, ctx.Err()
	}

	// wait for the channel.
	select {
	case resp = <-responseChannel:
		return resp, nil
	case <-wp.closing:
		e = fmt.Errorf("peer closing %s", wp.conn.RemoteAddr().String())
		return
	case <-ctx.Done():
		return resp, ctx.Err()
	}
}

func (wp *wsPeer) makeResponseChannel(key uint64) (responseChannel chan *Response) {
	newChan := make(chan *Response, 1)
	wp.responseChannelsMutex.Lock()
	defer wp.responseChannelsMutex.Unlock()
	wp.responseChannels[key] = newChan
	return newChan
}

// getAndRemoveResponseChannel returns the channel and deletes the channel from the map
func (wp *wsPeer) getAndRemoveResponseChannel(key uint64) (respChan chan *Response, found bool) {
	wp.responseChannelsMutex.Lock()
	defer wp.responseChannelsMutex.Unlock()
	respChan, found = wp.responseChannels[key]
	delete(wp.responseChannels, key)
	return
}

func (wp *wsPeer) getPeerData(key string) interface{} {
	wp.clientDataStoreMu.Lock()
	defer wp.clientDataStoreMu.Unlock()
	return wp.clientDataStore[key]
}

func (wp *wsPeer) setPeerData(key string, value interface{}) {
	wp.clientDataStoreMu.Lock()
	defer wp.clientDataStoreMu.Unlock()
	if value == nil {
		delete(wp.clientDataStore, key)
	} else {
		wp.clientDataStore[key] = value
	}
}
