// Copyright (C) 2019-2023 Algorand, Inc.
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/algorand/websocket"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/metrics"
)

// MaxMessageLength is the maximum length of a message that can be sent or received, exported to be used in the node.TestMaxSizesCorrect test
const MaxMessageLength = 6 * 1024 * 1024 // Currently the biggest message is VB vote bundles.
const averageMessageLength = 2 * 1024    // Most of the messages are smaller than this size, which makes it into a good base allocation.

// This parameter controls how many messages from a single peer can be
// queued up in the global wsNetwork.readBuffer at a time.  Making this
// too large will allow a small number of peers to flood the global read
// buffer and starve messages from other peers.
const msgsInReadBufferPerPeer = 10

var tagStringList []string

func init() {
	tagStringList = make([]string, len(protocol.TagList))
	for i, t := range protocol.TagList {
		tagStringList[i] = string(t)
	}
	networkSentBytesByTag = metrics.NewTagCounterFiltered("algod_network_sent_bytes_{TAG}", "Number of bytes that were sent over the network for {TAG} messages", tagStringList, "UNK")
	networkReceivedBytesByTag = metrics.NewTagCounterFiltered("algod_network_received_bytes_{TAG}", "Number of bytes that were received from the network for {TAG} messages", tagStringList, "UNK")
	networkMessageReceivedByTag = metrics.NewTagCounterFiltered("algod_network_message_received_{TAG}", "Number of complete messages that were received from the network for {TAG} messages", tagStringList, "UNK")
	networkMessageSentByTag = metrics.NewTagCounterFiltered("algod_network_message_sent_{TAG}", "Number of complete messages that were sent to the network for {TAG} messages", tagStringList, "UNK")

	matched := false
	for _, version := range SupportedProtocolVersions {
		if version == versionPeerFeatures {
			matched = true
		}
	}
	if !matched {
		panic(fmt.Sprintf("peer features version %s is not supported %v", versionPeerFeatures, SupportedProtocolVersions))
	}

	var err error
	versionPeerFeaturesNum[0], versionPeerFeaturesNum[1], err = versionToMajorMinor(versionPeerFeatures)
	if err != nil {
		panic(fmt.Sprintf("failed to parse version %v: %s", versionPeerFeatures, err.Error()))
	}
}

var networkSentBytesTotal = metrics.MakeCounter(metrics.NetworkSentBytesTotal)
var networkSentBytesByTag *metrics.TagCounter
var networkReceivedBytesTotal = metrics.MakeCounter(metrics.NetworkReceivedBytesTotal)
var networkReceivedBytesByTag *metrics.TagCounter

var networkMessageReceivedTotal = metrics.MakeCounter(metrics.NetworkMessageReceivedTotal)
var networkMessageReceivedByTag *metrics.TagCounter
var networkMessageSentTotal = metrics.MakeCounter(metrics.NetworkMessageSentTotal)
var networkMessageSentByTag *metrics.TagCounter

var networkConnectionsDroppedTotal = metrics.MakeCounter(metrics.NetworkConnectionsDroppedTotal)
var networkMessageQueueMicrosTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_message_sent_queue_micros_total", Description: "Total microseconds message spent waiting in queue to be sent"})

var duplicateNetworkMessageReceivedTotal = metrics.MakeCounter(metrics.DuplicateNetworkMessageReceivedTotal)
var duplicateNetworkMessageReceivedBytesTotal = metrics.MakeCounter(metrics.DuplicateNetworkMessageReceivedBytesTotal)
var duplicateNetworkFilterReceivedTotal = metrics.MakeCounter(metrics.DuplicateNetworkFilterReceivedTotal)
var outgoingNetworkMessageFilteredOutTotal = metrics.MakeCounter(metrics.OutgoingNetworkMessageFilteredOutTotal)
var outgoingNetworkMessageFilteredOutBytesTotal = metrics.MakeCounter(metrics.OutgoingNetworkMessageFilteredOutBytesTotal)
var unknownProtocolTagMessagesTotal = metrics.MakeCounter(metrics.UnknownProtocolTagMessagesTotal)

// defaultSendMessageTags is the default list of messages which a peer would
// allow to be sent without receiving any explicit request.
var defaultSendMessageTags = map[protocol.Tag]bool{
	protocol.AgreementVoteTag:     true,
	protocol.MsgDigestSkipTag:     true,
	protocol.NetPrioResponseTag:   true,
	protocol.NetIDVerificationTag: true,
	protocol.PingTag:              true,
	protocol.PingReplyTag:         true,
	protocol.ProposalPayloadTag:   true,
	protocol.TopicMsgRespTag:      true,
	protocol.MsgOfInterestTag:     true,
	protocol.TxnTag:               true,
	protocol.UniEnsBlockReqTag:    true,
	protocol.VoteBundleTag:        true,
}

// interface allows substituting debug implementation for *websocket.Conn
type wsPeerWebsocketConn interface {
	RemoteAddr() net.Addr
	RemoteAddrString() string
	NextReader() (int, io.Reader, error)
	WriteMessage(int, []byte) error
	CloseWithMessage([]byte, time.Time) error
	SetReadLimit(int64)
	CloseWithoutFlush() error
	wrappedConn
}

type wsPeerWebsocketConnImpl struct {
	*websocket.Conn
}

func (c wsPeerWebsocketConnImpl) RemoteAddrString() string {
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}

func (c wsPeerWebsocketConnImpl) CloseWithMessage(msg []byte, deadline time.Time) error {
	return c.WriteControl(websocket.CloseMessage, msg, deadline)
}

type wrappedConn interface {
	UnderlyingConn() net.Conn
}

type sendMessage struct {
	data         []byte
	enqueued     time.Time             // the time at which the message was first generated
	peerEnqueued time.Time             // the time at which the peer was attempting to enqueue the message
	msgTags      map[protocol.Tag]bool // when msgTags is specified ( i.e. non-nil ), the send goroutine is to replace the message tag filter with this one. No data would be accompanied to this message.
	hash         crypto.Digest
	ctx          context.Context
}

// wsPeerCore also works for non-connected peers we want to do HTTP GET from
type wsPeerCore struct {
	net           GossipNode
	netCtx        context.Context
	log           logging.Logger
	readBuffer    chan<- IncomingMessage
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
const disconnectDuplicateConnection disconnectReason = "DuplicateConnection"
const disconnectBadIdentityData disconnectReason = "BadIdentityData"
const disconnectUnexpectedTopicResp disconnectReason = "UnexpectedTopicResp"

// Response is the structure holding the response from the server
type Response struct {
	Topics Topics
}

type sendMessages struct {
	msgs []sendMessage

	// onRelease function is called when the message is released either by being sent or discarded.
	onRelease func()
}

type wsPeer struct {
	// lastPacketTime contains the UnixNano at the last time a successful communication was made with the peer.
	// "successful communication" above refers to either reading from or writing to a connection without receiving any
	// error.
	lastPacketTime atomic.Int64

	// outstandingTopicRequests is an atomic counter for the number of outstanding block requests we've made out to this peer
	// if a peer sends more blocks than we've requested, we'll disconnect from it.
	outstandingTopicRequests atomic.Int64

	// intermittentOutgoingMessageEnqueueTime contains the UnixNano of the message's enqueue time that is currently being written to the
	// peer, or zero if no message is being written.
	intermittentOutgoingMessageEnqueueTime atomic.Int64

	// Nonce used to uniquely identify requests
	requestNonce atomic.Uint64

	// duplicateFilterCount counts how many times the remote peer has sent us a message hash
	// to filter that it had already sent before.
	duplicateFilterCount atomic.Uint64

	txMessageCount, miMessageCount, ppMessageCount, avMessageCount, unkMessageCount atomic.Uint64

	wsPeerCore

	// conn will be *websocket.Conn (except in testing)
	conn wsPeerWebsocketConn

	// we started this connection; otherwise it was inbound
	outgoing bool

	closing chan struct{}

	sendBufferHighPrio chan sendMessages
	sendBufferBulk     chan sendMessages

	wg sync.WaitGroup

	didSignalClose atomic.Int32
	didInnerClose  atomic.Int32

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

	// the peer's identity key which it uses for identityChallenge exchanges
	identity         crypto.PublicKey
	identityVerified atomic.Uint32
	// the identityChallenge is recorded to the peer so it may verify its identity at a later time
	identityChallenge identityChallengeValue

	// Challenge sent to the peer on an incoming connection
	prioChallenge string

	prioAddress basics.Address
	prioWeight  uint64

	// createTime is the time at which the connection was established with the peer.
	createTime time.Time

	// peer version ( this is one of the version supported by the current node and listed in SupportedProtocolVersions )
	version string

	// peer features derived from the peer version
	features peerFeatureFlag

	// responseChannels used by the client to wait on the response of the request
	responseChannels map[uint64]chan *Response

	// responseChannelsMutex guards the operations of responseChannels
	responseChannelsMutex deadlock.RWMutex

	// sendMessageTag is a map of allowed message to send to a peer. We don't use any synchronization on this map, and the
	// only guarantee is that it's being accessed only during startup and/or by the sending loop go routine.
	sendMessageTag map[protocol.Tag]bool

	// messagesOfInterestGeneration is this node's messagesOfInterest version that we have seen to this peer.
	messagesOfInterestGeneration atomic.Uint32

	// connMonitor used to measure the relative performance of the connection
	// compared to the other outgoing connections. Incoming connections would have this
	// field set to nil.
	connMonitor *connectionPerformanceMonitor

	// peerMessageDelay is calculated by the connection monitor; it's the relative average per-message delay.
	peerMessageDelay int64

	// throttledOutgoingConnection determines if this outgoing connection will be throttled based on it's
	// performance or not. Throttled connections are more likely to be short-lived connections.
	throttledOutgoingConnection bool

	// clientDataStore is a generic key/value store used to store client-side data entries associated with a particular peer.
	// Locked by clientDataStoreMu.
	clientDataStore map[string]interface{}

	// clientDataStoreMu synchronizes access to clientDataStore
	clientDataStoreMu deadlock.Mutex

	// closers is a slice of functions to run when the peer is closed
	closers []func()
}

// HTTPPeer is what the opaque Peer might be.
// If you get an opaque Peer handle from a GossipNode, maybe try a .(HTTPPeer) type assertion on it.
type HTTPPeer interface {
	GetAddress() string
	GetHTTPClient() *http.Client
}

// IPAddressable is addressable with either IPv4 or IPv6 address
type IPAddressable interface {
	IPAddr() []byte
	RoutingAddr() []byte
}

// UnicastPeer is another possible interface for the opaque Peer.
// It is possible that we can only initiate a connection to a peer over websockets.
type UnicastPeer interface {
	GetAddress() string
	// Unicast sends the given bytes to this specific peer. Does not wait for message to be sent.
	Unicast(ctx context.Context, data []byte, tag protocol.Tag) error
	// Version returns the matching version from network.SupportedProtocolVersions
	Version() string
	Request(ctx context.Context, tag Tag, topics Topics) (resp *Response, e error)
	Respond(ctx context.Context, reqMsg IncomingMessage, outMsg OutgoingMessage) (e error)
}

// TCPInfoUnicastPeer exposes information about the underlying connection if available on the platform
type TCPInfoUnicastPeer interface {
	UnicastPeer
	GetUnderlyingConnTCPInfo() (*util.TCPInfo, error)
}

// Create a wsPeerCore object
func makePeerCore(ctx context.Context, net GossipNode, log logging.Logger, readBuffer chan<- IncomingMessage, rootURL string, roundTripper http.RoundTripper, originAddress string) wsPeerCore {
	return wsPeerCore{
		net:           net,
		netCtx:        ctx,
		log:           log,
		readBuffer:    readBuffer,
		rootURL:       rootURL,
		originAddress: originAddress,
		client:        http.Client{Transport: roundTripper},
	}
}

// GetAddress returns the root url to use to connect to this peer.
// This implements HTTPPeer interface and used by external services to determine where to connect to.
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

func (wp *wsPeer) IPAddr() []byte {
	remote := wp.conn.RemoteAddr()
	if remote == nil {
		return nil
	}
	ip := remote.(*net.TCPAddr).IP
	result := ip.To4()
	if result == nil {
		result = ip.To16()
	}
	return result
}

// RoutingAddr returns meaningful routing part of the address:
// ipv4 for ipv4 addresses
// top 8 bytes of ipv6 for ipv6 addresses
// low 4 bytes for ipv4 embedded into ipv6
// see http://www.tcpipguide.com/free/t_IPv6IPv4AddressEmbedding.htm for details.
func (wp *wsPeer) RoutingAddr() []byte {
	isZeros := func(ip []byte) bool {
		for i := 0; i < len(ip); i++ {
			if ip[i] != 0 {
				return false
			}
		}
		return true
	}

	var ip []byte
	// originAddress is set for incoming connections
	// and optionally includes reverse proxy support.
	// see RequestTracker.getForwardedConnectionAddress for details.
	if wp.wsPeerCore.originAddress != "" {
		ip = net.ParseIP(wp.wsPeerCore.originAddress)
	} else {
		ip = wp.IPAddr()
	}

	if len(ip) != net.IPv6len {
		return ip
	}
	// ipv6, check if it's ipv4 embedded
	if isZeros(ip[0:10]) {
		return ip[12:16]
	}
	return ip[0:8]
}

// Unicast sends the given bytes to this specific peer. Does not wait for message to be sent.
// (Implements UnicastPeer)
func (wp *wsPeer) Unicast(ctx context.Context, msg []byte, tag protocol.Tag) error {
	var err error

	tbytes := []byte(tag)
	mbytes := make([]byte, len(tbytes)+len(msg))
	copy(mbytes, tbytes)
	copy(mbytes[len(tbytes):], msg)
	var digest crypto.Digest
	if tag != protocol.MsgDigestSkipTag && len(msg) >= messageFilterSize {
		digest = crypto.Hash(mbytes)
	}

	ok := wp.writeNonBlock(ctx, mbytes, false, digest, time.Now())
	if !ok {
		networkBroadcastsDropped.Inc(nil)
		err = fmt.Errorf("wsPeer failed to unicast: %v", wp.GetAddress())
	}

	return err
}

// GetUnderlyingConnTCPInfo unwraps the connection and returns statistics about it on supported underlying implementations
//
// (Implements TCPInfoUnicastPeer)
func (wp *wsPeer) GetUnderlyingConnTCPInfo() (*util.TCPInfo, error) {
	// unwrap websocket.Conn, requestTrackedConnection, rejectingLimitListenerConn
	var uconn net.Conn = wp.conn.UnderlyingConn()
	for i := 0; i < 10; i++ {
		wconn, ok := uconn.(wrappedConn)
		if !ok {
			break
		}
		uconn = wconn.UnderlyingConn()
	}
	return util.GetConnTCPInfo(uconn)
}

// Respond sends the response of a request message
func (wp *wsPeer) Respond(ctx context.Context, reqMsg IncomingMessage, outMsg OutgoingMessage) (e error) {

	// Get the hash/key of the request message
	requestHash := hashTopics(reqMsg.Data)

	// Add the request hash
	requestHashData := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(requestHashData, requestHash)
	responseTopics := append(outMsg.Topics, Topic{key: requestHashKey, data: requestHashData})

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
	case wp.sendBufferBulk <- sendMessages{msgs: msg, onRelease: outMsg.OnRelease}:
	case <-wp.closing:
		if outMsg.OnRelease != nil {
			outMsg.OnRelease()
		}
		wp.log.Debugf("peer closing %s", wp.conn.RemoteAddrString())
		return
	case <-ctx.Done():
		if outMsg.OnRelease != nil {
			outMsg.OnRelease()
		}
		return ctx.Err()
	}
	return nil
}

// setup values not trivially assigned
func (wp *wsPeer) init(config config.Local, sendBufferLength int) {
	wp.log.Debugf("wsPeer init outgoing=%v %#v", wp.outgoing, wp.rootURL)
	wp.closing = make(chan struct{})
	wp.sendBufferHighPrio = make(chan sendMessages, sendBufferLength)
	wp.sendBufferBulk = make(chan sendMessages, sendBufferLength)
	wp.lastPacketTime.Store(time.Now().UnixNano())
	wp.responseChannels = make(map[uint64]chan *Response)
	wp.sendMessageTag = defaultSendMessageTags
	wp.clientDataStore = make(map[string]interface{})

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
	if wp.didInnerClose.Load() == 0 {
		_, _, line, _ := runtime.Caller(1)
		wp.log.Warnf("peer[%s] line=%d read err: %s", wp.conn.RemoteAddrString(), line, err)
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
	wp.conn.SetReadLimit(MaxMessageLength)
	slurper := MakeLimitedReaderSlurper(averageMessageLength, MaxMessageLength)
	dataConverter := makeWsPeerMsgDataConverter(wp)

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
			wp.log.Errorf("peer sent non websocket-binary message: %#v", mtype)
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

		// Skip the message if it's a response to a request we didn't make or has timed out
		if msg.Tag == protocol.TopicMsgRespTag && wp.lenResponseChannels() == 0 {
			wp.outstandingTopicRequests.Add(-1)

			// This peers has sent us more responses than we have requested.  This is a protocol violation and we should disconnect.
			if wp.outstandingTopicRequests.Load() < 0 {
				wp.log.Errorf("wsPeer readloop: peer %s sent TS response without a request", wp.conn.RemoteAddrString())
				networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "unrequestedTS"})
				cleanupCloseError = disconnectUnexpectedTopicResp
				return
			}
			var n int64
			// Peer sent us a response to a request we made but we've already timed out -- discard
			n, err = io.Copy(io.Discard, reader)
			if err != nil {
				wp.log.Infof("wsPeer readloop: could not discard timed-out TS message from %s : %s", wp.conn.RemoteAddrString(), err)
				wp.reportReadErr(err)
				return
			}
			wp.log.Warnf("wsPeer readLoop: received a TS response for a stale request from %s. %d bytes discarded", wp.conn.RemoteAddrString(), n)
			continue
		}

		slurper.Reset(uint64(msg.Tag.MaxMessageSize()))
		err = slurper.Read(reader)
		if err != nil {
			wp.reportReadErr(err)
			return
		}

		msg.processing = wp.processed
		msg.Received = time.Now().UnixNano()
		msg.Data = slurper.Bytes()
		msg.Data, err = dataConverter.convert(msg.Tag, msg.Data)
		if err != nil {
			wp.reportReadErr(err)
			return
		}
		msg.Net = wp.net
		wp.lastPacketTime.Store(msg.Received)
		networkReceivedBytesTotal.AddUint64(uint64(len(msg.Data)+2), nil)
		networkMessageReceivedTotal.AddUint64(1, nil)
		networkReceivedBytesByTag.Add(string(tag[:]), uint64(len(msg.Data)+2))
		networkMessageReceivedByTag.Add(string(tag[:]), 1)
		msg.Sender = wp

		// for outgoing connections, we want to notify the connection monitor that we've received
		// a message. The connection monitor would update it's statistics accordingly.
		if wp.connMonitor != nil {
			wp.connMonitor.Notify(&msg)
		}

		switch msg.Tag {
		case protocol.MsgOfInterestTag:
			// try to decode the message-of-interest
			wp.miMessageCount.Add(1)
			if close, reason := wp.handleMessageOfInterest(msg); close {
				cleanupCloseError = reason
				if reason == disconnectBadData {
					networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "protocol"})
				}
				return
			}
			continue
		case protocol.TopicMsgRespTag: // Handle Topic message
			wp.outstandingTopicRequests.Add(-1)
			topics, err := UnmarshallTopics(msg.Data)
			if err != nil {
				wp.log.Warnf("wsPeer readLoop: could not read the message from: %s %s", wp.conn.RemoteAddrString(), err)
				continue
			}
			requestHash, found := topics.GetValue(requestHashKey)
			if !found {
				wp.log.Warnf("wsPeer readLoop: message from %s is missing the %s", wp.conn.RemoteAddrString(), requestHashKey)
				continue
			}
			hashKey, _ := binary.Uvarint(requestHash)
			channel, found := wp.getAndRemoveResponseChannel(hashKey)
			if !found {
				wp.log.Warnf("wsPeer readLoop: received a message response from %s for a stale request", wp.conn.RemoteAddrString())
				continue
			}

			select {
			case channel <- &Response{Topics: topics}:
				// do nothing. writing was successful.
			default:
				wp.log.Warn("wsPeer readLoop: channel blocked. Could not pass the response to the requester", wp.conn.RemoteAddrString())
			}
			continue
		case protocol.MsgDigestSkipTag:
			// network maintenance message handled immediately instead of handing off to general handlers
			wp.handleFilterMessage(msg)
			continue
		case protocol.TxnTag:
			wp.txMessageCount.Add(1)
		case protocol.AgreementVoteTag:
			wp.avMessageCount.Add(1)
		case protocol.ProposalPayloadTag:
			wp.ppMessageCount.Add(1)
		// the remaining valid tags: no special handling here
		case protocol.NetPrioResponseTag, protocol.PingTag, protocol.PingReplyTag,
			protocol.StateProofSigTag, protocol.UniEnsBlockReqTag, protocol.VoteBundleTag, protocol.NetIDVerificationTag:
		default: // unrecognized tag
			unknownProtocolTagMessagesTotal.Inc(nil)
			wp.unkMessageCount.Add(1)
			continue // drop message, skip adding it to queue
			// TODO: should disconnect here?
		}
		if len(msg.Data) > 0 && wp.incomingMsgFilter != nil && dedupSafeTag(msg.Tag) {
			if wp.incomingMsgFilter.CheckIncomingMessage(msg.Tag, msg.Data, true, true) {
				//wp.log.Debugf("dropped incoming duplicate %s(%d)", msg.Tag, len(msg.Data))
				duplicateNetworkMessageReceivedTotal.Inc(nil)
				duplicateNetworkMessageReceivedBytesTotal.AddUint64(uint64(len(msg.Data)+len(msg.Tag)), nil)
				// drop message, skip adding it to queue
				continue
			}
		}
		//wp.log.Debugf("got msg %d bytes from %s", len(msg.Data), wp.conn.RemoteAddrString())

		// Wait for a previous message from this peer to be processed,
		// to achieve fairness in wp.net.readBuffer.
		select {
		case <-wp.processed:
		case <-wp.closing:
			wp.log.Debugf("peer closing %s", wp.conn.RemoteAddrString())
			return
		}

		select {
		case wp.readBuffer <- msg:
		case <-wp.closing:
			wp.log.Debugf("peer closing %s", wp.conn.RemoteAddrString())
			return
		}
	}
}

func (wp *wsPeer) handleMessageOfInterest(msg IncomingMessage) (close bool, reason disconnectReason) {
	close = false
	reason = disconnectReasonNone
	// decode the message, and ensure it's a valid message.
	msgTagsMap, err := unmarshallMessageOfInterest(msg.Data)
	if err != nil {
		wp.log.Warnf("wsPeer handleMessageOfInterest: could not unmarshall message from: %s %v", wp.conn.RemoteAddrString(), err)
		return true, disconnectBadData
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
		wp.log.Debugf("peer closing %s", wp.conn.RemoteAddrString())
		return true, disconnectReasonNone
	default:
	}

	select {
	case wp.sendBufferHighPrio <- sm:
	case wp.sendBufferBulk <- sm:
	case <-wp.closing:
		wp.log.Debugf("peer closing %s", wp.conn.RemoteAddrString())
		return true, disconnectReasonNone
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
		wp.log.Warnf("bad filter message size %d", len(msg.Data))
		return
	}
	var digest crypto.Digest
	copy(digest[:], msg.Data)
	//wp.log.Debugf("add filter %v", digest)
	has := wp.outgoingMsgFilter.CheckDigest(digest, true, true)
	if has {
		// Count that this peer has sent us duplicate filter messages: this means it received the same
		// large message concurrently from several peers, and then sent the filter message to us after
		// each large message finished transferring.
		duplicateNetworkFilterReceivedTotal.Inc(nil)
		wp.duplicateFilterCount.Add(1)
	}
}

func (wp *wsPeer) writeLoopSend(msgs sendMessages) disconnectReason {
	if msgs.onRelease != nil {
		defer msgs.onRelease()
	}
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
	if len(msg.data) > MaxMessageLength {
		wp.log.Errorf("trying to send a message longer than we would receive: %d > %d tag=%s", len(msg.data), MaxMessageLength, string(msg.data[0:2]))
		// just drop it, don't break the connection
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
		return disconnectReasonNone
	}

	// check if this message was waiting in the queue for too long. If this is the case, return "true" to indicate that we want to close the connection.
	now := time.Now()
	msgWaitDuration := now.Sub(msg.enqueued)
	if msgWaitDuration > maxMessageQueueDuration {
		wp.log.Warnf("peer stale enqueued message %dms", msgWaitDuration.Nanoseconds()/1000000)
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "stale message"})
		return disconnectStaleWrite
	}

	wp.intermittentOutgoingMessageEnqueueTime.Store(msg.enqueued.UnixNano())
	defer wp.intermittentOutgoingMessageEnqueueTime.Store(0)
	err := wp.conn.WriteMessage(websocket.BinaryMessage, msg.data)
	if err != nil {
		if wp.didInnerClose.Load() == 0 {
			wp.log.Warn("peer write error ", err)
			networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "write err"})
		}
		return disconnectWriteError
	}
	wp.lastPacketTime.Store(time.Now().UnixNano())
	networkSentBytesTotal.AddUint64(uint64(len(msg.data)), nil)
	networkSentBytesByTag.Add(string(tag), uint64(len(msg.data)))
	networkMessageSentTotal.AddUint64(1, nil)
	networkMessageSentByTag.Add(string(tag), 1)
	networkMessageQueueMicrosTotal.AddUint64(uint64(time.Now().Sub(msg.peerEnqueued).Nanoseconds()/1000), nil)
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

func (wp *wsPeer) writeNonBlock(ctx context.Context, data []byte, highPrio bool, digest crypto.Digest, msgEnqueueTime time.Time) bool {
	msgs := make([][]byte, 1, 1)
	digests := make([]crypto.Digest, 1, 1)
	msgs[0] = data
	digests[0] = digest
	return wp.writeNonBlockMsgs(ctx, msgs, highPrio, digests, msgEnqueueTime)
}

// return true if enqueued/sent
func (wp *wsPeer) writeNonBlockMsgs(ctx context.Context, data [][]byte, highPrio bool, digest []crypto.Digest, msgEnqueueTime time.Time) bool {
	includeIndices := make([]int, 0, len(data))
	for i := range data {
		if wp.outgoingMsgFilter != nil && len(data[i]) > messageFilterSize && wp.outgoingMsgFilter.CheckDigest(digest[i], false, false) {
			//wp.log.Debugf("msg drop as outbound dup %s(%d) %v", string(data[:2]), len(data)-2, digest)
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
		msgs = append(msgs, sendMessage{data: data[index], enqueued: msgEnqueueTime, peerEnqueued: enqueueTime, hash: digest[index], ctx: ctx})
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

// PingLength is the fixed length of ping message, exported to be used in the node.TestMaxSizesCorrect test
const PingLength = 8
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
	mbytes := make([]byte, len(tagBytes)+PingLength)
	copy(mbytes, tagBytes)
	crypto.RandBytes(mbytes[len(tagBytes):])
	wp.pingData = mbytes[len(tagBytes):]
	sent := wp.writeNonBlock(context.Background(), mbytes, false, crypto.Digest{}, time.Now())

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
	if wp.didSignalClose.CompareAndSwap(0, 1) {
		wp.net.peerRemoteClose(wp, reason)
	}
	wp.Close(time.Now().Add(peerDisconnectionAckDuration))
}

// called either here or from above enclosing node logic
func (wp *wsPeer) Close(deadline time.Time) {
	wp.didSignalClose.Store(1)
	if wp.didInnerClose.CompareAndSwap(0, 1) {
		close(wp.closing)
		err := wp.conn.CloseWithMessage(websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), deadline)
		if err != nil {
			wp.log.Infof("failed to write CloseMessage to connection for %s, err: %s", wp.conn.RemoteAddrString(), err)
		}
		err = wp.conn.CloseWithoutFlush()
		if err != nil {
			wp.log.Infof("failed to CloseWithoutFlush to connection for %s, err: %s", wp.conn.RemoteAddrString(), err)
		}
	}

	// We need to loop through all of the messages with callbacks still in the send queue and call them
	// to ensure that state of counters such as wsBlockBytesUsed is correct.
L:
	for {
		select {
		case msgs := <-wp.sendBufferBulk:
			if msgs.onRelease != nil {
				msgs.onRelease()
			}
		default:
			break L
		}

	}
	// now call all registered closers
	for _, f := range wp.closers {
		f()
	}
}

// CloseAndWait internally calls Close() then waits for all peer activity to stop
func (wp *wsPeer) CloseAndWait(deadline time.Time) {
	wp.Close(deadline)
	wp.wg.Wait()
}

func (wp *wsPeer) GetLastPacketTime() int64 {
	return wp.lastPacketTime.Load()
}

func (wp *wsPeer) CheckSlowWritingPeer(now time.Time) bool {
	ongoingMessageTime := wp.intermittentOutgoingMessageEnqueueTime.Load()
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
	binary.PutUvarint(buf, wp.requestNonce.Add(1))
	return buf
}

// MakeNonceTopic returns a topic with the nonce as the data
// exported for testing purposes
func MakeNonceTopic(nonce uint64) Topic {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, nonce)
	return Topic{key: "nonce", data: buf}
}

// Request submits the request to the server, waits for a response
func (wp *wsPeer) Request(ctx context.Context, tag Tag, topics Topics) (resp *Response, e error) {

	// Add nonce, stored on the wsPeer as the topic
	nonceTopic := MakeNonceTopic(wp.requestNonce.Add(1))
	topics = append(topics, nonceTopic)

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
		wp.outstandingTopicRequests.Add(1)
	case <-wp.closing:
		e = fmt.Errorf("peer closing %s", wp.conn.RemoteAddrString())
		return
	case <-ctx.Done():
		return resp, ctx.Err()
	}

	// wait for the channel.
	select {
	case resp = <-responseChannel:
		return resp, nil
	case <-wp.closing:
		e = fmt.Errorf("peer closing %s", wp.conn.RemoteAddrString())
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

func (wp *wsPeer) lenResponseChannels() int {
	wp.responseChannelsMutex.Lock()
	defer wp.responseChannelsMutex.Unlock()
	return len(wp.responseChannels)
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

func (wp *wsPeer) sendMessagesOfInterest(messagesOfInterestGeneration uint32, messagesOfInterestEnc []byte) {
	err := wp.Unicast(wp.netCtx, messagesOfInterestEnc, protocol.MsgOfInterestTag)
	if err != nil {
		wp.log.Errorf("ws send msgOfInterest: %v", err)
	} else {
		wp.messagesOfInterestGeneration.Store(messagesOfInterestGeneration)
	}
}

func (wp *wsPeer) pfProposalCompressionSupported() bool {
	return wp.features&pfCompressedProposal != 0
}

func (wp *wsPeer) OnClose(f func()) {
	if wp.closers == nil {
		wp.closers = []func(){}
	}
	wp.closers = append(wp.closers, f)
}

//msgp:ignore peerFeatureFlag
type peerFeatureFlag int

const pfCompressedProposal peerFeatureFlag = 1

// versionPeerFeatures defines protocol version when peer features were introduced
const versionPeerFeatures = "2.2"

// versionPeerFeaturesNum is a parsed numeric representation of versionPeerFeatures
var versionPeerFeaturesNum [2]int64

func versionToMajorMinor(version string) (int64, int64, error) {
	parts := strings.Split(version, ".")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("version %s does not have two components", version)
	}
	major, err := strconv.ParseInt(parts[0], 10, 8)
	if err != nil {
		return 0, 0, err
	}
	minor, err := strconv.ParseInt(parts[1], 10, 8)
	if err != nil {
		return 0, 0, err
	}
	return major, minor, nil
}

func decodePeerFeatures(version string, announcedFeatures string) peerFeatureFlag {
	major, minor, err := versionToMajorMinor(version)
	if err != nil {
		return 0
	}

	if major < versionPeerFeaturesNum[0] {
		return 0
	}
	if minor < versionPeerFeaturesNum[1] {
		return 0
	}

	var features peerFeatureFlag
	parts := strings.Split(announcedFeatures, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == PeerFeatureProposalCompression {
			features |= pfCompressedProposal
		}
	}
	return features
}
