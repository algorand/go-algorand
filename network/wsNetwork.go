// Copyright (C) 2019-2020 Algorand, Inc.
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
	"container/heap"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/algorand/websocket"
	"github.com/gorilla/mux"
	"golang.org/x/net/netutil"
	"golang.org/x/sys/unix"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	tools_network "github.com/algorand/go-algorand/tools/network"
	"github.com/algorand/go-algorand/tools/network/dnssec"
	"github.com/algorand/go-algorand/util/metrics"
)

const incomingThreads = 20
const broadcastThreads = 4
const messageFilterSize = 5000 // messages greater than that size may be blocked by incoming/outgoing filter

// httpServerReadHeaderTimeout is the amount of time allowed to read
// request headers. The connection's read deadline is reset
// after reading the headers and the Handler can decide what
// is considered too slow for the body.
const httpServerReadHeaderTimeout = time.Second * 10

// httpServerWriteTimeout is the maximum duration before timing out
// writes of the response. It is reset whenever a new
// request's header is read.
const httpServerWriteTimeout = time.Second * 60

// httpServerIdleTimeout is the maximum amount of time to wait for the
// next request when keep-alives are enabled. If httpServerIdleTimeout
// is zero, the value of ReadTimeout is used. If both are
// zero, ReadHeaderTimeout is used.
const httpServerIdleTimeout = time.Second * 4

// MaxHeaderBytes controls the maximum number of bytes the
// server will read parsing the request header's keys and
// values, including the request line. It does not limit the
// size of the request body.
const httpServerMaxHeaderBytes = 4096

// MaxInt is the maximum int which might be int32 or int64
const MaxInt = int((^uint(0)) >> 1)

// connectionActivityMonitorInterval is the interval at which we check
// if any of the connected peers have been idle for a long while and
// need to be disconnected.
const connectionActivityMonitorInterval = 3 * time.Minute

// maxPeerInactivityDuration is the maximum allowed duration for a
// peer to remain completly idle (i.e. no inbound or outbound communication), before
// we discard the connection.
const maxPeerInactivityDuration = 5 * time.Minute

// maxMessageQueueDuration is the maximum amount of time a message is allowed to be waiting
// in the various queues before being sent. Once that deadline has reached, sending the message
// is pointless, as it's too stale to be of any value
const maxMessageQueueDuration = 25 * time.Second

// slowWritingPeerMonitorInterval is the interval at which we peek on the connected peers to
// verify that their current outgoing message is not being blocked for too long.
const slowWritingPeerMonitorInterval = 5 * time.Second

var networkIncomingConnections = metrics.MakeGauge(metrics.NetworkIncomingConnections)
var networkOutgoingConnections = metrics.MakeGauge(metrics.NetworkOutgoingConnections)

var networkIncomingBufferMicros = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_rx_buffer_micros_total", Description: "microseconds spent by incoming messages on the receive buffer"})
var networkHandleMicros = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_rx_handle_micros_total", Description: "microseconds spent by protocol handlers in the receive thread"})

var networkBroadcasts = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_broadcasts_total", Description: "number of broadcast operations"})
var networkBroadcastQueueMicros = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_broadcast_queue_micros_total", Description: "microseconds broadcast requests sit on queue"})
var networkBroadcastSendMicros = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_broadcast_send_micros_total", Description: "microseconds spent broadcasting"})
var networkBroadcastsDropped = metrics.MakeCounter(metrics.MetricName{Name: "algod_broadcasts_dropped_total", Description: "number of broadcast messages not sent to any peer"})
var networkPeerBroadcastDropped = metrics.MakeCounter(metrics.MetricName{Name: "algod_peer_broadcast_dropped_total", Description: "number of broadcast messages not sent to some peer"})

var networkSlowPeerDrops = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_slow_drops_total", Description: "number of peers dropped for being slow to send to"})
var networkIdlePeerDrops = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_idle_drops_total", Description: "number of peers dropped due to idle connection"})
var networkBroadcastQueueFull = metrics.MakeCounter(metrics.MetricName{Name: "algod_network_broadcast_queue_full_total", Description: "number of messages that were drops due to full broadcast queue"})

var minPing = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peer_min_ping_seconds", Description: "Network round trip time to fastest peer in seconds."})
var meanPing = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peer_mean_ping_seconds", Description: "Network round trip time to average peer in seconds."})
var medianPing = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peer_median_ping_seconds", Description: "Network round trip time to median peer in seconds."})
var maxPing = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peer_max_ping_seconds", Description: "Network round trip time to slowest peer in seconds."})

var peers = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_peers", Description: "Number of active peers."})
var incomingPeers = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_incoming_peers", Description: "Number of active incoming peers."})
var outgoingPeers = metrics.MakeGauge(metrics.MetricName{Name: "algod_network_outgoing_peers", Description: "Number of active outgoing peers."})

// Peer opaque interface for referring to a neighbor in the network
type Peer interface{}

// PeerOption allows users to specify a subset of peers to query
type PeerOption int

const (
	// PeersConnectedOut specifies all peers with outgoing connections
	PeersConnectedOut PeerOption = iota
	// PeersConnectedIn specifies all peers with inbound connections
	PeersConnectedIn PeerOption = iota
	// PeersPhonebook specifies all peers in the phonebook
	PeersPhonebook PeerOption = iota
)

// GossipNode represents a node in the gossip network
type GossipNode interface {
	Address() (string, bool)
	Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error
	Relay(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error
	Disconnect(badnode Peer)
	DisconnectPeers()
	Ready() chan struct{}

	// RegisterHTTPHandler path accepts gorilla/mux path annotations
	RegisterHTTPHandler(path string, handler http.Handler)

	// RequestConnectOutgoing asks the system to actually connect to peers.
	// `replace` optionally drops existing connections before making new ones.
	// `quit` chan allows cancellation. TODO: use `context`
	RequestConnectOutgoing(replace bool, quit <-chan struct{})

	// Get a list of Peers we could potentially send a direct message to.
	GetPeers(options ...PeerOption) []Peer

	// Start threads, listen on sockets.
	Start()

	// Close sockets. Stop threads.
	Stop()

	// RegisterHandlers adds to the set of given message handlers.
	RegisterHandlers(dispatch []TaggedMessageHandler)

	// ClearHandlers deregisters all the existing message handlers.
	ClearHandlers()

	// GetRoundTripper returns a Transport that would limit the number of outgoing connections.
	GetRoundTripper() http.RoundTripper
}

// IncomingMessage represents a message arriving from some peer in our p2p network
type IncomingMessage struct {
	Sender Peer
	Tag    Tag
	Data   []byte
	Err    error
	Net    GossipNode

	// Received is time.Time.UnixNano()
	Received int64

	// processing is a channel that is used by messageHandlerThread
	// to indicate that it has started processing this message.  It
	// is used to ensure fairness across peers in terms of processing
	// messages.
	processing chan struct{}
}

// Tag is a short string (2 bytes) marking a type of message
type Tag = protocol.Tag

func highPriorityTag(tag protocol.Tag) bool {
	return tag == protocol.AgreementVoteTag || tag == protocol.ProposalPayloadTag
}

// OutgoingMessage represents a message we want to send.
type OutgoingMessage struct {
	Action  ForwardingPolicy
	Tag     Tag
	Payload []byte
	Topics  Topics
}

// ForwardingPolicy is an enum indicating to whom we should send a message
type ForwardingPolicy int

const (
	// Ignore - discard (don't forward)
	Ignore ForwardingPolicy = iota

	// Disconnect - disconnect from the peer that sent this message
	Disconnect

	// Broadcast - forward to everyone (except the sender)
	Broadcast

	// Respond - reply to the sender
	Respond
)

// MessageHandler takes a IncomingMessage (e.g., vote, transaction), processes it, and returns what (if anything)
// to send to the network in response.
// The ForwardingPolicy field of the returned OutgoingMessage indicates whether to reply directly to the sender
// (unicast), propagate to everyone except the sender (broadcast), or do nothing (ignore).
type MessageHandler interface {
	Handle(message IncomingMessage) OutgoingMessage
}

// HandlerFunc represents an implemenation of the MessageHandler interface
type HandlerFunc func(message IncomingMessage) OutgoingMessage

// Handle implements MessageHandler.Handle, calling the handler with the IncomingKessage and returning the OutgoingMessage
func (f HandlerFunc) Handle(message IncomingMessage) OutgoingMessage {
	return f(message)
}

// TaggedMessageHandler receives one type of broadcast messages
type TaggedMessageHandler struct {
	Tag
	MessageHandler
}

// Propagate is a convenience function to save typing in the common case of a message handler telling us to propagate an incoming message
// "return network.Propagate(msg)" instead of "return network.OutgoingMsg{network.Broadcast, msg.Tag, msg.Data}"
func Propagate(msg IncomingMessage) OutgoingMessage {
	return OutgoingMessage{Broadcast, msg.Tag, msg.Data, nil}
}

// GossipNetworkPath is the URL path to connect to the websocket gossip node at.
// Contains {genesisID} param to be handled by gorilla/mux
const GossipNetworkPath = "/v1/{genesisID}/gossip"

// WebsocketNetwork implements GossipNode
type WebsocketNetwork struct {
	listener net.Listener
	server   http.Server
	router   *mux.Router
	scheme   string // are we serving http or https ?

	upgrader websocket.Upgrader

	config config.Local

	log logging.Logger

	readBuffer chan IncomingMessage

	wg sync.WaitGroup

	handlers Multiplexer

	ctx       context.Context
	ctxCancel context.CancelFunc

	peersLock deadlock.RWMutex
	peers     []*wsPeer

	broadcastQueueHighPrio chan broadcastRequest
	broadcastQueueBulk     chan broadcastRequest

	phonebook *MultiPhonebook

	GenesisID string
	NetworkID protocol.NetworkID
	RandomID  string

	ready     int32
	readyChan chan struct{}

	meshUpdateRequests chan meshRequest

	// Keep a record of pending outgoing connections so
	// we don't start duplicates connection attempts.
	// Needs to be locked because it's accessed from the
	// meshThread and also threads started to run tryConnect()
	tryConnectAddrs map[string]int64
	tryConnectLock  deadlock.Mutex

	incomingMsgFilter *messageFilter // message filter to remove duplicate incoming messages from different peers

	eventualReadyDelay time.Duration

	relayMessages bool // True if we should relay messages from other nodes (nominally true for relays, false otherwise)

	prioScheme       NetPrioScheme
	prioTracker      *prioTracker
	prioResponseChan chan *wsPeer

	// outgoingMessagesBufferSize is the size used for outgoing messages.
	outgoingMessagesBufferSize int

	// slowWritingPeerMonitorInterval defines the interval between two consecutive tests for slow peer writing
	slowWritingPeerMonitorInterval time.Duration

	requestsTracker *RequestTracker
	requestsLogger  *RequestLogger

	// lastPeerConnectionsSent is the last time the peer connections were sent ( or attempted to be sent ) to the telemetry server.
	lastPeerConnectionsSent time.Time

	// transport and dialer are customized to limit the number of
	// connection in compliance with connectionsRateLimitingCount.
	transport rateLimitingTransport
	dialer    Dialer
}

type broadcastRequest struct {
	tag         Tag
	data        []byte
	except      *wsPeer
	done        chan struct{}
	enqueueTime time.Time
}

// Address returns a string and whether that is a 'final' address or guessed.
// Part of GossipNode interface
func (wn *WebsocketNetwork) Address() (string, bool) {
	parsedURL := url.URL{Scheme: wn.scheme}
	var connected bool
	if wn.listener == nil {
		parsedURL.Host = wn.config.NetAddress
		connected = false
	} else {
		parsedURL.Host = wn.listener.Addr().String()
		connected = true
	}
	return parsedURL.String(), connected
}

// PublicAddress what we tell other nodes to connect to.
// Might be different than our locally percieved network address due to NAT/etc.
// Returns config "PublicAddress" if available, otherwise local addr.
func (wn *WebsocketNetwork) PublicAddress() string {
	if len(wn.config.PublicAddress) > 0 {
		return wn.config.PublicAddress
	}
	localAddr, _ := wn.Address()
	return localAddr
}

// Broadcast sends a message.
// If except is not nil then we will not send it to that neighboring Peer.
// if wait is true then the call blocks until the packet has actually been sent to all neighbors.
// TODO: add `priority` argument so that we don't have to guess it based on tag
func (wn *WebsocketNetwork) Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error {
	request := broadcastRequest{tag: tag, data: data, enqueueTime: time.Now()}
	if except != nil {
		request.except = except.(*wsPeer)
	}

	broadcastQueue := wn.broadcastQueueBulk
	if highPriorityTag(tag) {
		broadcastQueue = wn.broadcastQueueHighPrio
	}
	if wait {
		request.done = make(chan struct{})
		select {
		case broadcastQueue <- request:
			// ok, enqueued
			//wn.log.Debugf("broadcast enqueued")
		case <-wn.ctx.Done():
			return errNetworkClosing
		case <-ctx.Done():
			return errBcastCallerCancel
		}
		select {
		case <-request.done:
			//wn.log.Debugf("broadcast done")
			return nil
		case <-wn.ctx.Done():
			return errNetworkClosing
		case <-ctx.Done():
			return errBcastCallerCancel
		}
	}
	// no wait
	select {
	case broadcastQueue <- request:
		//wn.log.Debugf("broadcast enqueued nowait")
		return nil
	default:
		wn.log.Debugf("broadcast queue full")
		// broadcastQueue full, and we're not going to wait for it.
		networkBroadcastQueueFull.Inc(nil)
		return errBcastQFull
	}
}

// Relay message
func (wn *WebsocketNetwork) Relay(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error {
	if wn.relayMessages {
		return wn.Broadcast(ctx, tag, data, wait, except)
	}
	return nil
}

func (wn *WebsocketNetwork) disconnectThread(badnode Peer, reason disconnectReason) {
	defer wn.wg.Done()
	wn.disconnect(badnode, reason)
}

// Disconnect from a peer, probably due to protocol errors.
func (wn *WebsocketNetwork) Disconnect(node Peer) {
	wn.disconnect(node, disconnectBadData)
}

// Disconnect from a peer, probably due to protocol errors.
func (wn *WebsocketNetwork) disconnect(badnode Peer, reason disconnectReason) {
	if badnode == nil {
		return
	}
	peer := badnode.(*wsPeer)
	peer.CloseAndWait()
	wn.removePeer(peer, reason)
}

func closeWaiter(wg *sync.WaitGroup, peer *wsPeer) {
	defer wg.Done()
	peer.CloseAndWait()
}

// DisconnectPeers shuts down all connections
func (wn *WebsocketNetwork) DisconnectPeers() {
	wn.peersLock.Lock()
	defer wn.peersLock.Unlock()
	closeGroup := sync.WaitGroup{}
	closeGroup.Add(len(wn.peers))
	for _, peer := range wn.peers {
		go closeWaiter(&closeGroup, peer)
	}
	wn.peers = wn.peers[:0]
	closeGroup.Wait()
}

// Ready returns a chan that will be closed when we have a minimum number of peer connections active
func (wn *WebsocketNetwork) Ready() chan struct{} {
	return wn.readyChan
}

// RegisterHTTPHandler path accepts gorilla/mux path annotations
func (wn *WebsocketNetwork) RegisterHTTPHandler(path string, handler http.Handler) {
	wn.router.Handle(path, handler)
}

// RequestConnectOutgoing tries to actually do the connect to new peers.
// `replace` drop all connections first and find new peers.
func (wn *WebsocketNetwork) RequestConnectOutgoing(replace bool, quit <-chan struct{}) {
	request := meshRequest{disconnect: false}
	if quit != nil {
		request.done = make(chan struct{})
	}
	select {
	case wn.meshUpdateRequests <- request:
	case <-quit:
		return
	}
	if request.done != nil {
		select {
		case <-request.done:
		case <-quit:
		}
	}
}

// GetPeers returns a snapshot of our Peer list, according to the specified options.
// Peers may be duplicated and refer to the same underlying node.
func (wn *WebsocketNetwork) GetPeers(options ...PeerOption) []Peer {
	outPeers := make([]Peer, 0)
	for _, option := range options {
		switch option {
		case PeersConnectedOut:
			wn.peersLock.RLock()
			for _, peer := range wn.peers {
				if peer.outgoing {
					outPeers = append(outPeers, Peer(peer))
				}
			}
			wn.peersLock.RUnlock()
		case PeersPhonebook:
			// return copy of phonebook, which probably also contains peers we're connected to, but if it doesn't maybe we shouldn't be making new connections to those peers (because they disappeared from the directory)
			var addrs []string
			addrs = wn.phonebook.GetAddresses(1000)
			for _, addr := range addrs {
				peerCore := makePeerCore(wn, addr, wn.GetRoundTripper(), "" /*origin address*/)
				outPeers = append(outPeers, &peerCore)
			}
		case PeersConnectedIn:
			wn.peersLock.RLock()
			for _, peer := range wn.peers {
				if !peer.outgoing {
					outPeers = append(outPeers, Peer(peer))
				}
			}
			wn.peersLock.RUnlock()
		}
	}
	return outPeers
}

func (wn *WebsocketNetwork) setup() {
	var preferredResolver *dnssec.Resolver
	if wn.config.DNSSecurityRelayAddrEnforced() {
		preferredResolver = &dnssec.DefaultResolver
	}
	wn.dialer = makeRateLimitingDialer(wn.phonebook, preferredResolver)
	wn.transport = makeRateLimitingTransport(wn.phonebook, 10*time.Second, &wn.dialer)

	wn.upgrader.ReadBufferSize = 4096
	wn.upgrader.WriteBufferSize = 4096
	wn.upgrader.EnableCompression = false
	wn.lastPeerConnectionsSent = time.Now()
	wn.router = mux.NewRouter()
	wn.router.Handle(GossipNetworkPath, wn)
	wn.requestsTracker = makeRequestsTracker(wn.router, wn.log, wn.config)
	if wn.config.EnableRequestLogger {
		wn.requestsLogger = makeRequestLogger(wn.requestsTracker, wn.log)
		wn.server.Handler = wn.requestsLogger
	} else {
		wn.server.Handler = wn.requestsTracker
	}
	wn.server.ReadHeaderTimeout = httpServerReadHeaderTimeout
	wn.server.WriteTimeout = httpServerWriteTimeout
	wn.server.IdleTimeout = httpServerIdleTimeout
	wn.server.MaxHeaderBytes = httpServerMaxHeaderBytes
	wn.ctx, wn.ctxCancel = context.WithCancel(context.Background())
	wn.relayMessages = wn.config.NetAddress != "" || wn.config.ForceRelayMessages
	// roughly estimate the number of messages that could be sent over the lifespan of a single round.
	wn.outgoingMessagesBufferSize = int(config.Consensus[protocol.ConsensusCurrentVersion].NumProposers*2 +
		config.Consensus[protocol.ConsensusCurrentVersion].SoftCommitteeSize +
		config.Consensus[protocol.ConsensusCurrentVersion].CertCommitteeSize +
		config.Consensus[protocol.ConsensusCurrentVersion].NextCommitteeSize +
		config.Consensus[protocol.ConsensusCurrentVersion].LateCommitteeSize +
		config.Consensus[protocol.ConsensusCurrentVersion].RedoCommitteeSize +
		config.Consensus[protocol.ConsensusCurrentVersion].DownCommitteeSize)

	wn.broadcastQueueHighPrio = make(chan broadcastRequest, wn.outgoingMessagesBufferSize)
	wn.broadcastQueueBulk = make(chan broadcastRequest, 100)
	wn.meshUpdateRequests = make(chan meshRequest, 5)
	wn.readyChan = make(chan struct{})
	wn.tryConnectAddrs = make(map[string]int64)
	wn.eventualReadyDelay = time.Minute
	wn.prioTracker = newPrioTracker(wn)
	if wn.slowWritingPeerMonitorInterval == 0 {
		wn.slowWritingPeerMonitorInterval = slowWritingPeerMonitorInterval
	}

	readBufferLen := wn.config.IncomingConnectionsLimit + wn.config.GossipFanout
	if readBufferLen < 100 {
		readBufferLen = 100
	}
	if readBufferLen > 10000 {
		readBufferLen = 10000
	}
	wn.readBuffer = make(chan IncomingMessage, readBufferLen)

	var rbytes [10]byte
	rand.Read(rbytes[:])
	wn.RandomID = base64.StdEncoding.EncodeToString(rbytes[:])

	if wn.config.EnableIncomingMessageFilter {
		wn.incomingMsgFilter = makeMessageFilter(wn.config.IncomingMessageFilterBucketCount, wn.config.IncomingMessageFilterBucketSize)
	}
	wn.handlers.log = wn.log
}

func (wn *WebsocketNetwork) rlimitIncomingConnections() error {
	var lim unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim)
	if err != nil {
		return err
	}

	// If rlim_max is not sufficient, reduce IncomingConnectionsLimit
	var rlimitMaxCap uint64
	if lim.Max < wn.config.ReservedFDs {
		rlimitMaxCap = 0
	} else {
		rlimitMaxCap = lim.Max - wn.config.ReservedFDs
	}
	if rlimitMaxCap > uint64(MaxInt) {
		rlimitMaxCap = uint64(MaxInt)
	}
	if wn.config.IncomingConnectionsLimit > int(rlimitMaxCap) {
		wn.log.Warnf("Reducing IncomingConnectionsLimit from %d to %d since RLIMIT_NOFILE is %d",
			wn.config.IncomingConnectionsLimit, rlimitMaxCap, lim.Max)
		wn.config.IncomingConnectionsLimit = int(rlimitMaxCap)
	}

	// Set rlim_cur to match IncomingConnectionsLimit
	newLimit := uint64(wn.config.IncomingConnectionsLimit) + wn.config.ReservedFDs
	if newLimit > lim.Cur {
		if runtime.GOOS == "darwin" && newLimit > 10240 && lim.Max == 0x7fffffffffffffff {
			// The max file limit is 10240, even though
			// the max returned by Getrlimit is 1<<63-1.
			// This is OPEN_MAX in sys/syslimits.h.
			// see https://github.com/golang/go/issues/30401
			newLimit = 10240
		}
		lim.Cur = newLimit
		err = unix.Setrlimit(unix.RLIMIT_NOFILE, &lim)
		if err != nil {
			return err
		}
	}

	return nil
}

// Start makes network connections and threads
func (wn *WebsocketNetwork) Start() {
	var err error
	if wn.config.IncomingConnectionsLimit < 0 {
		wn.config.IncomingConnectionsLimit = MaxInt
	}

	// Make sure we do not accept more incoming connections than our
	// open file rlimit, with some headroom for other FDs (DNS, log
	// files, SQLite files, telemetry, ...)
	err = wn.rlimitIncomingConnections()
	if err != nil {
		wn.log.Error("ws network start: rlimitIncomingConnections ", err)
		return
	}

	if wn.config.NetAddress != "" {
		listener, err := net.Listen("tcp", wn.config.NetAddress)
		if err != nil {
			wn.log.Errorf("network could not listen %v: %s", wn.config.NetAddress, err)
			return
		}
		// wrap the original listener with a limited connection listener
		listener = netutil.LimitListener(listener, wn.config.IncomingConnectionsLimit)
		// wrap the limited connection listener with a requests tracker listener
		wn.listener = wn.requestsTracker.Listener(listener)
		wn.log.Debugf("listening on %s", wn.listener.Addr().String())
	}
	if wn.config.TLSCertFile != "" && wn.config.TLSKeyFile != "" {
		wn.scheme = "https"
	} else {
		wn.scheme = "http"
	}
	wn.meshUpdateRequests <- meshRequest{false, nil}
	if wn.config.EnablePingHandler {
		wn.RegisterHandlers(pingHandlers)
	}
	if wn.prioScheme != nil {
		wn.RegisterHandlers(prioHandlers)
	}
	if wn.listener != nil {
		wn.wg.Add(1)
		go wn.httpdThread()
	}
	wn.wg.Add(1)
	go wn.meshThread()
	if wn.config.PeerPingPeriodSeconds > 0 {
		wn.wg.Add(1)
		go wn.pingThread()
	}
	for i := 0; i < incomingThreads; i++ {
		wn.wg.Add(1)
		go wn.messageHandlerThread()
	}
	for i := 0; i < broadcastThreads; i++ {
		wn.wg.Add(1)
		go wn.broadcastThread()
	}
	wn.wg.Add(1)
	go wn.prioWeightRefresh()
	wn.log.Infof("serving genesisID=%s on %#v with RandomID=%s", wn.GenesisID, wn.PublicAddress(), wn.RandomID)
}

func (wn *WebsocketNetwork) httpdThread() {
	defer wn.wg.Done()
	var err error
	if wn.config.TLSCertFile != "" && wn.config.TLSKeyFile != "" {
		err = wn.server.ServeTLS(wn.listener, wn.config.TLSCertFile, wn.config.TLSKeyFile)
	} else {
		err = wn.server.Serve(wn.listener)
	}
	if err == http.ErrServerClosed {
	} else if err != nil {
		wn.log.Info("ws net http server exited ", err)
	}
}

// innerStop context for shutting down peers
func (wn *WebsocketNetwork) innerStop() {
	wn.peersLock.Lock()
	defer wn.peersLock.Unlock()
	wn.wg.Add(len(wn.peers))
	for _, peer := range wn.peers {
		go closeWaiter(&wn.wg, peer)
	}
	wn.peers = wn.peers[:0]
}

// Stop closes network connections and stops threads.
// Stop blocks until all activity on this node is done.
func (wn *WebsocketNetwork) Stop() {
	wn.innerStop()
	var listenAddr string
	if wn.listener != nil {
		listenAddr = wn.listener.Addr().String()
	}
	wn.ctxCancel()
	ctx, timeoutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer timeoutCancel()
	err := wn.server.Shutdown(ctx)
	if err != nil {
		wn.log.Warnf("problem shutting down %s: %v", listenAddr, err)
	}
	wn.wg.Wait()
	if wn.listener != nil {
		wn.log.Debugf("closed %s", listenAddr)
	}
}

// RegisterHandlers registers the set of given message handlers.
func (wn *WebsocketNetwork) RegisterHandlers(dispatch []TaggedMessageHandler) {
	wn.handlers.RegisterHandlers(dispatch)
}

// ClearHandlers deregisters all the existing message handlers.
func (wn *WebsocketNetwork) ClearHandlers() {
	wn.handlers.ClearHandlers()
}

func (wn *WebsocketNetwork) setHeaders(header http.Header) {
	localTelemetryGUID := wn.log.GetTelemetryHostName()
	localInstanceName := wn.log.GetInstanceName()
	header.Set(TelemetryIDHeader, localTelemetryGUID)
	header.Set(InstanceNameHeader, localInstanceName)
	header.Set(AddressHeader, wn.PublicAddress())
	header.Set(NodeRandomHeader, wn.RandomID)
}

// checkServerResponseVariables check that the version and random-id in the request headers matches the server ones.
// it returns true if it's a match, and false otherwise.
func (wn *WebsocketNetwork) checkServerResponseVariables(otherHeader http.Header, addr string) (bool, string) {
	matchingVersion, otherVersion := wn.checkProtocolVersionMatch(otherHeader)
	if matchingVersion == "" {
		wn.log.Infof("new peer %s version mismatch, mine=%v theirs=%s, headers %#v", addr, SupportedProtocolVersions, otherVersion, otherHeader)
		return false, ""
	}
	otherRandom := otherHeader.Get(NodeRandomHeader)
	if otherRandom == wn.RandomID || otherRandom == "" {
		// This is pretty harmless and some configurations of phonebooks or DNS records make this likely. Quietly filter it out.
		if otherRandom == "" {
			// missing header.
			wn.log.Warnf("new peer %s did not include random ID header in request. mine=%s headers %#v", addr, wn.RandomID, otherHeader)
		} else {
			wn.log.Debugf("new peer %s has same node random id, am I talking to myself? %s", addr, wn.RandomID)
		}
		return false, ""
	}
	otherGenesisID := otherHeader.Get(GenesisHeader)
	if wn.GenesisID != otherGenesisID {
		if otherGenesisID != "" {
			wn.log.Warnf("new peer %#v genesis mismatch, mine=%#v theirs=%#v, headers %#v", addr, wn.GenesisID, otherGenesisID, otherHeader)
		} else {
			wn.log.Warnf("new peer %#v did not include genesis header in response. mine=%#v headers %#v", addr, wn.GenesisID, otherHeader)
		}
		return false, ""
	}
	return true, matchingVersion
}

// getCommonHeaders retreives the common headers for both incoming and outgoing connections from the provided headers.
func getCommonHeaders(headers http.Header) (otherTelemetryGUID, otherInstanceName, otherPublicAddr string) {
	otherTelemetryGUID = logging.SanitizeTelemetryString(headers.Get(TelemetryIDHeader), 1)
	otherInstanceName = logging.SanitizeTelemetryString(headers.Get(InstanceNameHeader), 2)
	otherPublicAddr = logging.SanitizeTelemetryString(headers.Get(AddressHeader), 1)
	return
}

// checkIncomingConnectionLimits perform the connection limits counting for the incoming connections.
func (wn *WebsocketNetwork) checkIncomingConnectionLimits(response http.ResponseWriter, request *http.Request, remoteHost, otherTelemetryGUID, otherInstanceName string) int {
	if wn.numIncomingPeers() >= wn.config.IncomingConnectionsLimit {
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "incoming_connection_limit"})
		wn.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerFailEvent,
			telemetryspec.ConnectPeerFailEventDetails{
				Address:      remoteHost,
				HostName:     otherTelemetryGUID,
				Incoming:     true,
				InstanceName: otherInstanceName,
				Reason:       "Connection Limit",
			})
		response.WriteHeader(http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}

	totalConnections := wn.connectedForIP(remoteHost)
	if totalConnections >= wn.config.MaxConnectionsPerIP {
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "incoming_connection_per_ip_limit"})
		wn.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerFailEvent,
			telemetryspec.ConnectPeerFailEventDetails{
				Address:      remoteHost,
				HostName:     otherTelemetryGUID,
				Incoming:     true,
				InstanceName: otherInstanceName,
				Reason:       "Remote IP Connection Limit",
			})
		response.WriteHeader(http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}

	return http.StatusOK
}

// checkProtocolVersionMatch test ProtocolAcceptVersionHeader and ProtocolVersionHeader headers from the request/response and see if it can find a match.
func (wn *WebsocketNetwork) checkProtocolVersionMatch(otherHeaders http.Header) (matchingVersion string, otherVersion string) {
	otherAcceptedVersions := otherHeaders[textproto.CanonicalMIMEHeaderKey(ProtocolAcceptVersionHeader)]
	for _, otherAcceptedVersion := range otherAcceptedVersions {
		// do we have a matching version ?
		for _, supportedProtocolVersion := range SupportedProtocolVersions {
			if supportedProtocolVersion == otherAcceptedVersion {
				matchingVersion = supportedProtocolVersion
				return matchingVersion, ""
			}
		}
	}

	otherVersion = otherHeaders.Get(ProtocolVersionHeader)
	for _, supportedProtocolVersion := range SupportedProtocolVersions {
		if supportedProtocolVersion == otherVersion {
			return supportedProtocolVersion, otherVersion
		}
	}
	return "", otherVersion
}

// checkIncomingConnectionVariables checks the variables that were provided on the request, and compares them to the
// local server supported parameters. If all good, it returns http.StatusOK; otherwise, it write the error to the ResponseWriter
// and returns the http status.
func (wn *WebsocketNetwork) checkIncomingConnectionVariables(response http.ResponseWriter, request *http.Request) int {
	// check to see that the genesisID in the request URI is valid and matches the supported one.
	pathVars := mux.Vars(request)
	otherGenesisID, hasGenesisID := pathVars["genesisID"]
	if !hasGenesisID || otherGenesisID == "" {
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "missing genesis-id"})
		response.WriteHeader(http.StatusNotFound)
		return http.StatusNotFound
	}

	if wn.GenesisID != otherGenesisID {
		wn.log.Warnf("new peer %#v genesis mismatch, mine=%#v theirs=%#v, headers %#v", request.RemoteAddr, wn.GenesisID, otherGenesisID, request.Header)
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "mismatching genesis-id"})
		response.WriteHeader(http.StatusPreconditionFailed)
		response.Write([]byte("mismatching genesis ID"))
		return http.StatusPreconditionFailed
	}

	otherRandom := request.Header.Get(NodeRandomHeader)
	if otherRandom == "" {
		// This is pretty harmless and some configurations of phonebooks or DNS records make this likely. Quietly filter it out.
		var message string
		// missing header.
		wn.log.Warnf("new peer %s did not include random ID header in request. mine=%s headers %#v", request.RemoteAddr, wn.RandomID, request.Header)
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "missing random ID header"})
		message = fmt.Sprintf("Request was missing a %s header", NodeRandomHeader)
		response.WriteHeader(http.StatusPreconditionFailed)
		n, err := response.Write([]byte(message))
		if err != nil {
			wn.log.Warnf("ws failed to write response '%s' : n = %d err = %v", message, n, err)
		}
		return http.StatusPreconditionFailed
	} else if otherRandom == wn.RandomID {
		// This is pretty harmless and some configurations of phonebooks or DNS records make this likely. Quietly filter it out.
		var message string
		wn.log.Debugf("new peer %s has same node random id, am I talking to myself? %s", request.RemoteAddr, wn.RandomID)
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "matching random ID header"})
		message = fmt.Sprintf("Request included matching %s=%s header", NodeRandomHeader, otherRandom)
		response.WriteHeader(http.StatusLoopDetected)
		n, err := response.Write([]byte(message))
		if err != nil {
			wn.log.Warnf("ws failed to write response '%s' : n = %d err = %v", message, n, err)
		}
		return http.StatusLoopDetected
	}
	return http.StatusOK
}

// ServerHTTP handles the gossip network functions over websockets
func (wn *WebsocketNetwork) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	trackedRequest := wn.requestsTracker.GetTrackedRequest(request)

	if wn.checkIncomingConnectionLimits(response, request, trackedRequest.remoteHost, trackedRequest.otherTelemetryGUID, trackedRequest.otherInstanceName) != http.StatusOK {
		// we've already logged and written all response(s).
		return
	}

	matchingVersion, otherVersion := wn.checkProtocolVersionMatch(request.Header)
	if matchingVersion == "" {
		wn.log.Infof("new peer %s version mismatch, mine=%v theirs=%s, headers %#v", request.RemoteAddr, SupportedProtocolVersions, otherVersion, request.Header)
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "mismatching protocol version"})
		response.WriteHeader(http.StatusPreconditionFailed)
		message := fmt.Sprintf("Requested version %s not in %v mismatches server version", otherVersion, SupportedProtocolVersions)
		n, err := response.Write([]byte(message))
		if err != nil {
			wn.log.Warnf("ws failed to write response '%s' : n = %d err = %v", message, n, err)
		}
		return
	}

	if wn.checkIncomingConnectionVariables(response, request) != http.StatusOK {
		// we've already logged and written all response(s).
		return
	}

	// if UseXForwardedForAddressField is not empty, attempt to override the otherPublicAddr with the X Forwarded For origin
	trackedRequest.otherPublicAddr = trackedRequest.remoteAddr

	responseHeader := make(http.Header)
	wn.setHeaders(responseHeader)
	responseHeader.Set(ProtocolVersionHeader, matchingVersion)
	responseHeader.Set(GenesisHeader, wn.GenesisID)
	var challenge string
	if wn.prioScheme != nil {
		challenge = wn.prioScheme.NewPrioChallenge()
		responseHeader.Set(PriorityChallengeHeader, challenge)
	}
	conn, err := wn.upgrader.Upgrade(response, request, responseHeader)
	if err != nil {
		wn.log.Info("ws upgrade fail ", err)
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "ws upgrade fail"})
		return
	}

	// we want to tell the response object that the status was changed to 101 ( switching protocols ) so that it will be logged.
	if wn.requestsLogger != nil {
		wn.requestsLogger.SetStatusCode(response, http.StatusSwitchingProtocols)
	}

	peer := &wsPeer{
		wsPeerCore:        makePeerCore(wn, trackedRequest.otherPublicAddr, wn.GetRoundTripper(), trackedRequest.remoteHost),
		conn:              conn,
		outgoing:          false,
		InstanceName:      trackedRequest.otherInstanceName,
		incomingMsgFilter: wn.incomingMsgFilter,
		prioChallenge:     challenge,
		createTime:        trackedRequest.created,
		version:           matchingVersion,
	}
	peer.TelemetryGUID = trackedRequest.otherTelemetryGUID
	peer.init(wn.config, wn.outgoingMessagesBufferSize)
	wn.addPeer(peer)
	localAddr, _ := wn.Address()
	wn.log.With("event", "ConnectedIn").With("remote", trackedRequest.otherPublicAddr).With("local", localAddr).Infof("Accepted incoming connection from peer %s", trackedRequest.otherPublicAddr)
	wn.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerEvent,
		telemetryspec.PeerEventDetails{
			Address:      trackedRequest.remoteHost,
			HostName:     trackedRequest.otherTelemetryGUID,
			Incoming:     true,
			InstanceName: trackedRequest.otherInstanceName,
		})

	peers.Set(float64(wn.NumPeers()), nil)
	incomingPeers.Set(float64(wn.numIncomingPeers()), nil)
}

func (wn *WebsocketNetwork) messageHandlerThread() {
	defer wn.wg.Done()
	inactivityCheckTicker := time.NewTicker(connectionActivityMonitorInterval)
	defer inactivityCheckTicker.Stop()
	for {
		select {
		case <-wn.ctx.Done():
			return
		case msg := <-wn.readBuffer:
			if msg.processing != nil {
				// The channel send should never block, but just in case..
				select {
				case msg.processing <- struct{}{}:
				default:
					wn.log.Warnf("could not send on msg.processing")
				}
			}
			if wn.config.EnableOutgoingNetworkMessageFiltering && len(msg.Data) >= messageFilterSize {
				wn.sendFilterMessage(msg)
			}
			//wn.log.Debugf("msg handling %#v [%d]byte", msg.Tag, len(msg.Data))
			start := time.Now()

			// now, send to global handlers
			outmsg := wn.handlers.Handle(msg)
			handled := time.Now()
			bufferNanos := start.UnixNano() - msg.Received
			networkIncomingBufferMicros.AddUint64(uint64(bufferNanos/1000), nil)
			handleTime := handled.Sub(start)
			networkHandleMicros.AddUint64(uint64(handleTime.Nanoseconds()/1000), nil)
			switch outmsg.Action {
			case Disconnect:
				wn.wg.Add(1)
				go wn.disconnectThread(msg.Sender, disconnectBadData)
			case Broadcast:
				wn.Broadcast(wn.ctx, msg.Tag, msg.Data, false, msg.Sender)
			case Respond:
				msg.Sender.(*wsPeer).Respond(wn.ctx, msg, outmsg)
			default:
			}
		case <-inactivityCheckTicker.C:
			// go over the peers and ensure we have some type of communication going on.
			wn.checkPeersConnectivity()
		}
	}
}

// checkPeersConnectivity tests the last timestamp where each of these
// peers was communicated with, and disconnect the peer if it has been too long since
// last time.
func (wn *WebsocketNetwork) checkPeersConnectivity() {
	wn.peersLock.Lock()
	defer wn.peersLock.Unlock()
	currentTime := time.Now()
	for _, peer := range wn.peers {
		lastPacketTime := peer.GetLastPacketTime()
		timeSinceLastPacket := currentTime.Sub(time.Unix(0, lastPacketTime))
		if timeSinceLastPacket > maxPeerInactivityDuration {
			wn.wg.Add(1)
			go wn.disconnectThread(peer, disconnectIdleConn)
			networkIdlePeerDrops.Inc(nil)
		}
	}
}

// checkSlowWritingPeers tests each of the peer's current message timestamp.
// if that timestamp is too old, it means that the transmission of that message
// takes longer than desired. In that case, it will disconnect the peer, allowing it to reconnect
// to a faster network endpoint.
func (wn *WebsocketNetwork) checkSlowWritingPeers() {
	wn.peersLock.Lock()
	defer wn.peersLock.Unlock()
	currentTime := time.Now()
	for _, peer := range wn.peers {
		if peer.CheckSlowWritingPeer(currentTime) {
			wn.wg.Add(1)
			go wn.disconnectThread(peer, disconnectSlowConn)
			networkSlowPeerDrops.Inc(nil)
		}
	}
}

func (wn *WebsocketNetwork) sendFilterMessage(msg IncomingMessage) {
	digest := generateMessageDigest(msg.Tag, msg.Data)
	//wn.log.Debugf("send filter %s(%d) %v", msg.Tag, len(msg.Data), digest)
	wn.Broadcast(context.Background(), protocol.MsgDigestSkipTag, digest[:], false, msg.Sender)
}

func (wn *WebsocketNetwork) broadcastThread() {
	defer wn.wg.Done()
	var peers []*wsPeer
	slowWritingPeerCheckTicker := time.NewTicker(wn.slowWritingPeerMonitorInterval)
	defer slowWritingPeerCheckTicker.Stop()
	for {
		// broadcast from high prio channel as long as we can
		// we want to try and keep this as a single case select with a default, since go compiles a single-case
		// select with a default into a more efficient non-blocking receive, instead of compiling it to the general-purpose selectgo
		select {
		case request := <-wn.broadcastQueueHighPrio:
			wn.innerBroadcast(request, true, &peers)
			continue
		default:
		}

		// if nothing high prio, broadcast anything
		select {
		case request := <-wn.broadcastQueueHighPrio:
			wn.innerBroadcast(request, true, &peers)
		case <-slowWritingPeerCheckTicker.C:
			wn.checkSlowWritingPeers()
			continue
		case request := <-wn.broadcastQueueBulk:
			wn.innerBroadcast(request, false, &peers)
		case <-wn.ctx.Done():
			return
		}
	}
}

func (wn *WebsocketNetwork) peerSnapshot(dest []*wsPeer) []*wsPeer {
	wn.peersLock.RLock()
	defer wn.peersLock.RUnlock()
	if cap(dest) >= len(wn.peers) {
		dest = dest[:len(wn.peers)]
	} else {
		dest = make([]*wsPeer, len(wn.peers))
	}
	copy(dest, wn.peers)
	return dest
}

// prio is set if the broadcast is a high-priority broadcast.
func (wn *WebsocketNetwork) innerBroadcast(request broadcastRequest, prio bool, ppeers *[]*wsPeer) {
	if request.done != nil {
		defer close(request.done)
	}

	broadcastQueueDuration := time.Now().Sub(request.enqueueTime)
	networkBroadcastQueueMicros.AddUint64(uint64(broadcastQueueDuration.Nanoseconds()/1000), nil)
	if broadcastQueueDuration > maxMessageQueueDuration {
		networkBroadcastsDropped.Inc(nil)
		return
	}

	start := time.Now()
	tbytes := []byte(request.tag)
	mbytes := make([]byte, len(tbytes)+len(request.data))
	copy(mbytes, tbytes)
	copy(mbytes[len(tbytes):], request.data)

	var digest crypto.Digest
	if request.tag != protocol.MsgDigestSkipTag && len(request.data) >= messageFilterSize {
		digest = crypto.Hash(mbytes)
	}

	*ppeers = wn.peerSnapshot(*ppeers)
	peers := *ppeers

	// first send to all the easy outbound peers who don't block, get them started.
	sentMessageCount := 0
	for pi, peer := range peers {
		if wn.config.BroadcastConnectionsLimit >= 0 && sentMessageCount >= wn.config.BroadcastConnectionsLimit {
			break
		}
		if peer == request.except {
			peers[pi] = nil
			continue
		}
		ok := peer.writeNonBlock(mbytes, prio, digest, request.enqueueTime)
		if ok {
			peers[pi] = nil
			sentMessageCount++
			continue
		}
		networkPeerBroadcastDropped.Inc(nil)
	}

	dt := time.Now().Sub(start)
	networkBroadcasts.Inc(nil)
	networkBroadcastSendMicros.AddUint64(uint64(dt.Nanoseconds()/1000), nil)
}

// NumPeers returns number of peers we connect to (all peers incoming and outbound).
func (wn *WebsocketNetwork) NumPeers() int {
	wn.peersLock.RLock()
	defer wn.peersLock.RUnlock()
	return len(wn.peers)
}

func (wn *WebsocketNetwork) numOutgoingPeers() int {
	wn.peersLock.RLock()
	defer wn.peersLock.RUnlock()
	count := 0
	for _, peer := range wn.peers {
		if peer.outgoing {
			count++
		}
	}
	return count
}
func (wn *WebsocketNetwork) numIncomingPeers() int {
	wn.peersLock.RLock()
	defer wn.peersLock.RUnlock()
	count := 0
	for _, peer := range wn.peers {
		if !peer.outgoing {
			count++
		}
	}
	return count
}

// isConnectedTo returns true if addr matches any connected peer, based on the peer's root url.
func (wn *WebsocketNetwork) isConnectedTo(addr string) bool {
	wn.peersLock.RLock()
	defer wn.peersLock.RUnlock()
	for _, peer := range wn.peers {
		if addr == peer.rootURL {
			return true
		}
	}
	return false
}

// connectedForIP returns number of peers with same host
func (wn *WebsocketNetwork) connectedForIP(host string) (totalConnections int) {
	wn.peersLock.RLock()
	defer wn.peersLock.RUnlock()
	totalConnections = 0
	for _, peer := range wn.peers {
		if host == peer.OriginAddress() {
			totalConnections++
		}
	}
	return
}

const meshThreadInterval = time.Minute

type meshRequest struct {
	disconnect bool
	done       chan struct{}
}

func imin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// meshThread maintains the network, e.g. that we have sufficient connectivity to peers
func (wn *WebsocketNetwork) meshThread() {
	defer wn.wg.Done()
	timer := time.NewTicker(meshThreadInterval)
	defer timer.Stop()
	for {
		var request meshRequest
		select {
		case <-timer.C:
			request.disconnect = false
			request.done = nil
		case request = <-wn.meshUpdateRequests:
		case <-wn.ctx.Done():
			return
		}

		if request.disconnect {
			wn.DisconnectPeers()
		}

		// TODO: only do DNS fetch every N seconds? Honor DNS TTL? Trust DNS library we're using to handle caching and TTL?
		dnsBootstrapArray := wn.config.DNSBootstrapArray(wn.NetworkID)
		for _, dnsBootstrap := range dnsBootstrapArray {
			dnsAddrs := wn.getDNSAddrs(dnsBootstrap)
			if len(dnsAddrs) > 0 {
				wn.log.Debugf("got %d dns addrs, %#v", len(dnsAddrs), dnsAddrs[:imin(5, len(dnsAddrs))])
				dnsPhonebook := wn.phonebook.GetPhonebook(dnsBootstrap)
				if dnsPhonebook == nil {
					// create one, if we don't have one already.
					dnsPhonebook = MakeThreadsafePhonebook(wn.config.ConnectionsRateLimitingCount,
						time.Duration(wn.config.ConnectionsRateLimitingWindowSeconds)*time.Second)
					wn.phonebook.AddOrUpdatePhonebook(dnsBootstrap, dnsPhonebook)
				}
				if tsPhonebook, ok := dnsPhonebook.(*ThreadsafePhonebook); ok {
					tsPhonebook.ReplacePeerList(dnsAddrs)
				}
			} else {
				wn.log.Infof("got no DNS addrs for network %s", wn.NetworkID)
			}
		}
		desired := wn.config.GossipFanout
		numOutgoing := wn.numOutgoingPeers() + wn.numOutgoingPending()
		need := desired - numOutgoing
		if need > 0 {
			// get more than we need so that we can ignore duplicates
			newAddrs := wn.phonebook.GetAddresses(desired + numOutgoing)
			for _, na := range newAddrs {
				if na == wn.config.PublicAddress {
					continue
				}
				gossipAddr, ok := wn.tryConnectReserveAddr(na)
				if ok {
					wn.wg.Add(1)
					go wn.tryConnect(na, gossipAddr)
					need--
					if need == 0 {
						break
					}
				}
			}
		}
		if request.done != nil {
			close(request.done)
		}

		// send the currently connected peers information to the
		// telemetry server; that would allow the telemetry server
		// to construct a cross-node map of all the nodes interconnections.
		wn.sendPeerConnectionsTelemetryStatus()
	}
}

// sendPeerConnectionsTelemetryStatus sends a snapshot of the currently connected peers
// to the telemetry server. Internally, it's using a timer to ensure that it would only
// send the information once every hour ( configurable via PeerConnectionsUpdateInterval )
func (wn *WebsocketNetwork) sendPeerConnectionsTelemetryStatus() {
	now := time.Now()
	if wn.lastPeerConnectionsSent.Add(time.Duration(wn.config.PeerConnectionsUpdateInterval)*time.Second).After(now) || wn.config.PeerConnectionsUpdateInterval <= 0 {
		// it's not yet time to send the update.
		return
	}
	wn.lastPeerConnectionsSent = now
	var peers []*wsPeer
	peers = wn.peerSnapshot(peers)
	var connectionDetails telemetryspec.PeersConnectionDetails
	for _, peer := range peers {
		connDetail := telemetryspec.PeerConnectionDetails{
			ConnectionDuration: uint(now.Sub(peer.createTime).Seconds()),
			HostName:           peer.TelemetryGUID,
			InstanceName:       peer.InstanceName,
		}
		if peer.outgoing {
			connDetail.Address = justHost(peer.conn.RemoteAddr().String())
			connDetail.Endpoint = peer.GetAddress()
			connectionDetails.OutgoingPeers = append(connectionDetails.OutgoingPeers, connDetail)
		} else {
			connDetail.Address = peer.OriginAddress()
			connectionDetails.IncomingPeers = append(connectionDetails.IncomingPeers, connDetail)
		}
	}

	wn.log.EventWithDetails(telemetryspec.Network, telemetryspec.PeerConnectionsEvent, connectionDetails)
}

// prioWeightRefreshTime controls how often we refresh the weights
// of connected peers.
const prioWeightRefreshTime = time.Minute

// prioWeightRefresh periodically refreshes the weights of connected peers.
func (wn *WebsocketNetwork) prioWeightRefresh() {
	defer wn.wg.Done()
	ticker := time.NewTicker(prioWeightRefreshTime)
	defer ticker.Stop()
	var peers []*wsPeer
	for {
		select {
		case <-ticker.C:
		case <-wn.ctx.Done():
			return
		}

		peers = wn.peerSnapshot(peers)
		for _, peer := range peers {
			wn.peersLock.RLock()
			addr := peer.prioAddress
			weight := peer.prioWeight
			wn.peersLock.RUnlock()

			newWeight := wn.prioScheme.GetPrioWeight(addr)
			if newWeight != weight {
				wn.peersLock.Lock()
				wn.prioTracker.setPriority(peer, addr, newWeight)
				wn.peersLock.Unlock()
			}
		}
	}
}

// Wake up the thread to do work this often.
const pingThreadPeriod = 30 * time.Second

// If ping stats are older than this, don't include in metrics.
const maxPingAge = 30 * time.Minute

// pingThread wakes up periodically to refresh the ping times on peers and update the metrics gauges.
func (wn *WebsocketNetwork) pingThread() {
	defer wn.wg.Done()
	ticker := time.NewTicker(pingThreadPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-wn.ctx.Done():
			return
		}
		sendList := wn.peersToPing()
		wn.log.Debugf("ping %d peers...", len(sendList))
		for _, peer := range sendList {
			if !peer.sendPing() {
				// if we failed to send a ping, see how long it was since last successfull ping.
				lastPingSent, _ := peer.pingTimes()
				wn.log.Infof("failed to ping to %v for the past %f seconds", peer, time.Now().Sub(lastPingSent).Seconds())
			}
		}
	}
}

// Walks list of peers, gathers list of peers to ping, also calculates statistics.
func (wn *WebsocketNetwork) peersToPing() []*wsPeer {
	wn.peersLock.RLock()
	defer wn.peersLock.RUnlock()
	// Never flood outbound traffic by trying to ping all the peers at once.
	// Send to at most one fifth of the peers.
	maxSend := 1 + (len(wn.peers) / 5)
	out := make([]*wsPeer, 0, maxSend)
	now := time.Now()
	// a list to sort to find median
	times := make([]float64, 0, len(wn.peers))
	var min = math.MaxFloat64
	var max float64
	var sum float64
	pingPeriod := time.Duration(wn.config.PeerPingPeriodSeconds) * time.Second
	for _, peer := range wn.peers {
		lastPingSent, lastPingRoundTripTime := peer.pingTimes()
		sendToNow := now.Sub(lastPingSent)
		if (sendToNow > pingPeriod) && (len(out) < maxSend) {
			out = append(out, peer)
		}
		if (lastPingRoundTripTime > 0) && (sendToNow < maxPingAge) {
			ftime := lastPingRoundTripTime.Seconds()
			sum += ftime
			times = append(times, ftime)
			if ftime < min {
				min = ftime
			}
			if ftime > max {
				max = ftime
			}
		}
	}
	if len(times) != 0 {
		sort.Float64s(times)
		median := times[len(times)/2]
		medianPing.Set(median, nil)
		mean := sum / float64(len(times))
		meanPing.Set(mean, nil)
		minPing.Set(min, nil)
		maxPing.Set(max, nil)
		wn.log.Infof("ping times min=%f mean=%f median=%f max=%f", min, mean, median, max)
	}
	return out
}

func (wn *WebsocketNetwork) getDNSAddrs(dnsBootstrap string) []string {
	srvPhonebook, err := tools_network.ReadFromSRV("algobootstrap", "tcp", dnsBootstrap, wn.config.FallbackDNSResolverAddress, wn.config.DNSSecuritySRVEnforced())
	if err != nil {
		// only log this warning on testnet or devnet
		if wn.NetworkID == config.Devnet || wn.NetworkID == config.Testnet {
			wn.log.Warnf("Cannot lookup SRV record for %s: %v", dnsBootstrap, err)
		}
		return nil
	}
	return srvPhonebook
}

// ProtocolVersionHeader HTTP header for protocol version.
const ProtocolVersionHeader = "X-Algorand-Version"

// ProtocolAcceptVersionHeader HTTP header for accept protocol version. Client use this to advertise supported protocol versions.
const ProtocolAcceptVersionHeader = "X-Algorand-Accept-Version"

// SupportedProtocolVersions contains the list of supported protocol versions by this node ( in order of preference ).
var SupportedProtocolVersions = []string{ /*"2",*/ "1"}

// ProtocolVersion is the current version attached to the ProtocolVersionHeader header
const ProtocolVersion = "1"

// TelemetryIDHeader HTTP header for telemetry-id for logging
const TelemetryIDHeader = "X-Algorand-TelId"

// GenesisHeader HTTP header for genesis id to make sure we're on the same chain
const GenesisHeader = "X-Algorand-Genesis"

// NodeRandomHeader HTTP header that a node uses to make sure it's not talking to itself
const NodeRandomHeader = "X-Algorand-NodeRandom"

// AddressHeader HTTP header by which an inbound connection reports its public address
const AddressHeader = "X-Algorand-Location"

// InstanceNameHeader HTTP header by which an inbound connection reports an ID to distinguish multiple local nodes.
const InstanceNameHeader = "X-Algorand-InstanceName"

// PriorityChallengeHeader HTTP header informs a client about the challenge it should sign to increase network priority.
const PriorityChallengeHeader = "X-Algorand-PriorityChallenge"

// TooManyRequestsRetryAfterHeader HTTP header let the client know when to make the next connection attempt
const TooManyRequestsRetryAfterHeader = "Retry-After"

// UserAgentHeader is the HTTP header identify the user agent.
const UserAgentHeader = "User-Agent"

var websocketsScheme = map[string]string{"http": "ws", "https": "wss"}

var errBadAddr = errors.New("bad address")

var errNetworkClosing = errors.New("WebsocketNetwork shutting down")

var errBcastCallerCancel = errors.New("caller cancelled broadcast")

var errBcastQFull = errors.New("broadcast queue full")

// HostColonPortPattern matches "^[^:]+:\\d+$" e.g. "foo.com.:1234"
var HostColonPortPattern = regexp.MustCompile("^[^:]+:\\d+$")

// ParseHostOrURL handles "host:port" or a full URL.
// Standard library net/url.Parse chokes on "host:port".
func ParseHostOrURL(addr string) (*url.URL, error) {
	var parsedURL *url.URL
	if HostColonPortPattern.MatchString(addr) {
		parsedURL = &url.URL{Scheme: "http", Host: addr}
		return parsedURL, nil
	}
	return url.Parse(addr)
}

// addrToGossipAddr parses host:port or a URL and returns the URL to the websocket interface at that address.
func (wn *WebsocketNetwork) addrToGossipAddr(addr string) (string, error) {
	parsedURL, err := ParseHostOrURL(addr)
	if err != nil {
		wn.log.Warnf("could not parse addr %#v: %s", addr, err)
		return "", errBadAddr
	}
	parsedURL.Scheme = websocketsScheme[parsedURL.Scheme]
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "ws"
	}
	parsedURL.Path = strings.Replace(path.Join(parsedURL.Path, GossipNetworkPath), "{genesisID}", wn.GenesisID, -1)
	return parsedURL.String(), nil
}

// tryConnectReserveAddr synchronously checks that addr is not already being connected to, returns (websocket URL or "", true if connection may procede)
func (wn *WebsocketNetwork) tryConnectReserveAddr(addr string) (gossipAddr string, ok bool) {
	wn.tryConnectLock.Lock()
	defer wn.tryConnectLock.Unlock()
	_, exists := wn.tryConnectAddrs[addr]
	if exists {
		return "", false
	}
	gossipAddr, err := wn.addrToGossipAddr(addr)
	if err != nil {
		return "", false
	}
	_, exists = wn.tryConnectAddrs[gossipAddr]
	if exists {
		return "", false
	}
	// WARNING: isConnectedTo takes wn.peersLock; to avoid deadlock, never try to take wn.peersLock outside an attempt to lock wn.tryConnectLock
	if wn.isConnectedTo(addr) {
		return "", false
	}
	now := time.Now().Unix()
	wn.tryConnectAddrs[addr] = now
	wn.tryConnectAddrs[gossipAddr] = now
	return gossipAddr, true
}

// tryConnectReleaseAddr should be called when connection succedes and becomes a peer or fails and is no longer being attempted
func (wn *WebsocketNetwork) tryConnectReleaseAddr(addr, gossipAddr string) {
	wn.tryConnectLock.Lock()
	defer wn.tryConnectLock.Unlock()
	delete(wn.tryConnectAddrs, addr)
	delete(wn.tryConnectAddrs, gossipAddr)
}

func (wn *WebsocketNetwork) numOutgoingPending() int {
	wn.tryConnectLock.Lock()
	defer wn.tryConnectLock.Unlock()
	return len(wn.tryConnectAddrs)
}

// GetRoundTripper returns an http.Transport that limits the number of connection
// to comply with connectionsRateLimitingCount.
func (wn *WebsocketNetwork) GetRoundTripper() http.RoundTripper {
	return &wn.transport
}

// tryConnect opens websocket connection and checks initial connection parameters.
// addr should be 'host:port' or a URL, gossipAddr is the websocket endpoint URL
func (wn *WebsocketNetwork) tryConnect(addr, gossipAddr string) {
	defer wn.tryConnectReleaseAddr(addr, gossipAddr)
	defer func() {
		if xpanic := recover(); xpanic != nil {
			wn.log.Errorf("panic in tryConnect: %v", xpanic)
		}
	}()
	defer wn.wg.Done()
	requestHeader := make(http.Header)
	wn.setHeaders(requestHeader)
	for _, supportedProtocolVersion := range SupportedProtocolVersions {
		requestHeader.Add(ProtocolAcceptVersionHeader, supportedProtocolVersion)
	}
	// for backward compatability, include the ProtocolVersion header as well.
	requestHeader.Set(ProtocolVersionHeader, ProtocolVersion)
	SetUserAgentHeader(requestHeader)
	myInstanceName := wn.log.GetInstanceName()
	requestHeader.Set(InstanceNameHeader, myInstanceName)
	var websocketDialer = websocket.Dialer{
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  45 * time.Second,
		EnableCompression: false,
		NetDialContext:    wn.dialer.DialContext,
		NetDial:           wn.dialer.Dial,
	}

	conn, response, err := websocketDialer.DialContext(wn.ctx, gossipAddr, requestHeader)
	if err != nil {
		if err == websocket.ErrBadHandshake {
			// reading here from ioutil is safe only because it came from DialContext above, which alredy finsihed reading all the data from the network
			// and placed it all in a ioutil.NopCloser reader.
			bodyBytes, _ := ioutil.ReadAll(response.Body)
			errString := string(bodyBytes)
			if len(errString) > 128 {
				errString = errString[:128]
			}

			// we're guaranteed to have a valid response object.
			switch response.StatusCode {
			case http.StatusPreconditionFailed:
				wn.log.Warnf("ws connect(%s) fail - bad handshake, precondition failed : '%s'", gossipAddr, errString)
			case http.StatusLoopDetected:
				wn.log.Infof("ws connect(%s) aborted due to connecting to self", gossipAddr)
			case http.StatusTooManyRequests:
				wn.log.Infof("ws connect(%s) aborted due to connecting too frequently", gossipAddr)
				retryAfterHeader := response.Header.Get(TooManyRequestsRetryAfterHeader)
				if retryAfter, retryParseErr := strconv.ParseUint(retryAfterHeader, 10, 32); retryParseErr == nil {
					// we've got a retry-after header.
					// convert it to a timestamp so that we could use it.
					retryAfterTime := time.Now().Add(time.Duration(retryAfter) * time.Second)
					wn.phonebook.UpdateRetryAfter(addr, retryAfterTime)
				}
			default:
				wn.log.Warnf("ws connect(%s) fail - bad handshake, Status code = %d, Headers = %#v, Body = %s", gossipAddr, response.StatusCode, response.Header, errString)
			}
		} else {
			wn.log.Warnf("ws connect(%s) fail: %s", gossipAddr, err)
		}
		return
	}

	// no need to test the response.StatusCode since we know it's going to be http.StatusSwitchingProtocols, as it's already being tested inside websocketDialer.DialContext.
	// we need to examine the headers here to extract which protocol version we should be using.
	responseHeaderOk, matchingVersion := wn.checkServerResponseVariables(response.Header, gossipAddr)
	if !responseHeaderOk {
		// The error was already logged, so no need to log again.
		return
	}

	peer := &wsPeer{
		wsPeerCore:        makePeerCore(wn, addr, wn.GetRoundTripper(), "" /* origin */),
		conn:              conn,
		outgoing:          true,
		incomingMsgFilter: wn.incomingMsgFilter,
		createTime:        time.Now(),
		version:           matchingVersion,
	}
	peer.TelemetryGUID, peer.InstanceName, _ = getCommonHeaders(response.Header)
	peer.init(wn.config, wn.outgoingMessagesBufferSize)
	wn.addPeer(peer)
	localAddr, _ := wn.Address()
	wn.log.With("event", "ConnectedOut").With("remote", addr).With("local", localAddr).Infof("Made outgoing connection to peer %v", addr)
	wn.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerEvent,
		telemetryspec.PeerEventDetails{
			Address:      justHost(conn.RemoteAddr().String()),
			HostName:     peer.TelemetryGUID,
			Incoming:     false,
			InstanceName: peer.InstanceName,
		})

	peers.Set(float64(wn.NumPeers()), nil)
	outgoingPeers.Set(float64(wn.numOutgoingPeers()), nil)

	if wn.prioScheme != nil {
		challenge := response.Header.Get(PriorityChallengeHeader)
		if challenge != "" {
			resp := wn.prioScheme.MakePrioResponse(challenge)
			if resp != nil {
				mbytes := append([]byte(protocol.NetPrioResponseTag), resp...)
				sent := peer.writeNonBlock(mbytes, true, crypto.Digest{}, time.Now())
				if !sent {
					wn.log.With("remote", addr).With("local", localAddr).Warnf("could not send priority response to %v", addr)
				}
			}
		}
	}
}

// NewWebsocketNetwork constructor for websockets based gossip network
func NewWebsocketNetwork(log logging.Logger, config config.Local, phonebook Phonebook, genesisID string, networkID protocol.NetworkID) (wn *WebsocketNetwork, err error) {
	outerPhonebook := MakeMultiPhonebook()
	outerPhonebook.AddOrUpdatePhonebook("default", phonebook)
	wn = &WebsocketNetwork{log: log, config: config, phonebook: outerPhonebook, GenesisID: genesisID, NetworkID: networkID}

	wn.setup()
	return wn, nil
}

// NewWebsocketGossipNode constructs a websocket network node and returns it as a GossipNode interface implementation
func NewWebsocketGossipNode(log logging.Logger, config config.Local, phonebook Phonebook, genesisID string, networkID protocol.NetworkID) (gn GossipNode, err error) {
	return NewWebsocketNetwork(log, config, phonebook, genesisID, networkID)
}

// SetPrioScheme specifies the network priority scheme for a network node
func (wn *WebsocketNetwork) SetPrioScheme(s NetPrioScheme) {
	wn.prioScheme = s
}

// called from wsPeer to report that it has closed
func (wn *WebsocketNetwork) peerRemoteClose(peer *wsPeer, reason disconnectReason) {
	wn.removePeer(peer, reason)
}

func (wn *WebsocketNetwork) removePeer(peer *wsPeer, reason disconnectReason) {
	// first logging, then take the lock and do the actual accounting.
	// definitely don't change this to do the logging while holding the lock.
	localAddr, _ := wn.Address()
	wn.log.With("event", "Disconnected").With("remote", peer.rootURL).With("local", localAddr).Infof("Peer %s disconnected: %s", peer.rootURL, reason)
	peerAddr := peer.OriginAddress()
	// we might be able to get addr out of conn, or it might be closed
	if peerAddr == "" && peer.conn != nil {
		paddr := peer.conn.RemoteAddr()
		if paddr != nil {
			peerAddr = justHost(paddr.String())
		}
	}
	if peerAddr == "" {
		// didn't get addr from peer, try from url
		url, err := url.Parse(peer.rootURL)
		if err == nil {
			peerAddr = justHost(url.Host)
		} else {
			// use whatever it is
			peerAddr = justHost(peer.rootURL)
		}
	}
	wn.log.EventWithDetails(telemetryspec.Network, telemetryspec.DisconnectPeerEvent,
		telemetryspec.DisconnectPeerEventDetails{
			PeerEventDetails: telemetryspec.PeerEventDetails{
				Address:      peerAddr,
				HostName:     peer.TelemetryGUID,
				Incoming:     !peer.outgoing,
				InstanceName: peer.InstanceName,
			},
			Reason: string(reason),
		})

	peers.Set(float64(wn.NumPeers()), nil)
	incomingPeers.Set(float64(wn.numIncomingPeers()), nil)
	outgoingPeers.Set(float64(wn.numOutgoingPeers()), nil)

	wn.peersLock.Lock()
	defer wn.peersLock.Unlock()
	if peer.peerIndex < len(wn.peers) && wn.peers[peer.peerIndex] == peer {
		heap.Remove(peersHeap{wn}, peer.peerIndex)
		wn.prioTracker.removePeer(peer)
	}
	wn.countPeersSetGauges()
}

func (wn *WebsocketNetwork) addPeer(peer *wsPeer) {
	wn.peersLock.Lock()
	defer wn.peersLock.Unlock()
	for _, p := range wn.peers {
		if p == peer {
			wn.log.Error("dup peer added %#v", peer)
			return
		}
	}
	heap.Push(peersHeap{wn}, peer)
	wn.prioTracker.setPriority(peer, peer.prioAddress, peer.prioWeight)
	wn.countPeersSetGauges()
	if len(wn.peers) >= wn.config.GossipFanout {
		// we have a quorum of connected peers, if we weren't ready before, we are now
		if atomic.CompareAndSwapInt32(&wn.ready, 0, 1) {
			wn.log.Debug("ready")
			close(wn.readyChan)
		}
	} else if atomic.LoadInt32(&wn.ready) == 0 {
		// but if we're not ready in a minute, call whatever peers we've got as good enough
		wn.wg.Add(1)
		go wn.eventualReady()
	}
}

func (wn *WebsocketNetwork) eventualReady() {
	defer wn.wg.Done()
	minute := time.NewTimer(wn.eventualReadyDelay)
	select {
	case <-wn.ctx.Done():
	case <-minute.C:
		if atomic.CompareAndSwapInt32(&wn.ready, 0, 1) {
			wn.log.Debug("ready")
			close(wn.readyChan)
		}
	}
}

// should be run from inside a context holding wn.peersLock
func (wn *WebsocketNetwork) countPeersSetGauges() {
	numIn := 0
	numOut := 0
	for _, xp := range wn.peers {
		if xp.outgoing {
			numOut++
		} else {
			numIn++
		}
	}
	networkIncomingConnections.Set(float64(numIn), nil)
	networkOutgoingConnections.Set(float64(numOut), nil)
}

func justHost(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

// SetUserAgentHeader adds the User-Agent header to the provided heades map.
func SetUserAgentHeader(header http.Header) {
	version := config.GetCurrentVersion()
	ua := fmt.Sprintf("algod/%d.%d (%s; commit=%s; %d) %s(%s)", version.Major, version.Minor, version.Channel, version.CommitHash, version.BuildNumber, runtime.GOOS, runtime.GOARCH)
	header.Set(UserAgentHeader, ua)
}
