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

package network

import (
	"container/heap"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/algorand/websocket"
	"github.com/gorilla/mux"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/network/addr"
	"github.com/algorand/go-algorand/network/limitcaller"
	"github.com/algorand/go-algorand/network/limitlistener"
	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/network/phonebook"
	"github.com/algorand/go-algorand/protocol"
	tools_network "github.com/algorand/go-algorand/tools/network"
	"github.com/algorand/go-algorand/tools/network/dnssec"
	"github.com/algorand/go-algorand/util"
)

const incomingThreads = 20
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

// connectionActivityMonitorInterval is the interval at which we check
// if any of the connected peers have been idle for a long while and
// need to be disconnected.
const connectionActivityMonitorInterval = 3 * time.Minute

// maxPeerInactivityDuration is the maximum allowed duration for a
// peer to remain completely idle (i.e. no inbound or outbound communication), before
// we discard the connection.
const maxPeerInactivityDuration = 5 * time.Minute

// maxMessageQueueDuration is the maximum amount of time a message is allowed to be waiting
// in the various queues before being sent. Once that deadline has reached, sending the message
// is pointless, as it's too stale to be of any value
const maxMessageQueueDuration = 25 * time.Second

// slowWritingPeerMonitorInterval is the interval at which we peek on the connected peers to
// verify that their current outgoing message is not being blocked for too long.
const slowWritingPeerMonitorInterval = 5 * time.Second

// unprintableCharacterGlyph is used to replace any non-ascii character when logging incoming network string directly
// to the log file. Note that the log file itself would also json-encode these before placing them in the log file.
const unprintableCharacterGlyph = "▯"

// testingPublicAddress is used in identity exchange tests for a predictable
// PublicAddress (which will match HTTP Listener's Address) in tests only.
const testingPublicAddress = "testing"

// Maximum number of bytes to read from a header when trying to establish a websocket connection.
const wsMaxHeaderBytes = 4096

// ReservedHealthServiceConnections reserves additional connections for the health check endpoint. This reserves
// capacity to query the health check service when a node is serving maximum peers. The file descriptors will be
// used from the ReservedFDs pool, as this pool is meant for short-lived usage (dns queries, disk i/o, etc.)
const ReservedHealthServiceConnections = 10

// peerDisconnectionAckDuration defines the time we would wait for the peer disconnection to complete.
const peerDisconnectionAckDuration = 5 * time.Second

// peerShutdownDisconnectionAckDuration defines the time we would wait for the peer disconnection to complete during shutdown.
const peerShutdownDisconnectionAckDuration = 50 * time.Millisecond

// GossipNetworkPath is the URL path to connect to the websocket gossip node at.
// Contains {genesisID} param to be handled by gorilla/mux
const GossipNetworkPath = "/v1/{genesisID}/gossip"

// HealthServiceStatusPath is the path to register HealthService as a handler for when using gorilla/mux
const HealthServiceStatusPath = "/status"

// NodeInfo helps the network get information about the node it is running on
type NodeInfo interface {
	// IsParticipating returns true if this node has stake and may vote on blocks or propose blocks.
	IsParticipating() bool
	// Capabilities returns a list of capabilities this node has.
	Capabilities() []p2p.Capability
}

type nopeNodeInfo struct {
}

func (nnni *nopeNodeInfo) IsParticipating() bool {
	return false
}

func (nnni *nopeNodeInfo) Capabilities() []p2p.Capability {
	return nil
}

// GenesisInfo contains information about the genesis of the network.
type GenesisInfo struct {
	GenesisID string
	NetworkID protocol.NetworkID
}

// WebsocketNetwork implements GossipNode
type WebsocketNetwork struct {
	listener net.Listener
	server   http.Server
	router   *mux.Router
	scheme   string // are we serving http or https ?

	upgrader websocket.Upgrader

	config config.Local

	log logging.Logger

	wg sync.WaitGroup

	ctx       context.Context
	ctxCancel context.CancelFunc

	peersLock          deadlock.RWMutex
	peers              []*wsPeer
	peersChangeCounter atomic.Int32 // peersChangeCounter is an atomic variable that increases on each change to the peers. It helps avoiding taking the peersLock when checking if the peers list was modified.

	broadcaster msgBroadcaster
	handler     msgHandler

	phonebook phonebook.Phonebook

	genesisInfo GenesisInfo
	randomID    string

	ready     atomic.Int32
	readyChan chan struct{}

	meshUpdateRequests chan meshRequest
	mesher             mesher
	meshCreator        MeshCreator // save parameter to use in setup()

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

	// identity challenge scheme for creating challenges and responding
	identityScheme  identityChallengeScheme
	identityTracker identityTracker

	// outgoingMessagesBufferSize is the size used for outgoing messages.
	outgoingMessagesBufferSize int

	// wsMaxHeaderBytes is the maximum accepted size of the header prior to upgrading to websocket connection.
	wsMaxHeaderBytes int64

	requestsTracker *RequestTracker
	requestsLogger  *RequestLogger

	// peerStater collects and report peers connectivity telemetry
	peerStater peerConnectionStater

	// connPerfMonitor is used on outgoing connections to measure their relative message timing
	connPerfMonitor *connectionPerformanceMonitor

	// lastNetworkAdvanceMu synchronized the access to lastNetworkAdvance
	lastNetworkAdvanceMu deadlock.Mutex

	// lastNetworkAdvance contains the last timestamp where the agreement protocol was able to make a notable progress.
	// it used as a watchdog to help us detect connectivity issues ( such as cliques )
	lastNetworkAdvance time.Time

	// number of throttled outgoing connections "slots" needed to be populated.
	throttledOutgoingConnections atomic.Int32

	// dialer is customized to limit the number of
	// connection in compliance with connectionsRateLimitingCount.
	dialer limitcaller.Dialer

	// messagesOfInterest specifies the message types that this node
	// wants to receive.  nil means default.  non-nil causes this
	// map to be sent to new peers as a MsgOfInterest message type.
	messagesOfInterest map[protocol.Tag]bool

	// messagesOfInterestEnc is the encoding of messagesOfInterest,
	// to be sent to new peers.  This is filled in at network start,
	// at which point messagesOfInterestEncoded is set to prevent
	// further changes.
	messagesOfInterestEnc        []byte
	messagesOfInterestEncoded    bool
	messagesOfInterestGeneration atomic.Uint32

	// messagesOfInterestMu protects messagesOfInterest and ensures
	// that messagesOfInterestEnc does not change once it is set during
	// network start.
	messagesOfInterestMu      deadlock.Mutex
	messagesOfInterestRefresh chan struct{}

	// peersConnectivityCheckTicker is the timer for testing that all the connected peers
	// are still transmitting or receiving information. The channel produced by this ticker
	// is consumed by any of the messageHandlerThread(s). The ticker itself is created during
	// Start(), and being shut down when Stop() is called.
	peersConnectivityCheckTicker *time.Ticker

	nodeInfo NodeInfo

	// atomic {0:unknown, 1:yes, 2:no}
	wantTXGossip atomic.Uint32

	// supportedProtocolVersions defines versions supported by this network.
	// Should be used instead of a global network.SupportedProtocolVersions for network/peers configuration
	supportedProtocolVersions []string

	// protocolVersion is an actual version announced as ProtocolVersionHeader
	protocolVersion string

	// resolveSRVRecords is a function that resolves SRV records for a given service, protocol and name
	resolveSRVRecords func(ctx context.Context, service string, protocol string, name string, fallbackDNSResolverAddress string, secure bool) (addrs []string, err error)
}

const (
	wantTXGossipUnk = 0
	wantTXGossipYes = 1
	wantTXGossipNo  = 2
)

type broadcastRequest struct {
	tag         Tag
	data        []byte
	except      Peer
	done        chan struct{}
	enqueueTime time.Time
	ctx         context.Context
}

// msgBroadcaster contains the logic for preparing data for broadcast, managing broadcast priorities
// and queues. It provides a goroutine (broadcastThread) for reading from those queues and scheduling
// broadcasts to peers managed by networkPeerManager.
type msgBroadcaster struct {
	ctx                    context.Context
	log                    logging.Logger
	config                 config.Local
	broadcastQueueHighPrio chan broadcastRequest
	broadcastQueueBulk     chan broadcastRequest
	// slowWritingPeerMonitorInterval defines the interval between two consecutive tests for slow peer writing
	slowWritingPeerMonitorInterval time.Duration
	// enableVoteCompression controls whether vote compression is enabled
	enableVoteCompression bool
}

// msgHandler contains the logic for handling incoming messages and managing a readBuffer. It provides
// a goroutine (messageHandlerThread) for reading incoming messages and calling handlers.
type msgHandler struct {
	ctx        context.Context
	log        logging.Logger
	config     config.Local
	readBuffer chan IncomingMessage
	Multiplexer
}

// networkPeerManager provides the network functionality needed by msgBroadcaster and msgHandler for managing
// peer connectivity, and also sending messages.
type networkPeerManager interface {
	// used by msgBroadcaster
	peerSnapshot(dest []*wsPeer) ([]*wsPeer, int32)
	checkSlowWritingPeers()
	getPeersChangeCounter() int32

	// used by msgHandler
	Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error
	disconnectThread(badnode DisconnectablePeer, reason disconnectReason)
	checkPeersConnectivity()
}

// Address returns a string and whether that is a 'final' address or guessed.
// Part of GossipNode interface
func (wn *WebsocketNetwork) Address() (string, bool) {
	parsedURL := url.URL{Scheme: wn.scheme}
	var connected bool
	if wn.listener == nil {
		if wn.config.NetAddress == "" {
			parsedURL.Scheme = ""
		}
		parsedURL.Host = wn.config.NetAddress
		connected = false
	} else {
		parsedURL.Host = wn.listener.Addr().String()
		connected = true
	}
	return parsedURL.String(), connected
}

// PublicAddress what we tell other nodes to connect to.
// Might be different than our locally perceived network address due to NAT/etc.
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
func (wn *WebsocketNetwork) Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error {
	return wn.broadcaster.broadcast(ctx, tag, data, wait, except)
}

func (wn *msgBroadcaster) broadcast(ctx context.Context, tag Tag, data []byte, wait bool, except Peer) error {
	if wn.config.DisableNetworking {
		return nil
	}
	request := broadcastRequest{tag: tag, data: data, enqueueTime: time.Now(), ctx: ctx}
	if except != nil {
		request.except = except
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

func (wn *WebsocketNetwork) disconnectThread(badnode DisconnectablePeer, reason disconnectReason) {
	defer wn.wg.Done()
	wn.disconnect(badnode, reason)
}

// Disconnect from a peer, probably due to protocol errors.
func (wn *WebsocketNetwork) Disconnect(node DisconnectablePeer) {
	wn.disconnect(node, disconnectBadData)
}

// Disconnect from a peer, probably due to protocol errors.
func (wn *WebsocketNetwork) disconnect(badnode Peer, reason disconnectReason) {
	if badnode == nil {
		return
	}
	peer := badnode.(*wsPeer)
	peer.CloseAndWait(time.Now().Add(peerDisconnectionAckDuration))
	wn.removePeer(peer, reason)
}

func closeWaiter(wg *sync.WaitGroup, peer *wsPeer, deadline time.Time) {
	defer wg.Done()
	peer.CloseAndWait(deadline)
}

// DisconnectPeers shuts down all connections
func (wn *WebsocketNetwork) DisconnectPeers() {
	wn.peersLock.Lock()
	defer wn.peersLock.Unlock()
	closeGroup := sync.WaitGroup{}
	closeGroup.Add(len(wn.peers))
	deadline := time.Now().Add(peerDisconnectionAckDuration)
	for _, peer := range wn.peers {
		go closeWaiter(&closeGroup, peer, deadline)
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

// RegisterHTTPHandlerFunc path accepts gorilla/mux path annotations
func (wn *WebsocketNetwork) RegisterHTTPHandlerFunc(path string, handler func(http.ResponseWriter, *http.Request)) {
	wn.router.HandleFunc(path, handler)
}

// RequestConnectOutgoing tries to actually do the connect to new peers.
// `replace` drop all connections first and find new peers.
func (wn *WebsocketNetwork) RequestConnectOutgoing(replace bool, quit <-chan struct{}) {
	request := meshRequest{}
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
		case PeersPhonebookRelays:
			// return copy of phonebook, which probably also contains peers we're connected to, but if it doesn't maybe we shouldn't be making new connections to those peers (because they disappeared from the directory)
			var addrs []string
			addrs = wn.phonebook.GetAddresses(1000, phonebook.RelayRole)
			for _, addr := range addrs {
				client, _ := wn.GetHTTPClient(addr)
				peerCore := makePeerCore(wn.ctx, wn, wn.log, wn.handler.readBuffer, addr, client, "" /*origin address*/)
				outPeers = append(outPeers, &peerCore)
			}
		case PeersPhonebookArchivalNodes:
			var addrs []string
			addrs = wn.phonebook.GetAddresses(1000, phonebook.ArchivalRole)
			for _, addr := range addrs {
				client, _ := wn.GetHTTPClient(addr)
				peerCore := makePeerCore(wn.ctx, wn, wn.log, wn.handler.readBuffer, addr, client, "" /*origin address*/)
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

func (wn *WebsocketNetwork) setup() error {
	var preferredResolver dnssec.ResolverIf
	if wn.config.DNSSecurityRelayAddrEnforced() {
		preferredResolver = dnssec.MakeDefaultDnssecResolver(wn.config.FallbackDNSResolverAddress, wn.log)
	}
	if wn.nodeInfo == nil {
		wn.nodeInfo = &nopeNodeInfo{}
	}
	wn.dialer = limitcaller.MakeRateLimitingDialer(wn.phonebook, preferredResolver)

	wn.upgrader.ReadBufferSize = 4096
	wn.upgrader.WriteBufferSize = 4096
	wn.upgrader.EnableCompression = false
	wn.router = mux.NewRouter()
	if wn.config.EnableGossipService {
		wn.router.Handle(GossipNetworkPath, wn)
	}
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
	wn.relayMessages = wn.config.IsGossipServer() || wn.config.ForceRelayMessages
	if wn.relayMessages || wn.config.ForceFetchTransactions {
		wn.wantTXGossip.Store(wantTXGossipYes)
	}
	// roughly estimate the number of messages that could be seen at any given moment.
	// For the late/redo/down committee, which happen in parallel, we need to allocate
	// extra space there.
	wn.outgoingMessagesBufferSize = outgoingMessagesBufferSize
	wn.wsMaxHeaderBytes = wsMaxHeaderBytes

	wn.broadcaster = msgBroadcaster{
		ctx:                    wn.ctx,
		log:                    wn.log,
		config:                 wn.config,
		broadcastQueueHighPrio: make(chan broadcastRequest, wn.outgoingMessagesBufferSize),
		broadcastQueueBulk:     make(chan broadcastRequest, 100),
		enableVoteCompression:  wn.config.EnableVoteCompression,
	}
	if wn.broadcaster.slowWritingPeerMonitorInterval == 0 {
		wn.broadcaster.slowWritingPeerMonitorInterval = slowWritingPeerMonitorInterval
	}
	wn.meshUpdateRequests = make(chan meshRequest, 5)
	meshCreator := wn.meshCreator
	if meshCreator == nil {
		meshCreator = baseMeshCreator{}
	}
	var err error
	wn.mesher, err = meshCreator.create(
		withContext(wn.ctx),
		withMeshNetMeshFn(wn.meshThreadInner),
		withMeshPeerStatReporter(func() {
			wn.peerStater.sendPeerConnectionsTelemetryStatus(wn)
		}),
		withMeshUpdateRequest(wn.meshUpdateRequests),
		withMeshUpdateInterval(meshThreadInterval),
	)
	if err != nil {
		return fmt.Errorf("failed to create mesh: %w", err)
	}

	wn.readyChan = make(chan struct{})
	wn.tryConnectAddrs = make(map[string]int64)
	wn.eventualReadyDelay = time.Minute
	wn.prioTracker = newPrioTracker(wn)

	readBufferLen := min(max(wn.config.IncomingConnectionsLimit+wn.config.GossipFanout, 100), 10000)
	wn.handler = msgHandler{
		ctx:        wn.ctx,
		log:        wn.log,
		config:     wn.config,
		readBuffer: make(chan IncomingMessage, readBufferLen),
	}

	var rbytes [10]byte
	crypto.RandBytes(rbytes[:])
	wn.randomID = base64.StdEncoding.EncodeToString(rbytes[:])

	if wn.config.EnableIncomingMessageFilter {
		wn.incomingMsgFilter = makeMessageFilter(wn.config.IncomingMessageFilterBucketCount, wn.config.IncomingMessageFilterBucketSize)
	}
	wn.connPerfMonitor = makeConnectionPerformanceMonitor([]Tag{protocol.AgreementVoteTag, protocol.TxnTag})
	wn.lastNetworkAdvance = time.Now().UTC()

	// set our supported versions
	if wn.config.NetworkProtocolVersion != "" {
		wn.supportedProtocolVersions = []string{wn.config.NetworkProtocolVersion}
	} else {
		wn.supportedProtocolVersions = SupportedProtocolVersions
	}

	// set our actual version
	wn.protocolVersion = ProtocolVersion

	wn.messagesOfInterestRefresh = make(chan struct{}, 2)
	wn.messagesOfInterestGeneration.Store(1) // something nonzero so that any new wsPeer needs updating
	if wn.relayMessages {
		wn.registerMessageInterest(protocol.StateProofSigTag)
	}
	return nil
}

// Start makes network connections and threads
func (wn *WebsocketNetwork) Start() error {
	wn.messagesOfInterestMu.Lock()
	defer wn.messagesOfInterestMu.Unlock()
	wn.messagesOfInterestEncoded = true
	if wn.messagesOfInterest != nil {
		wn.messagesOfInterestEnc = marshallMessageOfInterestMap(wn.messagesOfInterest)
	}

	if wn.config.IsGossipServer() || wn.config.ForceRelayMessages {
		listener, err := net.Listen("tcp", wn.config.NetAddress)
		if err != nil {
			wn.log.Errorf("network could not listen %v: %s", wn.config.NetAddress, err)
			return err
		}
		// wrap the original listener with a limited connection listener
		listener = limitlistener.RejectingLimitListener(
			listener, uint64(wn.config.IncomingConnectionsLimit)+ReservedHealthServiceConnections, wn.log)
		// wrap the limited connection listener with a requests tracker listener
		wn.listener = wn.requestsTracker.Listener(listener)
		wn.log.Debugf("listening on %s", wn.listener.Addr().String())
		wn.throttledOutgoingConnections.Store(int32(wn.config.GossipFanout / 2))
	} else {
		// on non-relay, all the outgoing connections are throttled.
		wn.throttledOutgoingConnections.Store(int32(wn.config.GossipFanout))
	}
	if wn.config.DisableOutgoingConnectionThrottling {
		wn.throttledOutgoingConnections.Store(0)
	}
	if wn.config.TLSCertFile != "" && wn.config.TLSKeyFile != "" {
		wn.scheme = "https"
	} else {
		wn.scheme = "http"
	}

	// if PublicAddress set to testing, pull the name from Address()
	if wn.config.PublicAddress == testingPublicAddress {
		addr, ok := wn.Address()
		if ok {
			url, err := url.Parse(addr)
			if err == nil {
				wn.config.PublicAddress = fmt.Sprintf("%s:%s", url.Hostname(), url.Port())
			}
		}
	}
	// if the network has a public address or a libp2p peer ID, use that as the name for connection deduplication
	if wn.config.PublicAddress != "" || wn.identityScheme != nil {
		wn.RegisterHandlers(identityHandlers)
	}
	if wn.identityScheme == nil {
		wn.identityScheme = NewIdentityChallengeScheme(NetIdentityDedupNames(wn.config.PublicAddress))
	}

	wn.meshUpdateRequests <- meshRequest{}
	if wn.prioScheme != nil {
		wn.RegisterHandlers(prioHandlers)
	}
	if wn.listener != nil {
		wn.wg.Add(1)
		go wn.httpdThread()
	}

	wn.mesher.start()

	// we shouldn't have any ticker here.. but in case we do - just stop it.
	if wn.peersConnectivityCheckTicker != nil {
		wn.peersConnectivityCheckTicker.Stop()
	}
	wn.peersConnectivityCheckTicker = time.NewTicker(connectionActivityMonitorInterval)
	for i := 0; i < incomingThreads; i++ {
		wn.wg.Add(1)
		// We pass the peersConnectivityCheckTicker.C here so that we don't need to syncronize the access to the ticker's data structure.
		go wn.handler.messageHandlerThread(&wn.wg, wn.peersConnectivityCheckTicker.C, wn, "network", "WebsocketNetwork")
	}
	wn.wg.Add(1)
	go wn.broadcaster.broadcastThread(&wn.wg, wn, "network", "WebsocketNetwork")
	if wn.prioScheme != nil {
		wn.wg.Add(1)
		go wn.prioWeightRefresh()
	}

	go wn.postMessagesOfInterestThread()

	wn.log.Infof("serving genesisID=%s on %#v with RandomID=%s", wn.genesisInfo.GenesisID, wn.PublicAddress(), wn.randomID)

	return nil
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
	// this method is called only during node shutdown. In this case, we want to send the
	// shutdown message, but we don't want to wait for a long time - since we might not be lucky
	// to get a response.
	deadline := time.Now().Add(peerShutdownDisconnectionAckDuration)
	for _, peer := range wn.peers {
		go closeWaiter(&wn.wg, peer, deadline)
	}
	wn.peers = wn.peers[:0]
}

// Stop closes network connections and stops threads.
// Stop blocks until all activity on this node is done.
func (wn *WebsocketNetwork) Stop() {
	wn.log.Debug("network is stopping")
	defer wn.log.Debug("network has stopped")

	wn.handler.ClearHandlers([]Tag{})

	// if we have a working ticker, just stop it and clear it out. The access to this variable is safe since the Start()/Stop() are synced by the
	// caller, and the WebsocketNetwork doesn't access wn.peersConnectivityCheckTicker directly.
	if wn.peersConnectivityCheckTicker != nil {
		wn.peersConnectivityCheckTicker.Stop()
		wn.peersConnectivityCheckTicker = nil
	}
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
	wn.mesher.stop()
	wn.wg.Wait()
	if wn.listener != nil {
		wn.log.Debugf("closed %s", listenAddr)
	}

	// Wait for the requestsTracker to finish up to avoid potential race condition
	<-wn.requestsTracker.getWaitUntilNoConnectionsChannel(5 * time.Millisecond)
	wn.messagesOfInterestMu.Lock()
	defer wn.messagesOfInterestMu.Unlock()

	wn.messagesOfInterestEncoded = false
	wn.messagesOfInterestEnc = nil
	wn.messagesOfInterest = nil
}

// RegisterHandlers registers the set of given message handlers.
func (wn *WebsocketNetwork) RegisterHandlers(dispatch []TaggedMessageHandler) {
	wn.handler.RegisterHandlers(dispatch)
}

// ClearHandlers deregisters all the existing message handlers.
func (wn *WebsocketNetwork) ClearHandlers() {
	// exclude the internal handlers. These would get cleared out when Stop is called.
	wn.handler.ClearHandlers([]Tag{protocol.NetPrioResponseTag})
}

// RegisterValidatorHandlers registers the set of given message handlers.
func (wn *WebsocketNetwork) RegisterValidatorHandlers(dispatch []TaggedMessageValidatorHandler) {
}

// ClearValidatorHandlers deregisters all the existing message handlers.
func (wn *WebsocketNetwork) ClearValidatorHandlers() {
}

type peerMetadataProvider interface {
	TelemetryGUID() string
	InstanceName() string
	GetGenesisID() string
	PublicAddress() string
	RandomID() string
	SupportedProtoVersions() []string
	Config() config.Local
}

// TelemetryGUID returns the telemetry GUID of this node.
func (wn *WebsocketNetwork) TelemetryGUID() string {
	return wn.log.GetTelemetryGUID()
}

// InstanceName returns the instance name of this node.
func (wn *WebsocketNetwork) InstanceName() string {
	return wn.log.GetInstanceName()
}

// RandomID returns the random ID of this node.
func (wn *WebsocketNetwork) RandomID() string {
	return wn.randomID
}

// SupportedProtoVersions returns the supported protocol versions of this node.
func (wn *WebsocketNetwork) SupportedProtoVersions() []string {
	return wn.supportedProtocolVersions
}

// Config returns the configuration of this node.
func (wn *WebsocketNetwork) Config() config.Local {
	return wn.config
}

func setHeaders(header http.Header, netProtoVer string, meta peerMetadataProvider) {
	header.Set(TelemetryIDHeader, meta.TelemetryGUID())
	header.Set(InstanceNameHeader, meta.InstanceName())
	if pa := meta.PublicAddress(); pa != "" {
		header.Set(AddressHeader, pa)
	}
	if rid := meta.RandomID(); rid != "" {
		header.Set(NodeRandomHeader, rid)
	}
	header.Set(GenesisHeader, meta.GetGenesisID())

	// set the features header (comma-separated list)
	header.Set(PeerFeaturesHeader, PeerFeatureProposalCompression)
	features := []string{PeerFeatureProposalCompression}
	if meta.Config().EnableVoteCompression {
		features = append(features, PeerFeatureVoteVpackCompression)
	}
	header.Set(PeerFeaturesHeader, strings.Join(features, ","))

	if netProtoVer != "" {
		// for backward compatibility, include the ProtocolVersion header in request as well.
		header.Set(ProtocolVersionHeader, netProtoVer)
	}
	for _, v := range meta.SupportedProtoVersions() {
		header.Add(ProtocolAcceptVersionHeader, v)
	}
}

// checkServerResponseVariables check that the version and random-id in the request headers matches the server ones.
// it returns true if it's a match, and false otherwise.
func (wn *WebsocketNetwork) checkServerResponseVariables(otherHeader http.Header, addr string) (bool, string) {
	matchingVersion, otherVersion := checkProtocolVersionMatch(otherHeader, wn.supportedProtocolVersions)
	if matchingVersion == "" {
		wn.log.Info(filterASCII(fmt.Sprintf("new peer %s version mismatch, mine=%v theirs=%s, headers %#v", addr, wn.supportedProtocolVersions, otherVersion, otherHeader)))
		return false, ""
	}
	otherRandom := otherHeader.Get(NodeRandomHeader)
	if otherRandom == wn.randomID || otherRandom == "" {
		// This is pretty harmless and some configurations of phonebooks or DNS records make this likely. Quietly filter it out.
		if otherRandom == "" {
			// missing header.
			wn.log.Warn(filterASCII(fmt.Sprintf("new peer %s did not include random ID header in request. mine=%s headers %#v", addr, wn.randomID, otherHeader)))
		} else {
			wn.log.Debugf("new peer %s has same node random id, am I talking to myself? %s", addr, wn.randomID)
		}
		return false, ""
	}
	otherGenesisID := otherHeader.Get(GenesisHeader)
	if wn.genesisInfo.GenesisID != otherGenesisID {
		if otherGenesisID != "" {
			wn.log.Warn(filterASCII(fmt.Sprintf("new peer %#v genesis mismatch, mine=%#v theirs=%#v, headers %#v", addr, wn.genesisInfo.GenesisID, otherGenesisID, otherHeader)))
		} else {
			wn.log.Warnf("new peer %#v did not include genesis header in response. mine=%#v headers %#v", addr, wn.genesisInfo.GenesisID, otherHeader)
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
				Address:       remoteHost,
				TelemetryGUID: otherTelemetryGUID,
				Incoming:      true,
				InstanceName:  otherInstanceName,
				Reason:        "Connection Limit",
			})
		response.WriteHeader(http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}

	totalConnections := wn.connectedForIP(remoteHost)
	if totalConnections >= wn.config.MaxConnectionsPerIP {
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "incoming_connection_per_ip_limit"})
		wn.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerFailEvent,
			telemetryspec.ConnectPeerFailEventDetails{
				Address:       remoteHost,
				TelemetryGUID: otherTelemetryGUID,
				Incoming:      true,
				InstanceName:  otherInstanceName,
				Reason:        "Remote IP Connection Limit",
			})
		response.WriteHeader(http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}

	return http.StatusOK
}

// checkProtocolVersionMatch test ProtocolAcceptVersionHeader and ProtocolVersionHeader headers from the request/response and see if it can find a match.
func checkProtocolVersionMatch(otherHeaders http.Header, ourSupportedProtocolVersions []string) (matchingVersion string, otherVersion string) {
	otherAcceptedVersions := otherHeaders[textproto.CanonicalMIMEHeaderKey(ProtocolAcceptVersionHeader)]
	for _, otherAcceptedVersion := range otherAcceptedVersions {
		// do we have a matching version ?
		if slices.Contains(ourSupportedProtocolVersions, otherAcceptedVersion) {
			return otherAcceptedVersion, ""
		}
	}

	otherVersion = otherHeaders.Get(ProtocolVersionHeader)
	if slices.Contains(ourSupportedProtocolVersions, otherVersion) {
		return otherVersion, otherVersion
	}

	return "", filterASCII(otherVersion)
}

// checkIncomingConnectionVariables checks the variables that were provided on the request, and compares them to the
// local server supported parameters. If all good, it returns http.StatusOK; otherwise, it write the error to the ResponseWriter
// and returns the http status.
func (wn *WebsocketNetwork) checkIncomingConnectionVariables(response http.ResponseWriter, request *http.Request, remoteAddrForLogging string) int {
	// check to see that the genesisID in the request URI is valid and matches the supported one.
	pathVars := mux.Vars(request)
	otherGenesisID, hasGenesisID := pathVars["genesisID"]
	if !hasGenesisID || otherGenesisID == "" {
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "missing genesis-id"})
		response.WriteHeader(http.StatusNotFound)
		return http.StatusNotFound
	}

	if wn.genesisInfo.GenesisID != otherGenesisID {
		wn.log.Warn(filterASCII(fmt.Sprintf("new peer %#v genesis mismatch, mine=%#v theirs=%#v, headers %#v", remoteAddrForLogging, wn.genesisInfo.GenesisID, otherGenesisID, request.Header)))
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "mismatching genesis-id"})
		response.WriteHeader(http.StatusPreconditionFailed)
		n, err := response.Write([]byte("mismatching genesis ID"))
		if err != nil {
			wn.log.Warnf("ws failed to write mismatching genesis ID response '%s' : n = %d err = %v", otherGenesisID, n, err)
		}
		return http.StatusPreconditionFailed
	}

	otherRandom := request.Header.Get(NodeRandomHeader)
	if otherRandom == "" {
		// This is pretty harmless and some configurations of phonebooks or DNS records make this likely. Quietly filter it out.
		var message string
		// missing header.
		wn.log.Warn(filterASCII(fmt.Sprintf("new peer %s did not include random ID header in request. mine=%s headers %#v", remoteAddrForLogging, wn.randomID, request.Header)))
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "missing random ID header"})
		message = fmt.Sprintf("Request was missing a %s header", NodeRandomHeader)
		response.WriteHeader(http.StatusPreconditionFailed)
		n, err := response.Write([]byte(message))
		if err != nil {
			wn.log.Warnf("ws failed to write response '%s' : n = %d err = %v", message, n, err)
		}
		return http.StatusPreconditionFailed
	} else if otherRandom == wn.randomID {
		// This is pretty harmless and some configurations of phonebooks or DNS records make this likely. Quietly filter it out.
		var message string
		wn.log.Debugf("new peer %s has same node random id, am I talking to myself? %s", remoteAddrForLogging, wn.randomID)
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
	if !wn.config.EnableGossipService {
		response.WriteHeader(http.StatusNotFound)
		return
	}

	trackedRequest := wn.requestsTracker.GetTrackedRequest(request)

	if wn.checkIncomingConnectionLimits(response, request, trackedRequest.remoteHost, trackedRequest.otherTelemetryGUID, trackedRequest.otherInstanceName) != http.StatusOK {
		// we've already logged and written all response(s).
		return
	}

	matchingVersion, otherVersion := checkProtocolVersionMatch(request.Header, wn.supportedProtocolVersions)
	if matchingVersion == "" {
		wn.log.Info(filterASCII(fmt.Sprintf("new peer %s version mismatch, mine=%v theirs=%s, headers %#v", trackedRequest.remoteHost, wn.supportedProtocolVersions, otherVersion, request.Header)))
		networkConnectionsDroppedTotal.Inc(map[string]string{"reason": "mismatching protocol version"})
		response.WriteHeader(http.StatusPreconditionFailed)
		message := fmt.Sprintf("Requested version %s not in %v mismatches server version", filterASCII(otherVersion), wn.supportedProtocolVersions)
		n, err := response.Write([]byte(message))
		if err != nil {
			wn.log.Warnf("ws failed to write response '%s' : n = %d err = %v", message, n, err)
		}
		return
	}

	if wn.checkIncomingConnectionVariables(response, request, trackedRequest.remoteAddress()) != http.StatusOK {
		// we've already logged and written all response(s).
		return
	}

	responseHeader := make(http.Header)
	setHeaders(responseHeader, matchingVersion, wn)
	var challenge string
	if wn.prioScheme != nil {
		challenge = wn.prioScheme.NewPrioChallenge()
		responseHeader.Set(PriorityChallengeHeader, challenge)
	}

	localAddr, _ := wn.Address()
	var peerIDChallenge identityChallengeValue
	var peerID crypto.PublicKey
	if wn.identityScheme != nil {
		var err error
		peerIDChallenge, peerID, err = wn.identityScheme.VerifyRequestAndAttachResponse(responseHeader, request.Header)
		if err != nil {
			networkPeerIdentityError.Inc(nil)
			wn.log.With("err", err).With("remote", trackedRequest.remoteAddress()).With("local", localAddr).Warnf("peer (%s) supplied an invalid identity challenge, abandoning peering", trackedRequest.remoteAddr)
			return
		}
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

	client, _ := wn.GetHTTPClient(trackedRequest.remoteAddress())
	peer := &wsPeer{
		wsPeerCore:            makePeerCore(wn.ctx, wn, wn.log, wn.handler.readBuffer, trackedRequest.remoteAddress(), client, trackedRequest.remoteHost),
		conn:                  wsPeerWebsocketConnImpl{conn},
		outgoing:              false,
		InstanceName:          trackedRequest.otherInstanceName,
		incomingMsgFilter:     wn.incomingMsgFilter,
		prioChallenge:         challenge,
		createTime:            trackedRequest.created,
		version:               matchingVersion,
		identity:              peerID,
		identityChallenge:     peerIDChallenge,
		identityVerified:      atomic.Uint32{},
		features:              decodePeerFeatures(matchingVersion, request.Header.Get(PeerFeaturesHeader)),
		enableVoteCompression: wn.config.EnableVoteCompression,
	}
	peer.TelemetryGUID = trackedRequest.otherTelemetryGUID
	peer.init(wn.config, wn.outgoingMessagesBufferSize)
	wn.addPeer(peer)
	wn.log.With("event", "ConnectedIn").With("remote", trackedRequest.remoteAddress()).With("local", localAddr).Infof("Accepted incoming connection from peer %s", trackedRequest.remoteAddr)
	wn.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerEvent,
		telemetryspec.PeerEventDetails{
			Address:       trackedRequest.remoteHost,
			TelemetryGUID: trackedRequest.otherTelemetryGUID,
			Incoming:      true,
			InstanceName:  trackedRequest.otherInstanceName,
		})

	wn.maybeSendMessagesOfInterest(peer, nil)

	peers.Set(uint64(wn.NumPeers()))
	incomingPeers.Set(uint64(wn.numIncomingPeers()))
}

func (wn *WebsocketNetwork) maybeSendMessagesOfInterest(peer *wsPeer, messagesOfInterestEnc []byte) {
	messagesOfInterestGeneration := wn.messagesOfInterestGeneration.Load()
	peerMessagesOfInterestGeneration := peer.messagesOfInterestGeneration.Load()
	if peerMessagesOfInterestGeneration != messagesOfInterestGeneration {
		if messagesOfInterestEnc == nil {
			wn.messagesOfInterestMu.Lock()
			messagesOfInterestEnc = wn.messagesOfInterestEnc
			wn.messagesOfInterestMu.Unlock()
		}
		if messagesOfInterestEnc != nil {
			peer.sendMessagesOfInterest(messagesOfInterestGeneration, messagesOfInterestEnc)
		} else {
			wn.log.Infof("msgOfInterest Enc=nil, MOIGen=%d", messagesOfInterestGeneration)
		}
	}
}

func (wn *msgHandler) messageHandlerThread(wg *sync.WaitGroup, peersConnectivityCheckCh <-chan time.Time, net networkPeerManager, profLabels ...string) {
	defer wg.Done()
	util.SetGoroutineLabels(append(profLabels, "func", "msgHandler.messageHandlerThread")...)

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
				wn.sendFilterMessage(msg, net)
			}
			//wn.log.Debugf("msg handling %#v [%d]byte", msg.Tag, len(msg.Data))
			start := time.Now()

			// now, send to global handlers
			outmsg := wn.Handle(msg)
			handled := time.Now()
			bufferNanos := start.UnixNano() - msg.Received
			networkIncomingBufferMicros.AddUint64(uint64(bufferNanos/1000), nil)
			handleTime := handled.Sub(start)
			networkHandleMicros.AddUint64(uint64(handleTime.Nanoseconds()/1000), nil)
			networkHandleMicrosByTag.Add(string(msg.Tag), uint64(handleTime.Nanoseconds()/1000))
			networkHandleCountByTag.Add(string(msg.Tag), 1)
			switch outmsg.Action {
			case Disconnect:
				wg.Add(1)
				reason := disconnectBadData
				if outmsg.reason != disconnectReasonNone {
					reason = outmsg.reason
				}
				go net.disconnectThread(msg.Sender, reason)
			case Broadcast:
				err := net.Broadcast(wn.ctx, msg.Tag, msg.Data, false, msg.Sender)
				if err != nil && err != errBcastQFull {
					wn.log.Warnf("WebsocketNetwork.messageHandlerThread: WebsocketNetwork.Broadcast returned unexpected error %v", err)
				}
			case Respond:
				err := msg.Sender.(*wsPeer).Respond(wn.ctx, msg, outmsg)
				if err != nil && err != wn.ctx.Err() {
					wn.log.Warnf("WebsocketNetwork.messageHandlerThread: wsPeer.Respond returned unexpected error %v", err)
				}
			default:
			}
		case <-peersConnectivityCheckCh:
			// go over the peers and ensure we have some type of communication going on.
			net.checkPeersConnectivity()
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

func (wn *msgHandler) sendFilterMessage(msg IncomingMessage, net networkPeerManager) {
	digest := generateMessageDigest(msg.Tag, msg.Data)
	//wn.log.Debugf("send filter %s(%d) %v", msg.Tag, len(msg.Data), digest)
	err := net.Broadcast(context.Background(), protocol.MsgDigestSkipTag, digest[:], false, msg.Sender)
	if err != nil && err != errBcastQFull {
		wn.log.Warnf("WebsocketNetwork.sendFilterMessage: WebsocketNetwork.Broadcast returned unexpected error %v", err)
	}
}

func (wn *msgBroadcaster) broadcastThread(wg *sync.WaitGroup, net networkPeerManager, profLabels ...string) {
	defer wg.Done()
	util.SetGoroutineLabels(append(profLabels, "func", "msgHandler.broadcastThread")...)

	slowWritingPeerCheckTicker := time.NewTicker(wn.slowWritingPeerMonitorInterval)
	defer slowWritingPeerCheckTicker.Stop()
	peers, lastPeersChangeCounter := net.peerSnapshot([]*wsPeer{})
	// updatePeers update the peers list if their peer change counter has changed.
	updatePeers := func() {
		if curPeersChangeCounter := net.getPeersChangeCounter(); curPeersChangeCounter != lastPeersChangeCounter {
			peers, lastPeersChangeCounter = net.peerSnapshot(peers)
		}
	}

	// waitForPeers waits until there is at least a single peer connected or pending request expires.
	// in any of the above two cases, it returns true.
	// otherwise, false is returned ( the network context has expired )
	waitForPeers := func(request *broadcastRequest) bool {
		// waitSleepTime defines how long we'd like to sleep between consecutive tests that the peers list have been updated.
		const waitSleepTime = 5 * time.Millisecond
		// requestDeadline is the request deadline. If we surpass that deadline, the function returns true.
		var requestDeadline time.Time
		// sleepDuration is the current iteration sleep time.
		var sleepDuration time.Duration
		// initialize the requestDeadline if we have a request.
		if request != nil {
			requestDeadline = request.enqueueTime.Add(maxMessageQueueDuration)
		} else {
			sleepDuration = waitSleepTime
		}

		// wait until the we have at least a single peer connected.
		for len(peers) == 0 {
			// adjust the sleep time in case we have a request
			if request != nil {
				// we want to clamp the sleep time so that we won't sleep beyond the expiration of the request.
				now := time.Now()
				sleepDuration = requestDeadline.Sub(now)
				if sleepDuration > waitSleepTime {
					sleepDuration = waitSleepTime
				} else if sleepDuration < 0 {
					return true
				}
			}
			select {
			case <-util.NanoAfter(sleepDuration):
				if (request != nil) && time.Now().After(requestDeadline) {
					// message time have elapsed.
					return true
				}
				updatePeers()
				continue
			case <-wn.ctx.Done():
				return false
			}
		}
		return true
	}

	// load the peers list
	updatePeers()

	// wait until the we have at least a single peer connected.
	if !waitForPeers(nil) {
		return
	}

	for {
		// broadcast from high prio channel as long as we can
		// we want to try and keep this as a single case select with a default, since go compiles a single-case
		// select with a default into a more efficient non-blocking receive, instead of compiling it to the general-purpose selectgo
		select {
		case request := <-wn.broadcastQueueHighPrio:
			wn.innerBroadcast(request, true, peers)
			continue
		default:
		}

		// if nothing high prio, try to sample from either queques in a non-blocking fashion.
		select {
		case request := <-wn.broadcastQueueHighPrio:
			wn.innerBroadcast(request, true, peers)
			continue
		case request := <-wn.broadcastQueueBulk:
			wn.innerBroadcast(request, false, peers)
			continue
		case <-wn.ctx.Done():
			return
		default:
		}

		// block until we have some request that need to be sent.
		select {
		case request := <-wn.broadcastQueueHighPrio:
			// check if peers need to be updated, since we've been waiting a while.
			updatePeers()
			if !waitForPeers(&request) {
				return
			}
			wn.innerBroadcast(request, true, peers)
		case <-slowWritingPeerCheckTicker.C:
			net.checkSlowWritingPeers()
			continue
		case request := <-wn.broadcastQueueBulk:
			// check if peers need to be updated, since we've been waiting a while.
			updatePeers()
			if !waitForPeers(&request) {
				return
			}
			wn.innerBroadcast(request, false, peers)
		case <-wn.ctx.Done():
			return
		}
	}
}

// peerSnapshot returns the currently connected peers as well as the current value of the peersChangeCounter
func (wn *WebsocketNetwork) peerSnapshot(dest []*wsPeer) ([]*wsPeer, int32) {
	wn.peersLock.RLock()
	defer wn.peersLock.RUnlock()
	if cap(dest) >= len(wn.peers) {
		// clear out the unused portion of the peers array to allow the GC to cleanup unused peers.
		remainderPeers := dest[len(wn.peers):cap(dest)]
		for i := range remainderPeers {
			// we want to delete only up to the first nil peer, since we're always writing to this array from the beginning to the end
			if remainderPeers[i] == nil {
				break
			}
			remainderPeers[i] = nil
		}
		// adjust array size
		dest = dest[:len(wn.peers)]
	} else {
		dest = make([]*wsPeer, len(wn.peers))
	}
	copy(dest, wn.peers)
	return dest, wn.getPeersChangeCounter()
}

func (wn *WebsocketNetwork) getPeersChangeCounter() int32 {
	return wn.peersChangeCounter.Load()
}

// preparePeerData prepares batches of data for sending.
// It performs zstd compression for proposal massages if they this is a prio request and has proposal.
func (wn *msgBroadcaster) preparePeerData(request broadcastRequest, prio bool) ([]byte, []byte, crypto.Digest) {
	tbytes := []byte(request.tag)
	mbytes := make([]byte, len(tbytes)+len(request.data))
	copy(mbytes, tbytes)
	copy(mbytes[len(tbytes):], request.data)
	var compressedData []byte

	var digest crypto.Digest
	if request.tag != protocol.MsgDigestSkipTag && len(request.data) >= messageFilterSize {
		digest = crypto.Hash(mbytes)
	}
	// Compress proposals -- all proposals are compressed as of wsnet 2.2
	if prio && request.tag == protocol.ProposalPayloadTag {
		compressed, logMsg := zstdCompressMsg(tbytes, request.data)
		if len(logMsg) > 0 {
			wn.log.Warn(logMsg)
		}
		mbytes = compressed
	}
	// Optionally compress votes: only supporting peers will receive it.
	if prio && request.tag == protocol.AgreementVoteTag && wn.enableVoteCompression {
		var logMsg string
		compressedData, logMsg = vpackCompressVote(tbytes, request.data)
		if len(logMsg) > 0 {
			wn.log.Warn(logMsg)
		}
	}
	return mbytes, compressedData, digest
}

// prio is set if the broadcast is a high-priority broadcast.
func (wn *msgBroadcaster) innerBroadcast(request broadcastRequest, prio bool, peers []*wsPeer) {
	if request.done != nil {
		defer close(request.done)
	}

	broadcastQueueDuration := time.Since(request.enqueueTime)
	networkBroadcastQueueMicros.AddUint64(uint64(broadcastQueueDuration.Nanoseconds()/1000), nil)
	if broadcastQueueDuration > maxMessageQueueDuration {
		networkBroadcastsDropped.Inc(nil)
		return
	}

	start := time.Now()
	data, dataWithCompression, digest := wn.preparePeerData(request, prio)

	// first send to all the easy outbound peers who don't block, get them started.
	sentMessageCount := 0
	for _, peer := range peers {
		if wn.config.BroadcastConnectionsLimit >= 0 && sentMessageCount >= wn.config.BroadcastConnectionsLimit {
			break
		}
		if Peer(peer) == request.except {
			continue
		}
		dataToSend := data
		// check whether to send a compressed vote. dataWithCompression will be empty if this node
		// has not enabled vote compression.
		if peer.vpackVoteCompressionSupported() && len(dataWithCompression) > 0 {
			dataToSend = dataWithCompression
		}
		ok := peer.writeNonBlock(request.ctx, dataToSend, prio, digest, request.enqueueTime)
		if ok {
			sentMessageCount++
			continue
		}
		networkPeerBroadcastDropped.Inc(nil)
	}

	dt := time.Since(start)
	networkBroadcasts.Inc(nil)
	networkBroadcastSendMicros.AddUint64(uint64(dt.Nanoseconds()/1000), nil)
}

// NumPeers returns number of peers we connect to (all peers incoming and outbound).
func (wn *WebsocketNetwork) NumPeers() int {
	wn.peersLock.RLock()
	defer wn.peersLock.RUnlock()
	return len(wn.peers)
}

// outgoingPeers returns an array of the outgoing peers.
func (wn *WebsocketNetwork) outgoingPeers() (peers []Peer) {
	wn.peersLock.RLock()
	defer wn.peersLock.RUnlock()
	peers = make([]Peer, 0, len(wn.peers))
	for _, peer := range wn.peers {
		if peer.outgoing {
			peers = append(peers, peer)
		}
	}
	return
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
		if addr == peer.GetAddress() {
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

const cliqueResolveInterval = 5 * time.Minute

type meshRequest struct {
	done chan struct{}
}

func (wn *WebsocketNetwork) meshThreadInner() bool {
	wn.refreshRelayArchivePhonebookAddresses()

	// as long as the call to checkExistingConnectionsNeedDisconnecting is deleting existing connections, we want to
	// kick off the creation of new connections.
	for {
		if wn.checkNewConnectionsNeeded() {
			// new connections were created.
			break
		}
		if !wn.checkExistingConnectionsNeedDisconnecting() {
			// no connection were removed.
			break
		}
	}
	return true
}

func (wn *WebsocketNetwork) refreshRelayArchivePhonebookAddresses() {
	// TODO: only do DNS fetch every N seconds? Honor DNS TTL? Trust DNS library we're using to handle caching and TTL?
	dnsBootstrapArray := wn.config.DNSBootstrapArray(wn.genesisInfo.NetworkID)

	for _, dnsBootstrap := range dnsBootstrapArray {
		primaryRelayAddrs, primaryArchivalAddrs := wn.getDNSAddrs(dnsBootstrap.PrimarySRVBootstrap)

		if dnsBootstrap.BackupSRVBootstrap != "" {
			backupRelayAddrs, backupArchivalAddrs := wn.getDNSAddrs(dnsBootstrap.BackupSRVBootstrap)
			dedupedRelayAddresses := wn.mergePrimarySecondaryAddressSlices(primaryRelayAddrs,
				backupRelayAddrs, dnsBootstrap.DedupExp)
			dedupedArchivalAddresses := wn.mergePrimarySecondaryAddressSlices(primaryArchivalAddrs,
				backupArchivalAddrs, dnsBootstrap.DedupExp)
			wn.updatePhonebookAddresses(dedupedRelayAddresses, dedupedArchivalAddresses)
		} else {
			wn.updatePhonebookAddresses(primaryRelayAddrs, primaryArchivalAddrs)
		}
	}
}

func (wn *WebsocketNetwork) updatePhonebookAddresses(relayAddrs []string, archiveAddrs []string) {
	if len(relayAddrs) > 0 {
		wn.log.Debugf("got %d relay dns addrs, %#v", len(relayAddrs), relayAddrs[:min(5, len(relayAddrs))])
		wn.phonebook.ReplacePeerList(relayAddrs, string(wn.genesisInfo.NetworkID), phonebook.RelayRole)
	} else {
		wn.log.Infof("got no relay DNS addrs for network %s", wn.genesisInfo.NetworkID)
	}
	if len(archiveAddrs) > 0 {
		wn.phonebook.ReplacePeerList(archiveAddrs, string(wn.genesisInfo.NetworkID), phonebook.ArchivalRole)
	} else {
		wn.log.Infof("got no archive DNS addrs for network %s", wn.genesisInfo.NetworkID)
	}
}

// checkNewConnectionsNeeded checks to see if we need to have more connections to meet the GossipFanout target.
// if we do, it will spin async connection go routines.
// it returns false if no connections are needed, and true otherwise.
// note that the determination of needed connection could be inaccurate, and it might return false while
// more connection should be created.
func (wn *WebsocketNetwork) checkNewConnectionsNeeded() bool {
	desired := wn.config.GossipFanout
	numOutgoingTotal := wn.numOutgoingPeers() + wn.numOutgoingPending()
	need := desired - numOutgoingTotal
	if need <= 0 {
		return false
	}
	// get more than we need so that we can ignore duplicates
	newAddrs := wn.phonebook.GetAddresses(desired+numOutgoingTotal, phonebook.RelayRole)
	for _, na := range newAddrs {
		if na == wn.config.PublicAddress {
			// filter out self-public address, so we won't try to connect to ourselves.
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
	return true
}

// checkExistingConnectionsNeedDisconnecting check to see if existing connection need to be dropped due to
// performance issues and/or network being stalled.
func (wn *WebsocketNetwork) checkExistingConnectionsNeedDisconnecting() bool {
	// we already connected ( or connecting.. ) to  GossipFanout peers.
	// get the actual peers.
	outgoingPeers := wn.outgoingPeers()
	if len(outgoingPeers) < wn.config.GossipFanout {
		// reset the performance monitor.
		wn.connPerfMonitor.Reset([]Peer{})
		return wn.checkNetworkAdvanceDisconnect()
	}

	if !wn.connPerfMonitor.ComparePeers(outgoingPeers) {
		// different set of peers. restart monitoring.
		wn.connPerfMonitor.Reset(outgoingPeers)
	}

	// same set of peers.
	peerStat := wn.connPerfMonitor.GetPeersStatistics()
	if peerStat == nil {
		// performance metrics are not yet ready.
		return wn.checkNetworkAdvanceDisconnect()
	}

	// update peers with the performance metrics we've gathered.
	var leastPerformingPeer *wsPeer = nil
	for _, stat := range peerStat.peerStatistics {
		wsPeer := stat.peer.(*wsPeer)
		wsPeer.peerMessageDelay = stat.peerDelay
		wn.log.Infof("network performance monitor - peer '%s' delay %d first message portion %d%%", wsPeer.GetAddress(), stat.peerDelay, int(stat.peerFirstMessage*100))
		if wsPeer.throttledOutgoingConnection && leastPerformingPeer == nil {
			leastPerformingPeer = wsPeer
		}
	}
	if leastPerformingPeer == nil {
		return wn.checkNetworkAdvanceDisconnect()
	}
	wn.disconnect(leastPerformingPeer, disconnectLeastPerformingPeer)
	wn.connPerfMonitor.Reset([]Peer{})

	return true
}

// checkNetworkAdvanceDisconnect is using the lastNetworkAdvance indicator to see if the network is currently "stuck".
// if it's seems to be "stuck", a randomally picked peer would be disconnected.
func (wn *WebsocketNetwork) checkNetworkAdvanceDisconnect() bool {
	lastNetworkAdvance := wn.getLastNetworkAdvance()
	if time.Now().UTC().Sub(lastNetworkAdvance) < cliqueResolveInterval {
		return false
	}
	outgoingPeers := wn.outgoingPeers()
	if len(outgoingPeers) == 0 {
		return false
	}
	if wn.numOutgoingPending() > 0 {
		// we're currently trying to extend the list of outgoing connections. no need to
		// disconnect any existing connection to free up room for another connection.
		return false
	}
	var peer *wsPeer
	disconnectPeerIdx := crypto.RandUint63() % uint64(len(outgoingPeers))
	peer = outgoingPeers[disconnectPeerIdx].(*wsPeer)

	wn.disconnect(peer, disconnectCliqueResolve)
	wn.connPerfMonitor.Reset([]Peer{})
	wn.OnNetworkAdvance()
	return true
}

func (wn *WebsocketNetwork) getLastNetworkAdvance() time.Time {
	wn.lastNetworkAdvanceMu.Lock()
	defer wn.lastNetworkAdvanceMu.Unlock()
	return wn.lastNetworkAdvance
}

// OnNetworkAdvance notifies the network library that the agreement protocol was able to make a notable progress.
// this is the only indication that we have that we haven't formed a clique, where all incoming messages
// arrive very quickly, but might be missing some votes. The usage of this call is expected to have similar
// characteristics as with a watchdog timer.
func (wn *WebsocketNetwork) OnNetworkAdvance() {
	wn.lastNetworkAdvanceMu.Lock()
	defer wn.lastNetworkAdvanceMu.Unlock()
	wn.lastNetworkAdvance = time.Now().UTC()
	if wn.nodeInfo != nil && !wn.relayMessages && !wn.config.ForceFetchTransactions {
		select {
		case wn.messagesOfInterestRefresh <- struct{}{}:
		default:
			// if the notify chan is full, it will get around to updating the latest when it actually runs
		}
	}
}

type peerConnectionStater struct {
	log logging.Logger

	peerConnectionsUpdateInterval time.Duration
	lastPeerConnectionsSent       time.Time
}

type peerSnapshotter interface {
	peerSnapshot(peers []*wsPeer) ([]*wsPeer, int32)
}

// sendPeerConnectionsTelemetryStatus sends a snapshot of the currently connected peers
// to the telemetry server. Internally, it's using a timer to ensure that it would only
// send the information once every hour ( configurable via PeerConnectionsUpdateInterval )
func (pcs *peerConnectionStater) sendPeerConnectionsTelemetryStatus(snapshotter peerSnapshotter) {
	if !pcs.log.GetTelemetryEnabled() {
		return
	}
	now := time.Now()
	if pcs.lastPeerConnectionsSent.Add(pcs.peerConnectionsUpdateInterval).After(now) || pcs.peerConnectionsUpdateInterval <= 0 {
		// it's not yet time to send the update.
		return
	}
	pcs.lastPeerConnectionsSent = now

	var peers []*wsPeer
	peers, _ = snapshotter.peerSnapshot(peers)
	connectionDetails := getPeerConnectionTelemetryDetails(now, peers)
	pcs.log.EventWithDetails(telemetryspec.Network, telemetryspec.PeerConnectionsEvent, connectionDetails)
}

func getPeerConnectionTelemetryDetails(now time.Time, peers []*wsPeer) telemetryspec.PeersConnectionDetails {
	var connectionDetails telemetryspec.PeersConnectionDetails
	for _, peer := range peers {
		connDetail := telemetryspec.PeerConnectionDetails{
			ConnectionDuration:   uint(now.Sub(peer.createTime).Seconds()),
			TelemetryGUID:        peer.TelemetryGUID,
			InstanceName:         peer.InstanceName,
			DuplicateFilterCount: peer.duplicateFilterCount.Load(),
			TXCount:              peer.txMessageCount.Load(),
			MICount:              peer.miMessageCount.Load(),
			AVCount:              peer.avMessageCount.Load(),
			PPCount:              peer.ppMessageCount.Load(),
			UNKCount:             peer.unkMessageCount.Load(),
		}
		if tcpInfo, err := peer.GetUnderlyingConnTCPInfo(); err == nil && tcpInfo != nil {
			connDetail.TCP = *tcpInfo
		}
		if peer.outgoing {
			connDetail.Address = justHost(peer.conn.RemoteAddrString())
			connDetail.Endpoint = peer.GetAddress()
			connDetail.MessageDelay = peer.peerMessageDelay
			connectionDetails.OutgoingPeers = append(connectionDetails.OutgoingPeers, connDetail)
		} else {
			connDetail.Address = peer.OriginAddress()
			connectionDetails.IncomingPeers = append(connectionDetails.IncomingPeers, connDetail)
		}
	}
	return connectionDetails
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
	// the lastPeersChangeCounter is initialized with -1 in order to force the peers to be loaded on the first iteration.
	// then, it would get reloaded on per-need basis.
	lastPeersChangeCounter := int32(-1)
	for {
		select {
		case <-ticker.C:
		case <-wn.ctx.Done():
			return
		}

		if curPeersChangeCounter := wn.peersChangeCounter.Load(); curPeersChangeCounter != lastPeersChangeCounter {
			peers, lastPeersChangeCounter = wn.peerSnapshot(peers)
		}

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

// This logic assumes that the address suffixes
// correspond to the primary/backup network conventions. If this proves to be false, i.e. one network's
// suffix is a substring of another network's suffix, then duplicates can end up in the merged slice.
func (wn *WebsocketNetwork) mergePrimarySecondaryAddressSlices(
	primaryAddresses []string, secondaryAddresses []string, dedupExp *regexp.Regexp) (dedupedAddresses []string) {

	if dedupExp == nil {
		// No expression provided, so just append the slices without deduping
		return append(primaryAddresses, secondaryAddresses...)
	}

	var addressPrefixToValue = make(map[string]string, 2*len(primaryAddresses))

	for _, pra := range primaryAddresses {
		var normalizedPra = strings.ToLower(pra)

		var pfxKey = dedupExp.ReplaceAllString(normalizedPra, "")
		if _, exists := addressPrefixToValue[pfxKey]; !exists {
			addressPrefixToValue[pfxKey] = normalizedPra
		}
	}

	for _, sra := range secondaryAddresses {
		var normalizedSra = strings.ToLower(sra)
		var pfxKey = dedupExp.ReplaceAllString(normalizedSra, "")

		if _, exists := addressPrefixToValue[pfxKey]; !exists {
			addressPrefixToValue[pfxKey] = normalizedSra
		}
	}

	dedupedAddresses = make([]string, 0, len(addressPrefixToValue))
	for _, value := range addressPrefixToValue {
		dedupedAddresses = append(dedupedAddresses, value)
	}

	return
}

func (wn *WebsocketNetwork) getDNSAddrs(dnsBootstrap string) (relaysAddresses []string, archivalAddresses []string) {
	var err error
	relaysAddresses, err = wn.resolveSRVRecords(wn.ctx, "algobootstrap", "tcp", dnsBootstrap, wn.config.FallbackDNSResolverAddress, wn.config.DNSSecuritySRVEnforced())
	if err != nil {
		// only log this warning on testnet or devnet
		if wn.genesisInfo.NetworkID == config.Devnet || wn.genesisInfo.NetworkID == config.Testnet {
			wn.log.Warnf("Cannot lookup algobootstrap SRV record for %s: %v", dnsBootstrap, err)
		}
		relaysAddresses = nil
	}

	archivalAddresses, err = wn.resolveSRVRecords(wn.ctx, "archive", "tcp", dnsBootstrap, wn.config.FallbackDNSResolverAddress, wn.config.DNSSecuritySRVEnforced())
	if err != nil {
		// only log this warning on testnet or devnet
		if wn.genesisInfo.NetworkID == config.Devnet || wn.genesisInfo.NetworkID == config.Testnet {
			wn.log.Warnf("Cannot lookup archive SRV record for %s: %v", dnsBootstrap, err)
		}
		archivalAddresses = nil
	}
	return
}

// ProtocolVersionHeader HTTP header for network protocol version.
const ProtocolVersionHeader = "X-Algorand-Version"

// ProtocolAcceptVersionHeader HTTP header for accept network protocol version. Client use this to advertise supported protocol versions.
const ProtocolAcceptVersionHeader = "X-Algorand-Accept-Version"

// SupportedProtocolVersions contains the list of supported network protocol versions by this node ( in order of preference ).
var SupportedProtocolVersions = []string{"2.2"}

// ProtocolVersion is the current version attached to the ProtocolVersionHeader header
/* Version history:
 *  1   Catchup service over websocket connections with unicast messages between peers
 *  2.1 Introduced topic key/data pairs and enabled services over the gossip connections
 *  2.2 Peer features
 */
const ProtocolVersion = "2.2"

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

// IdentityChallengeHeader is used to exchange IdentityChallenges
const IdentityChallengeHeader = "X-Algorand-IdentityChallenge"

// TooManyRequestsRetryAfterHeader HTTP header let the client know when to make the next connection attempt
const TooManyRequestsRetryAfterHeader = "Retry-After"

// UserAgentHeader is the HTTP header identify the user agent.
const UserAgentHeader = "User-Agent"

// PeerFeaturesHeader is the HTTP header listing features
const PeerFeaturesHeader = "X-Algorand-Peer-Features"

// PeerFeatureProposalCompression is a value for PeerFeaturesHeader indicating peer
// supports proposal payload compression with zstd
const PeerFeatureProposalCompression = "ppzstd"

// PeerFeatureVoteVpackCompression is a value for PeerFeaturesHeader indicating peer
// supports agreement vote message compression with vpack
const PeerFeatureVoteVpackCompression = "avvpack"

var websocketsScheme = map[string]string{"http": "ws", "https": "wss"}

var errBadAddr = errors.New("bad address")

var errNetworkClosing = errors.New("WebsocketNetwork shutting down")

var errBcastCallerCancel = errors.New("caller cancelled broadcast")

var errBcastQFull = errors.New("broadcast queue full")

// tryConnectReserveAddr synchronously checks that addr is not already being connected to, returns (websocket URL or "", true if connection may proceed)
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

// tryConnectReleaseAddr should be called when connection succeeds and becomes a peer or fails and is no longer being attempted
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

// GetHTTPClient returns a http.Client with a suitable for the network Transport
// that would also limit the number of outgoing connections.
func (wn *WebsocketNetwork) GetHTTPClient(address string) (*http.Client, error) {
	url, err := addr.ParseHostOrURL(address)
	if err != nil {
		return nil, err
	}

	maxIdleConnsPerHost := int(wn.config.ConnectionsRateLimitingCount)
	rltr := limitcaller.MakeRateLimitingBoundTransport(wn.phonebook, limitcaller.DefaultQueueingTimeout, &wn.dialer, maxIdleConnsPerHost, url.Host)
	return &http.Client{
		Transport: &HTTPPAddressBoundTransport{
			address,
			&rltr,
		},
	}, nil
}

// HTTPPAddressBoundTransport is a http.RoundTripper that sets the scheme and host of the request URL to the given address
type HTTPPAddressBoundTransport struct {
	Addr           string
	InnerTransport http.RoundTripper
}

// RoundTrip implements http.RoundTripper by adding the schema, host, port, path prefix from the
// parsed address to the request URL and then calling the inner transport.
func (t *HTTPPAddressBoundTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	url, err := addr.ParseHostOrURL(t.Addr)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = url.Scheme
	req.URL.Host = url.Host
	req.URL.Path = path.Join(url.Path, req.URL.Path)
	return t.InnerTransport.RoundTrip(req)
}

// filterASCII filter out the non-ascii printable characters out of the given input string and
// and replace these with unprintableCharacterGlyph.
// It's used as a security qualifier before logging a network-provided data.
// The function allows only characters in the range of [32..126], which excludes all the
// control character, new lines, deletion, etc. All the alpha numeric and punctuation characters
// are included in this range.
func filterASCII(unfilteredString string) (filteredString string) {
	for _, r := range unfilteredString {
		if int(r) >= 0x20 && int(r) <= 0x7e {
			filteredString += string(r)
		} else {
			filteredString += unprintableCharacterGlyph
		}
	}
	return
}

// tryConnect opens websocket connection and checks initial connection parameters.
// netAddr should be 'host:port' or a URL, gossipAddr is the websocket endpoint URL
func (wn *WebsocketNetwork) tryConnect(netAddr, gossipAddr string) {
	defer wn.tryConnectReleaseAddr(netAddr, gossipAddr)
	defer func() {
		if xpanic := recover(); xpanic != nil {
			wn.log.Errorf("panic in tryConnect: %v", xpanic)
		}
	}()
	defer wn.wg.Done()

	requestHeader := make(http.Header)
	setHeaders(requestHeader, wn.protocolVersion, wn)

	var idChallenge identityChallengeValue
	if wn.identityScheme != nil {
		theirAddr := strings.ToLower(netAddr)
		idChallenge = wn.identityScheme.AttachChallenge(requestHeader, theirAddr)
	}

	SetUserAgentHeader(requestHeader)
	var websocketDialer = websocket.Dialer{
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  45 * time.Second,
		EnableCompression: false,
		NetDialContext:    wn.dialer.DialContext,
		NetDial:           wn.dialer.Dial,
		MaxHeaderSize:     wn.wsMaxHeaderBytes,
	}

	conn, response, err := websocketDialer.DialContext(wn.ctx, gossipAddr, requestHeader)

	if err != nil {
		if err == websocket.ErrBadHandshake {
			// reading here from ioutil is safe only because it came from DialContext above, which already finished reading all the data from the network
			// and placed it all in a ioutil.NopCloser reader.
			bodyBytes, _ := io.ReadAll(response.Body)
			errString := string(bodyBytes)
			if len(errString) > 128 {
				errString = errString[:128]
			}
			errString = filterASCII(errString)

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
					wn.phonebook.UpdateRetryAfter(netAddr, retryAfterTime)
				}
			default:
				wn.log.Warnf("ws connect(%s) fail - bad handshake, Status code = %d, Headers = %#v, Body = %s", gossipAddr, response.StatusCode, response.Header, errString)
			}
		} else {
			wn.log.Warnf("ws connect(%s) fail: %s", gossipAddr, err)
		}
		return
	}

	// if we abort before making a wsPeer this cleanup logic will close the connection
	closeEarly := func(msg string) {
		deadline := time.Now().Add(peerDisconnectionAckDuration)
		err2 := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseProtocolError, msg), deadline)
		if err2 != nil {
			wn.log.Infof("tryConnect: failed to write CloseMessage to connection for %s: %v", conn.RemoteAddr().String(), err2)
		}
		err2 = conn.CloseWithoutFlush()
		if err2 != nil {
			wn.log.Infof("tryConnect: failed to CloseWithoutFlush to connection for %s: %v", conn.RemoteAddr().String(), err2)
		}
	}

	// no need to test the response.StatusCode since we know it's going to be http.StatusSwitchingProtocols, as it's already being tested inside websocketDialer.DialContext.
	// we need to examine the headers here to extract which protocol version we should be using.
	responseHeaderOk, matchingVersion := wn.checkServerResponseVariables(response.Header, gossipAddr)
	if !responseHeaderOk {
		// The error was already logged, so no need to log again.
		closeEarly("Unsupported headers")
		return
	}
	localAddr, _ := wn.Address()

	var peerID crypto.PublicKey
	var idVerificationMessage []byte
	if wn.identityScheme != nil {
		// if the peer responded with an identity challenge response, but it can't be verified, don't proceed with peering
		peerID, idVerificationMessage, err = wn.identityScheme.VerifyResponse(response.Header, idChallenge)
		if err != nil {
			networkPeerIdentityError.Inc(nil)
			wn.log.With("err", err).With("remote", netAddr).With("local", localAddr).Warn("peer supplied an invalid identity response, abandoning peering")
			closeEarly("Invalid identity response")
			return
		}
	}

	throttledConnection := false
	if wn.throttledOutgoingConnections.Add(int32(-1)) >= 0 {
		throttledConnection = true
	} else {
		wn.throttledOutgoingConnections.Add(int32(1))
	}

	client, _ := wn.GetHTTPClient(netAddr)
	peer := &wsPeer{
		wsPeerCore:                  makePeerCore(wn.ctx, wn, wn.log, wn.handler.readBuffer, netAddr, client, "" /* origin */),
		conn:                        wsPeerWebsocketConnImpl{conn},
		outgoing:                    true,
		incomingMsgFilter:           wn.incomingMsgFilter,
		createTime:                  time.Now(),
		connMonitor:                 wn.connPerfMonitor,
		throttledOutgoingConnection: throttledConnection,
		version:                     matchingVersion,
		identity:                    peerID,
		features:                    decodePeerFeatures(matchingVersion, response.Header.Get(PeerFeaturesHeader)),
		enableVoteCompression:       wn.config.EnableVoteCompression,
	}
	peer.TelemetryGUID, peer.InstanceName, _ = getCommonHeaders(response.Header)

	// if there is a final verification message to send, it means this peer has a verified identity,
	// attempt to set the peer and identityTracker
	if len(idVerificationMessage) > 0 {
		peer.identityVerified.Store(uint32(1))
		wn.peersLock.Lock()
		ok := wn.identityTracker.setIdentity(peer)
		wn.peersLock.Unlock()
		if !ok {
			networkPeerIdentityDisconnect.Inc(nil)
			wn.log.With("remote", netAddr).With("local", localAddr).Warn("peer deduplicated before adding because the identity is already known")
			closeEarly("Duplicate connection")
			return
		}
	}
	peer.init(wn.config, wn.outgoingMessagesBufferSize)
	wn.addPeer(peer)

	wn.log.With("event", "ConnectedOut").With("remote", netAddr).With("local", localAddr).Infof("Made outgoing connection to peer %v", netAddr)
	wn.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerEvent,
		telemetryspec.PeerEventDetails{
			Address:       justHost(conn.RemoteAddr().String()),
			TelemetryGUID: peer.TelemetryGUID,
			Incoming:      false,
			InstanceName:  peer.InstanceName,
			Endpoint:      peer.GetAddress(),
		})

	wn.maybeSendMessagesOfInterest(peer, nil)

	// if there is a final identification verification message to send, send it to the peer
	if len(idVerificationMessage) > 0 {
		sent := peer.writeNonBlock(context.Background(), idVerificationMessage, true, crypto.Digest{}, time.Now())
		if !sent {
			wn.log.With("remote", netAddr).With("local", localAddr).Warn("could not send identity challenge verification")
		}
	}

	peers.Set(uint64(wn.NumPeers()))
	outgoingPeers.Set(uint64(wn.numOutgoingPeers()))

	if wn.prioScheme != nil {
		challenge := response.Header.Get(PriorityChallengeHeader)
		if challenge != "" {
			resp := wn.prioScheme.MakePrioResponse(challenge)
			if resp != nil {
				mbytes := append([]byte(protocol.NetPrioResponseTag), resp...)
				sent := peer.writeNonBlock(context.Background(), mbytes, true, crypto.Digest{}, time.Now())
				if !sent {
					wn.log.With("remote", netAddr).With("local", localAddr).Warnf("could not send priority response to %v", netAddr)
				}
			}
		}
	}
}

// GetPeerData returns the peer data associated with a particular key.
func (wn *WebsocketNetwork) GetPeerData(peer Peer, key string) interface{} {
	switch p := peer.(type) {
	case *wsPeer:
		return p.getPeerData(key)
	default:
		return nil
	}
}

// SetPeerData sets the peer data associated with a particular key.
func (wn *WebsocketNetwork) SetPeerData(peer Peer, key string, value interface{}) {
	switch p := peer.(type) {
	case *wsPeer:
		p.setPeerData(key, value)
	default:
		return
	}
}

// NewWebsocketNetwork constructor for websockets based gossip network
func NewWebsocketNetwork(log logging.Logger, config config.Local, phonebookAddresses []string, genesisInfo GenesisInfo, nodeInfo NodeInfo, identityOpts *identityOpts, meshCreator MeshCreator) (wn *WebsocketNetwork, err error) {
	pb := phonebook.MakePhonebook(config.ConnectionsRateLimitingCount,
		time.Duration(config.ConnectionsRateLimitingWindowSeconds)*time.Second)

	addresses := make([]string, 0, len(phonebookAddresses))
	for _, a := range phonebookAddresses {
		_, err0 := addr.ParseHostOrURL(a)
		if err0 == nil {
			addresses = append(addresses, a)
		}
	}
	pb.AddPersistentPeers(addresses, string(genesisInfo.NetworkID), phonebook.RelayRole)
	wn = &WebsocketNetwork{
		log:               log,
		config:            config,
		phonebook:         pb,
		genesisInfo:       genesisInfo,
		nodeInfo:          nodeInfo,
		resolveSRVRecords: tools_network.ReadFromSRV,
		meshCreator:       meshCreator,
		peerStater: peerConnectionStater{
			log:                           log,
			peerConnectionsUpdateInterval: time.Duration(config.PeerConnectionsUpdateInterval) * time.Second,
			lastPeerConnectionsSent:       time.Now(),
		},
	}

	// initialize net identity tracker either from the provided options or with a new one
	if identityOpts != nil {
		wn.identityScheme = identityOpts.scheme
		wn.identityTracker = identityOpts.tracker
	}
	if wn.identityTracker == nil {
		wn.identityTracker = NewIdentityTracker()
	}

	if err = wn.setup(); err != nil {
		return nil, err
	}
	return wn, nil
}

// NewWebsocketGossipNode constructs a websocket network node and returns it as a GossipNode interface implementation
func NewWebsocketGossipNode(log logging.Logger, config config.Local, phonebookAddresses []string, genesisID string, networkID protocol.NetworkID) (gn GossipNode, err error) {
	return NewWebsocketNetwork(log, config, phonebookAddresses, GenesisInfo{genesisID, networkID}, nil, nil, nil)
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
	logEntry := wn.log.With("event", "Disconnected").With("remote", peer.GetAddress()).With("local", localAddr)
	if peer.outgoing && peer.peerMessageDelay > 0 {
		logEntry = logEntry.With("messageDelay", peer.peerMessageDelay)
	}
	logEntry.Infof("Peer %s disconnected: %s", peer.GetAddress(), reason)
	peerAddr := peer.OriginAddress()
	// we might be able to get addr out of conn, or it might be closed
	if peerAddr == "" && peer.conn != nil {
		paddr := peer.conn.RemoteAddrString()
		if paddr != "" {
			peerAddr = justHost(paddr)
		}
	}
	if peerAddr == "" {
		// didn't get addr from peer, try from url
		url, err := url.Parse(peer.GetAddress())
		if err == nil {
			peerAddr = justHost(url.Host)
		} else {
			// use whatever it is
			peerAddr = justHost(peer.GetAddress())
		}
	}
	eventDetails := telemetryspec.PeerEventDetails{
		Address:       peerAddr,
		TelemetryGUID: peer.TelemetryGUID,
		Incoming:      !peer.outgoing,
		InstanceName:  peer.InstanceName,
	}
	if peer.outgoing {
		eventDetails.Endpoint = peer.GetAddress()
		eventDetails.MessageDelay = peer.peerMessageDelay
	}
	wn.log.EventWithDetails(telemetryspec.Network, telemetryspec.DisconnectPeerEvent,
		telemetryspec.DisconnectPeerEventDetails{
			PeerEventDetails: eventDetails,
			Reason:           string(reason),
			TXCount:          peer.txMessageCount.Load(),
			MICount:          peer.miMessageCount.Load(),
			AVCount:          peer.avMessageCount.Load(),
			PPCount:          peer.ppMessageCount.Load(),
		})

	peers.Set(uint64(wn.NumPeers()))
	incomingPeers.Set(uint64(wn.numIncomingPeers()))
	outgoingPeers.Set(uint64(wn.numOutgoingPeers()))

	wn.peersLock.Lock()
	defer wn.peersLock.Unlock()
	if peer.peerIndex < len(wn.peers) && wn.peers[peer.peerIndex] == peer {
		heap.Remove(peersHeap{wn}, peer.peerIndex)
		wn.prioTracker.removePeer(peer)
		wn.identityTracker.removeIdentity(peer)
		if peer.throttledOutgoingConnection {
			wn.throttledOutgoingConnections.Add(int32(1))
		}
		wn.peersChangeCounter.Add(1)
	}
	wn.countPeersSetGauges()
}

func (wn *WebsocketNetwork) addPeer(peer *wsPeer) {
	wn.peersLock.Lock()
	defer wn.peersLock.Unlock()
	// guard against peers which are closed or closing
	if peer.didSignalClose.Load() == 1 {
		networkPeerAlreadyClosed.Inc(nil)
		wn.log.Debugf("peer closing %s", peer.conn.RemoteAddrString())
		return
	}
	// simple duplicate *pointer* check. should never trigger given the callers to addPeer
	// TODO: remove this after making sure it is safe to do so
	if slices.Contains(wn.peers, peer) {
		wn.log.Errorf("dup peer added %#v", peer)
		return
	}
	heap.Push(peersHeap{wn}, peer)
	wn.prioTracker.setPriority(peer, peer.prioAddress, peer.prioWeight)
	wn.peersChangeCounter.Add(1)
	wn.countPeersSetGauges()
	if len(wn.peers) >= wn.config.GossipFanout {
		// we have a quorum of connected peers, if we weren't ready before, we are now
		if wn.ready.CompareAndSwap(0, 1) {
			wn.log.Debug("ready")
			close(wn.readyChan)
		}
	} else if wn.ready.Load() == 0 {
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
		if wn.ready.CompareAndSwap(0, 1) {
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
	networkIncomingConnections.Set(uint64(numIn))
	networkOutgoingConnections.Set(uint64(numOut))
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

// registerMessageInterest notifies the network library that this node
// wants to receive messages with the specified tag.  This will cause
// this node to send corresponding MsgOfInterest notifications to any
// newly connecting peers.  This should be called before the network
// is started.
func (wn *WebsocketNetwork) registerMessageInterest(t protocol.Tag) {
	wn.messagesOfInterestMu.Lock()
	defer wn.messagesOfInterestMu.Unlock()

	if wn.messagesOfInterest == nil {
		wn.messagesOfInterest = make(map[protocol.Tag]bool)
		maps.Copy(wn.messagesOfInterest, defaultSendMessageTags)
	}

	wn.messagesOfInterest[t] = true
	wn.updateMessagesOfInterestEnc()
}

// DeregisterMessageInterest will tell peers to no longer send us traffic with a protocol Tag
func (wn *WebsocketNetwork) DeregisterMessageInterest(t protocol.Tag) {
	wn.messagesOfInterestMu.Lock()
	defer wn.messagesOfInterestMu.Unlock()

	if wn.messagesOfInterest == nil {
		wn.messagesOfInterest = make(map[protocol.Tag]bool)
		maps.Copy(wn.messagesOfInterest, defaultSendMessageTags)
	}

	delete(wn.messagesOfInterest, t)
	wn.updateMessagesOfInterestEnc()
}

func (wn *WebsocketNetwork) updateMessagesOfInterestEnc() {
	// must run inside wn.messagesOfInterestMu.Lock
	wn.messagesOfInterestEnc = marshallMessageOfInterestMap(wn.messagesOfInterest)
	wn.messagesOfInterestEncoded = true
	wn.messagesOfInterestGeneration.Add(1)
	var peers []*wsPeer
	peers, _ = wn.peerSnapshot(peers)
	wn.log.Infof("updateMessagesOfInterestEnc maybe sending messagesOfInterest %v", wn.messagesOfInterest)
	for _, peer := range peers {
		wn.maybeSendMessagesOfInterest(peer, wn.messagesOfInterestEnc)
	}
}

func (wn *WebsocketNetwork) postMessagesOfInterestThread() {
	for {
		<-wn.messagesOfInterestRefresh
		// if we're not a relay, and not participating, we don't need txn pool
		wantTXGossip := wn.nodeInfo.IsParticipating()
		if wantTXGossip && (wn.wantTXGossip.Load() != wantTXGossipYes) {
			wn.log.Infof("postMessagesOfInterestThread: enabling TX gossip")
			wn.registerMessageInterest(protocol.TxnTag)
			wn.wantTXGossip.Store(wantTXGossipYes)
		} else if !wantTXGossip && (wn.wantTXGossip.Load() != wantTXGossipNo) {
			wn.log.Infof("postMessagesOfInterestThread: disabling TX gossip")
			wn.DeregisterMessageInterest(protocol.TxnTag)
			wn.wantTXGossip.Store(wantTXGossipNo)
		}
	}
}

// GetGenesisID returns the network-specific genesisID.
func (wn *WebsocketNetwork) GetGenesisID() string { return wn.genesisInfo.GenesisID }
