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
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/config"
	algocrypto "github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/network/limitcaller"
	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/network/p2p/dnsaddr"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
	"github.com/algorand/go-algorand/network/phonebook"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-deadlock"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// some arbitrary number TODO: figure out a better value based on peerSelector/fetcher algorithm
const numArchivalPeersToFind = 4

// disableV22Protocol is a flag for testing in order to test v1 node can communicate with v1 + v22 node
var disableV22Protocol = false

// P2PNetwork implements the GossipNode interface
type P2PNetwork struct {
	service     p2p.Service
	log         logging.Logger
	config      config.Local
	genesisInfo GenesisInfo
	// voteCompressionTableSize is the validated/normalized table size for VP compression.
	// It is set during setup() by validating config.StatefulVoteCompressionTableSize.
	voteCompressionTableSize uint
	ctx                      context.Context
	ctxCancel                context.CancelFunc
	peerStats                map[peer.ID]*p2pPeerStats
	peerStatsMu              deadlock.Mutex

	wg sync.WaitGroup

	// which tags to use with libp2p's GossipSub, mapped to topic names
	topicTags map[protocol.Tag]string

	// websockets message support
	handler                        msgHandler
	broadcaster                    msgBroadcaster
	wsPeers                        map[peer.ID]*wsPeer
	wsPeersToIDs                   map[*wsPeer]peer.ID
	wsPeersLock                    deadlock.RWMutex
	wsPeersChangeCounter           atomic.Int32
	wsPeersConnectivityCheckTicker *time.Ticker
	peerStater                     peerConnectionStater

	// connPerfMonitor is used on outgoing connections to measure their relative message timing
	connPerfMonitor *connectionPerformanceMonitor

	// outgoingConnsCloser used to check number of outgoing connections and disconnect as needed.
	// it is also used as a watchdog to help us detect connectivity issues ( such as cliques ) so that it monitors agreement protocol progress.
	outgoingConnsCloser *outgoingConnsCloser

	// number of throttled outgoing connections "slots" needed to be populated.
	throttledOutgoingConnections atomic.Int32

	meshUpdateRequests chan meshRequest
	mesher             mesher
	meshCreator        MeshCreator // save parameter to use in setup()

	relayMessages bool // True if we should relay messages from other nodes (nominally true for relays, false otherwise)
	wantTXGossip  atomic.Bool

	capabilitiesDiscovery *p2p.CapabilitiesDiscovery

	bootstrapperStart func()
	bootstrapperStop  func()
	nodeInfo          NodeInfo
	pstore            *peerstore.PeerStore
	httpServer        *p2p.HTTPServer

	identityTracker identityTracker

	// supportedProtocolVersions defines versions supported by this network.
	// Should be used instead of a global network.SupportedProtocolVersions for network/peers configuration
	supportedProtocolVersions []string

	// protocolVersion is an actual version announced as ProtocolVersionHeader
	protocolVersion string
}

type bootstrapper struct {
	cfg               config.Local
	networkID         protocol.NetworkID
	phonebookPeers    []*peer.AddrInfo
	resolveController dnsaddr.ResolveController
	started           atomic.Bool
	log               logging.Logger
}

func (b *bootstrapper) start() {
	b.started.Store(true)
}

func (b *bootstrapper) stop() {
	b.started.Store(false)
}

func (b *bootstrapper) BootstrapFunc() []peer.AddrInfo {
	// not started yet, do not give it any peers
	if !b.started.Load() {
		return nil
	}

	// have a list of peers, use them
	if len(b.phonebookPeers) > 0 {
		var addrs []peer.AddrInfo
		for _, bPeer := range b.phonebookPeers {
			if bPeer != nil {
				addrs = append(addrs, *bPeer)
			}
		}
		return addrs
	}

	return dnsLookupBootstrapPeers(b.log, b.cfg, b.networkID, b.resolveController)
}

// dnsLookupBootstrapPeers looks up a list of Multiaddrs strings from the dnsaddr records at the primary
// SRV record domain.
func dnsLookupBootstrapPeers(log logging.Logger, cfg config.Local, network protocol.NetworkID, controller dnsaddr.ResolveController) []peer.AddrInfo {
	var addrs []peer.AddrInfo
	bootstraps := cfg.DNSBootstrapArray(network)
	for _, dnsBootstrap := range bootstraps {
		var resolvedAddrs, resolvedAddrsBackup []multiaddr.Multiaddr
		var errPrim, errBackup error
		resolvedAddrs, errPrim = dnsaddr.MultiaddrsFromResolver(dnsBootstrap.PrimarySRVBootstrap, controller)
		if errPrim != nil {
			log.Infof("Failed to resolve bootstrap peers from %s: %v", dnsBootstrap.PrimarySRVBootstrap, errPrim)
		}
		if dnsBootstrap.BackupSRVBootstrap != "" {
			resolvedAddrsBackup, errBackup = dnsaddr.MultiaddrsFromResolver(dnsBootstrap.BackupSRVBootstrap, controller)
			if errBackup != nil {
				log.Infof("Failed to resolve bootstrap peers from %s: %v", dnsBootstrap.BackupSRVBootstrap, errBackup)
			}
		}

		if len(resolvedAddrs) > 0 || len(resolvedAddrsBackup) > 0 {
			resolvedAddrInfos := mergeP2PMultiaddrResolvedAddresses(resolvedAddrs, resolvedAddrsBackup)
			addrs = append(addrs, resolvedAddrInfos...)
		}
	}
	return addrs
}

func mergeP2PMultiaddrResolvedAddresses(primary, backup []multiaddr.Multiaddr) []peer.AddrInfo {
	// deduplicate addresses by PeerID
	unique := make(map[peer.ID]*peer.AddrInfo)
	for _, addr := range primary {
		info, err0 := peer.AddrInfoFromP2pAddr(addr)
		if err0 != nil {
			continue
		}
		unique[info.ID] = info
	}
	for _, addr := range backup {
		info, err0 := peer.AddrInfoFromP2pAddr(addr)
		if err0 != nil {
			continue
		}
		unique[info.ID] = info
	}
	var result []peer.AddrInfo
	for _, addr := range unique {
		result = append(result, *addr)
	}
	return result
}

func mergeP2PAddrInfoResolvedAddresses(primary, backup []peer.AddrInfo) []peer.AddrInfo {
	// deduplicate addresses by PeerID
	unique := make(map[peer.ID]peer.AddrInfo)
	for _, addr := range primary {
		unique[addr.ID] = addr
	}
	for _, addr := range backup {
		unique[addr.ID] = addr
	}
	var result []peer.AddrInfo
	for _, addr := range unique {
		result = append(result, addr)
	}
	return result
}

type p2pPeerStats struct {
	txReceived atomic.Uint64
}

// gossipSubTags defines protocol messages that are relayed using GossipSub
var gossipSubTags = map[protocol.Tag]string{
	protocol.TxnTag: p2p.TXTopicName,
}

// NewP2PNetwork returns an instance of GossipNode that uses the p2p.Service
func NewP2PNetwork(log logging.Logger, cfg config.Local, datadir string, phonebookAddresses []string, genesisInfo GenesisInfo, node NodeInfo, identityOpts *identityOpts, meshCreator MeshCreator) (*P2PNetwork, error) {
	const readBufferLen = 2048

	// create Peerstore and add phonebook addresses
	addrInfo, malformedAddrs := peerstore.PeerInfoFromAddrs(phonebookAddresses)
	for malAddr, malErr := range malformedAddrs {
		log.Infof("Ignoring malformed phonebook address %s: %s", malAddr, malErr)
	}
	pstore, err := peerstore.NewPeerStore(addrInfo, string(genesisInfo.NetworkID))
	if err != nil {
		return nil, err
	}

	relayMessages := cfg.IsGossipServer() || cfg.ForceRelayMessages
	net := &P2PNetwork{
		log:           log,
		config:        cfg,
		genesisInfo:   genesisInfo,
		topicTags:     gossipSubTags,
		wsPeers:       make(map[peer.ID]*wsPeer),
		wsPeersToIDs:  make(map[*wsPeer]peer.ID),
		peerStats:     make(map[peer.ID]*p2pPeerStats),
		nodeInfo:      node,
		pstore:        pstore,
		relayMessages: relayMessages,
		meshCreator:   meshCreator,
		peerStater: peerConnectionStater{
			log:                           log,
			peerConnectionsUpdateInterval: time.Duration(cfg.PeerConnectionsUpdateInterval) * time.Second,
			lastPeerConnectionsSent:       time.Now(),
		},
	}

	net.ctx, net.ctxCancel = context.WithCancel(context.Background())
	net.handler = msgHandler{
		ctx:        net.ctx,
		log:        log,
		config:     cfg,
		readBuffer: make(chan IncomingMessage, readBufferLen),
	}
	net.broadcaster = msgBroadcaster{
		ctx:                    net.ctx,
		log:                    log,
		config:                 cfg,
		broadcastQueueHighPrio: make(chan broadcastRequest, outgoingMessagesBufferSize),
		broadcastQueueBulk:     make(chan broadcastRequest, 100),
		enableVoteCompression:  cfg.EnableVoteCompression,
	}

	if identityOpts != nil {
		net.identityTracker = identityOpts.tracker
	}
	if net.identityTracker == nil {
		net.identityTracker = noopIdentityTracker{}
	}

	// set our supported versions
	if net.config.NetworkProtocolVersion != "" {
		net.supportedProtocolVersions = []string{net.config.NetworkProtocolVersion}
	} else {
		net.supportedProtocolVersions = SupportedProtocolVersions
	}

	// set our actual version
	net.protocolVersion = ProtocolVersion

	err = p2p.EnableP2PLogging(log, logging.Level(cfg.BaseLoggerDebugLevel))
	if err != nil {
		return nil, err
	}

	h, la, err := p2p.MakeHost(cfg, datadir, pstore)
	if err != nil {
		return nil, err
	}
	log.Infof("P2P host created: peer ID %s addrs %s", h.ID(), h.Addrs())

	var extraOpts networkConfig
	if meshCreator != nil {
		extraOpts = meshCreator.makeConfig(nil, net)
	}

	opts := append([]p2p.PubSubOption{p2p.SetPubSubMetricsTracer(pubsubMetricsTracer{})}, extraOpts.pubsubOpts...)

	// TODO: remove after consensus v41 takes effect.
	// ordered list of supported protocol versions
	hm := p2p.StreamHandlers{}
	if !disableV22Protocol {
		hm = append(hm, p2p.StreamHandlerPair{
			ProtoID: p2p.AlgorandWsProtocolV22,
			Handler: net.wsStreamHandlerV22,
		})
	}
	hm = append(hm, p2p.StreamHandlerPair{
		ProtoID: p2p.AlgorandWsProtocolV1,
		Handler: net.wsStreamHandlerV1,
	})
	// END TODO
	net.service, err = p2p.MakeService(net.ctx, log, cfg, h, la, hm, opts...)
	if err != nil {
		return nil, err
	}

	peerIDs := pstore.Peers()
	addrInfos := make([]*peer.AddrInfo, 0, len(peerIDs))
	for _, peerID := range peerIDs {
		addrInfo := pstore.PeerInfo(peerID)
		addrInfos = append(addrInfos, &addrInfo)
	}
	bootstrapper := &bootstrapper{
		cfg:               cfg,
		networkID:         net.genesisInfo.NetworkID,
		phonebookPeers:    addrInfos,
		resolveController: dnsaddr.NewMultiaddrDNSResolveController(cfg.DNSSecurityTXTEnforced(), ""),
		log:               net.log,
	}
	net.bootstrapperStart = bootstrapper.start
	net.bootstrapperStop = bootstrapper.stop

	if cfg.EnableDHTProviders {
		disc, err0 := p2p.MakeCapabilitiesDiscovery(net.ctx, cfg, h, net.genesisInfo.NetworkID, net.log, bootstrapper.BootstrapFunc)
		if err0 != nil {
			log.Errorf("Failed to create dht node capabilities discovery: %v", err0)
			return nil, err0
		}
		net.capabilitiesDiscovery = disc
	}

	net.httpServer = p2p.MakeHTTPServer(h)

	if err = net.setup(); err != nil {
		return nil, err
	}

	return net, nil
}

func (n *P2PNetwork) setup() error {
	// Validate and normalize vote compression table size
	n.voteCompressionTableSize = n.config.NormalizedVoteCompressionTableSize(n.log)

	if n.broadcaster.slowWritingPeerMonitorInterval == 0 {
		n.broadcaster.slowWritingPeerMonitorInterval = slowWritingPeerMonitorInterval
	}
	n.meshUpdateRequests = make(chan meshRequest, 5)
	meshCreator := n.meshCreator
	if meshCreator == nil {
		meshCreator = baseMeshCreator{}
	}
	var err error
	n.mesher, err = meshCreator.create(
		withContext(n.ctx),
		withTargetConnCount(n.config.GossipFanout),
		withMeshExpJitterBackoff(),
		withMeshNetMeshFn(n.meshThreadInner),
		withMeshPeerStatReporter(func() {
			n.peerStater.sendPeerConnectionsTelemetryStatus(n)
		}),
		withMeshUpdateRequest(n.meshUpdateRequests),
		withMeshUpdateInterval(meshThreadInterval),
	)
	if err != nil {
		return fmt.Errorf("failed to create mesh: %w", err)
	}

	n.connPerfMonitor = makeConnectionPerformanceMonitor([]Tag{protocol.AgreementVoteTag, protocol.TxnTag})
	n.outgoingConnsCloser = makeOutgoingConnsCloser(n.log, n, n.connPerfMonitor, cliqueResolveInterval)

	return nil
}

func (n *P2PNetwork) outgoingPeers() (peers []Peer) {
	n.wsPeersLock.RLock()
	defer n.wsPeersLock.RUnlock()
	for _, peer := range n.wsPeers {
		if peer.outgoing {
			peers = append(peers, Peer(peer))
		}
	}
	return peers
}

func (n *P2PNetwork) numOutgoingPending() int {
	return 0
}

// PeerID returns this node's peer ID.
func (n *P2PNetwork) PeerID() p2p.PeerID {
	return p2p.PeerID(n.service.ID())
}

// PeerIDSigner returns an identityChallengeSigner that uses the libp2p peer ID's private key.
func (n *P2PNetwork) PeerIDSigner() identityChallengeSigner {
	return n.service.IDSigner()
}

// Start threads, listen on sockets.
func (n *P2PNetwork) Start() error {
	n.bootstrapperStart()
	err := n.service.Start()
	if err != nil {
		return err
	}

	if n.relayMessages {
		n.throttledOutgoingConnections.Store(int32(n.config.GossipFanout / 2))
	} else {
		// on non-relay, all the outgoing connections are throttled.
		n.throttledOutgoingConnections.Store(int32(n.config.GossipFanout))
	}
	if n.config.DisableOutgoingConnectionThrottling {
		n.throttledOutgoingConnections.Store(0)
	}

	wantTXGossip := n.relayMessages || n.config.ForceFetchTransactions || n.nodeInfo.IsParticipating()
	if wantTXGossip {
		n.wantTXGossip.Store(true)
		n.wg.Add(1)
		go n.txTopicHandleLoop()
	}

	if n.wsPeersConnectivityCheckTicker != nil {
		n.wsPeersConnectivityCheckTicker.Stop()
	}
	n.wsPeersConnectivityCheckTicker = time.NewTicker(connectionActivityMonitorInterval)
	for i := 0; i < incomingThreads; i++ {
		n.wg.Add(1)
		// We pass the peersConnectivityCheckTicker.C here so that we don't need to syncronize the access to the ticker's data structure.
		go n.handler.messageHandlerThread(&n.wg, n.wsPeersConnectivityCheckTicker.C, n, "network", "P2PNetwork")
	}

	// start the HTTP server if configured to listen
	if n.config.NetAddress != "" {
		n.wg.Add(1)
		go n.httpdThread()
	}

	n.wg.Add(1)
	go n.broadcaster.broadcastThread(&n.wg, n, "network", "P2PNetwork")

	n.meshUpdateRequests <- meshRequest{}
	n.mesher.start()

	if n.capabilitiesDiscovery != nil {
		n.capabilitiesDiscovery.AdvertiseCapabilities(n.nodeInfo.Capabilities()...)
	}

	return nil
}

// Stop closes sockets and stop threads.
func (n *P2PNetwork) Stop() {
	if n.capabilitiesDiscovery != nil {
		err := n.capabilitiesDiscovery.Close()
		if err != nil {
			n.log.Warnf("Error closing capabilities discovery: %v", err)
		}
	}

	n.handler.ClearHandlers([]Tag{})
	if n.wsPeersConnectivityCheckTicker != nil {
		n.wsPeersConnectivityCheckTicker.Stop()
		n.wsPeersConnectivityCheckTicker = nil
	}
	n.innerStop()

	// This is a workaround for a race between PubSub.processLoop (triggered by context cancellation below) termination
	// and this function returning that causes main goroutine to exit before
	// PubSub.processLoop goroutine finishes logging its termination message
	// to already closed logger. Not seen in wild, only in tests.
	if n.log.GetLevel() >= logging.Warn {
		_ = p2p.SetP2PLogLevel(logging.Warn)
	}
	n.ctxCancel()

	n.service.Close()
	n.bootstrapperStop()
	n.httpServer.Close()
	n.mesher.stop()
	n.wg.Wait()
}

// innerStop context for shutting down peers
func (n *P2PNetwork) innerStop() {
	closeGroup := sync.WaitGroup{}
	n.wsPeersLock.Lock()
	closeGroup.Add(len(n.wsPeers))
	deadline := time.Now().Add(peerDisconnectionAckDuration)
	for peerID, peer := range n.wsPeers {
		// we need to both close the wsPeer and close the p2p connection
		go closeWaiter(&closeGroup, peer, deadline)
		err := n.service.ClosePeer(peerID)
		if err != nil {
			n.log.Warnf("Error closing peer %s: %v", peerID, err)
		}
		delete(n.wsPeers, peerID)
		delete(n.wsPeersToIDs, peer)
	}
	n.wsPeersLock.Unlock()
	closeGroup.Wait()
}

func (n *P2PNetwork) refreshPeerStoreAddresses() {
	// fetch peers from DNS
	var dnsPeers, dhtPeers []peer.AddrInfo
	dnsPeers = dnsLookupBootstrapPeers(n.log, n.config, n.genesisInfo.NetworkID, dnsaddr.NewMultiaddrDNSResolveController(n.config.DNSSecurityTXTEnforced(), ""))

	// discover peers from DHT
	if n.capabilitiesDiscovery != nil {
		var err error
		dhtPeers, err = n.capabilitiesDiscovery.PeersForCapability(p2p.Gossip, n.config.GossipFanout)
		if err != nil {
			n.log.Warnf("Error getting relay nodes from capabilities discovery: %v", err)
		}
		n.log.Debugf("Discovered %d gossip peers from DHT", len(dhtPeers))

		// also discover archival nodes
		var dhtArchivalPeers []peer.AddrInfo
		dhtArchivalPeers, err = n.capabilitiesDiscovery.PeersForCapability(p2p.Archival, numArchivalPeersToFind)
		if err != nil {
			n.log.Warnf("Error getting archival nodes from capabilities discovery: %v", err)
		}
		n.log.Debugf("Discovered %d archival peers from DHT", len(dhtArchivalPeers))

		if len(dhtArchivalPeers) > 0 {
			replace := make([]*peer.AddrInfo, len(dhtArchivalPeers))
			for i := range dhtArchivalPeers {
				replace[i] = &dhtArchivalPeers[i]
			}
			n.pstore.ReplacePeerList(replace, string(n.genesisInfo.NetworkID), phonebook.ArchivalRole)
		}
	}

	peers := mergeP2PAddrInfoResolvedAddresses(dnsPeers, dhtPeers)
	replace := make([]*peer.AddrInfo, len(peers))
	for i := range peers {
		replace[i] = &peers[i]
	}
	if len(peers) > 0 {
		n.pstore.ReplacePeerList(replace, string(n.genesisInfo.NetworkID), phonebook.RelayRole)
	}
}

// meshThreadInner fetches nodes from DHT and attempts to connect to them.
// It returns the number of peers connected.
func (n *P2PNetwork) meshThreadInner(targetConnCount int) int {
	n.refreshPeerStoreAddresses()
	for { //nolint:staticcheck // easier to read
		if n.service.DialPeersUntilTargetCount(targetConnCount) {
			break
		}
		if !n.outgoingConnsCloser.checkExistingConnectionsNeedDisconnecting(targetConnCount) {
			// no connection were removed.
			break
		}
	}

	return len(n.outgoingPeers())
}

func (n *P2PNetwork) httpdThread() {
	defer n.wg.Done()

	err := n.httpServer.Serve()
	if err != nil {
		n.log.Errorf("Error serving libp2phttp: %v", err)
		return
	}
}

// GetGenesisID implements GossipNode
func (n *P2PNetwork) GetGenesisID() string {
	return n.genesisInfo.GenesisID
}

// Address returns a string and whether that is a 'final' address or guessed.
func (n *P2PNetwork) Address() (string, bool) {
	addrInfo := n.service.AddrInfo()
	if len(addrInfo.Addrs) == 0 {
		return "", false
	}
	addrs, err := peer.AddrInfoToP2pAddrs(&addrInfo)
	if err != nil {
		n.log.Warnf("Failed to generate valid multiaddr: %v", err)
		return "", false
	}
	// loop through and see if we have a non loopback address available
	for _, addr := range addrs {
		if !manet.IsIPLoopback(addr) && !manet.IsIPUnspecified(addr) {
			return addr.String(), true
		}
	}
	// We don't have a non loopback address, so just return the first one if it contains an ip4 address or port
	addr := addrs[0].String()
	if strings.Contains(addr, "/ip4/") && strings.Contains(addr, "/tcp/") {
		return addr, true

	}
	return "", false

}

// Broadcast sends a message.
func (n *P2PNetwork) Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error {
	// For tags using pubsub topics, publish to GossipSub
	if topic, ok := n.topicTags[tag]; ok {
		return n.service.Publish(ctx, topic, data)
	}
	// Otherwise broadcast over websocket protocol stream
	return n.broadcaster.broadcast(ctx, tag, data, wait, except)
}

// Relay message
func (n *P2PNetwork) Relay(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error {
	if n.relayMessages {
		return n.Broadcast(ctx, tag, data, wait, except)
	}
	return nil
}

// Disconnect from a peer, probably due to protocol errors.
func (n *P2PNetwork) Disconnect(badpeer DisconnectablePeer) {
	n.disconnect(badpeer, disconnectReasonNone)
}

func (n *P2PNetwork) disconnect(badpeer Peer, reason disconnectReason) {
	var peerID peer.ID
	var wsp *wsPeer

	switch p := badpeer.(type) {
	case *wsPeer: // Disconnect came from a message received via wsPeer
		n.wsPeersLock.RLock()
		peerID, wsp = n.wsPeersToIDs[p], p
		n.wsPeersLock.RUnlock()
	default:
		n.log.Warnf("Unknown peer type %T", badpeer)
		return
	}
	if wsp != nil {
		wsp.CloseAndWait(time.Now().Add(peerDisconnectionAckDuration))
		n.removePeer(wsp, peerID, reason)
	} else {
		n.log.Warnf("Could not find wsPeer reference for peer %s", peerID)
	}
	err := n.service.ClosePeer(peerID)
	if err != nil {
		n.log.Warnf("Error disconnecting from peer %s: %v", peerID, err)
	}
}

func (n *P2PNetwork) disconnectThread(badnode DisconnectablePeer, reason disconnectReason) {
	defer n.wg.Done()
	n.Disconnect(badnode) // ignores reason
}

// DisconnectPeers is used by testing
func (n *P2PNetwork) DisconnectPeers() {
	for _, conn := range n.service.Conns() {
		conn.Close()
	}
}

// RegisterHTTPHandler path accepts gorilla/mux path annotations
func (n *P2PNetwork) RegisterHTTPHandler(path string, handler http.Handler) {
	n.httpServer.RegisterHTTPHandler(path, handler)
}

// RegisterHTTPHandlerFunc is like RegisterHTTPHandler but accepts
// a callback handler function instead of a method receiver.
func (n *P2PNetwork) RegisterHTTPHandlerFunc(path string, handler func(http.ResponseWriter, *http.Request)) {
	n.httpServer.RegisterHTTPHandlerFunc(path, handler)
}

// RequestConnectOutgoing asks the system to actually connect to peers.
// `replace` optionally drops existing connections before making new ones.
// `quit` chan allows cancellation.
func (n *P2PNetwork) RequestConnectOutgoing(replace bool, quit <-chan struct{}) {
	request := meshRequest{}
	if quit != nil {
		request.done = make(chan struct{})
	}
	select {
	case n.meshUpdateRequests <- request:
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

func addrInfoToWsPeerCore(n *P2PNetwork, addrInfo *peer.AddrInfo) (wsPeerCore, bool) {
	mas, err := peer.AddrInfoToP2pAddrs(addrInfo)
	if err != nil {
		n.log.Warnf("Archival AddrInfo conversion error: %v", err)
		return wsPeerCore{}, false
	}
	if len(mas) == 0 {
		n.log.Warnf("Archival AddrInfo: empty multiaddr for : %v", addrInfo)
		return wsPeerCore{}, false
	}
	addr := mas[0].String()

	client, err := n.service.GetHTTPClient(addrInfo, n.pstore, limitcaller.DefaultQueueingTimeout)
	if err != nil {
		n.log.Warnf("MakeHTTPClient failed: %v", err)
		return wsPeerCore{}, false
	}

	peerCore := makePeerCore(
		n.ctx, n, n.log, n.handler.readBuffer,
		addr, client, "", /*origin address*/
	)
	return peerCore, true
}

// GetPeers returns a list of Peers we could potentially send a direct message to.
func (n *P2PNetwork) GetPeers(options ...PeerOption) []Peer {
	peers := make([]Peer, 0)
	for _, option := range options {
		switch option {
		case PeersConnectedOut:
			n.wsPeersLock.RLock()
			for _, peer := range n.wsPeers {
				if peer.outgoing {
					peers = append(peers, Peer(peer))
				}
			}
			n.wsPeersLock.RUnlock()
		case PeersPhonebookRelays:
			const maxNodes = 100
			addrInfos := n.pstore.GetAddresses(maxNodes, phonebook.RelayRole)
			for _, peerInfo := range addrInfos {
				if peerInfo.ID == n.service.ID() {
					continue
				}
				if peerCore, ok := addrInfoToWsPeerCore(n, peerInfo); ok {
					peers = append(peers, &peerCore)
				}
			}
			if n.log.GetLevel() >= logging.Debug && len(peers) > 0 {
				addrs := make([]string, 0, len(peers))
				for _, peer := range peers {
					addrs = append(addrs, peer.(*wsPeerCore).GetAddress())
				}
				n.log.Debugf("Relay node(s) from peerstore: %v", addrs)
			}
		case PeersPhonebookArchivalNodes:
			// query known archival nodes that came from DHT if enabled (or DNS if configured)
			addrInfos := n.pstore.GetAddresses(numArchivalPeersToFind, phonebook.ArchivalRole)
			for _, peerInfo := range addrInfos {
				if peerInfo.ID == n.service.ID() {
					continue
				}
				if peerCore, ok := addrInfoToWsPeerCore(n, peerInfo); ok {
					peers = append(peers, &peerCore)
				}
			}
			if n.log.GetLevel() >= logging.Debug && len(peers) > 0 {
				addrs := make([]string, 0, len(peers))
				for _, peer := range peers {
					addrs = append(addrs, peer.(*wsPeerCore).GetAddress())
				}
				n.log.Debugf("Archival node(s) from peerstore: %v", addrs)
			}
		case PeersConnectedIn:
			n.wsPeersLock.RLock()
			for _, peer := range n.wsPeers {
				if !peer.outgoing {
					peers = append(peers, Peer(peer))
				}
			}
			n.wsPeersLock.RUnlock()
		}
	}
	return peers
}

// RegisterHandlers adds to the set of given message handlers.
func (n *P2PNetwork) RegisterHandlers(dispatch []TaggedMessageHandler) {
	n.handler.RegisterHandlers(dispatch)
}

// ClearHandlers deregisters all the existing message handlers.
func (n *P2PNetwork) ClearHandlers() {
	n.handler.ClearHandlers([]Tag{})
}

// RegisterValidatorHandlers adds to the set of given message handlers.
func (n *P2PNetwork) RegisterValidatorHandlers(dispatch []TaggedMessageValidatorHandler) {
	n.handler.RegisterValidatorHandlers(dispatch)
}

// ClearValidatorHandlers deregisters all the existing message handlers.
func (n *P2PNetwork) ClearValidatorHandlers() {
	n.handler.ClearValidatorHandlers([]Tag{})
}

// GetHTTPClient returns a http.Client with a suitable for the network Transport
// that would also limit the number of outgoing connections.
func (n *P2PNetwork) GetHTTPClient(address string) (*http.Client, error) {
	addrInfo, err := peer.AddrInfoFromString(address)
	if err != nil {
		return nil, err
	}
	return n.service.GetHTTPClient(addrInfo, n.pstore, limitcaller.DefaultQueueingTimeout)
}

// OnNetworkAdvance notifies the network library that the agreement protocol was able to make a notable progress.
// this is the only indication that we have that we haven't formed a clique, where all incoming messages
// arrive very quickly, but might be missing some votes. The usage of this call is expected to have similar
// characteristics as with a watchdog timer.
func (n *P2PNetwork) OnNetworkAdvance() {
	n.outgoingConnsCloser.updateLastAdvance()
	if n.nodeInfo != nil {
		old := n.wantTXGossip.Load()
		new := n.relayMessages || n.config.ForceFetchTransactions || n.nodeInfo.IsParticipating()
		if old != new {
			n.wantTXGossip.Store(new)
			if new {
				n.wg.Add(1)
				go n.txTopicHandleLoop()
			}
		}
	}
}

// TelemetryGUID returns the telemetry GUID of this node.
func (n *P2PNetwork) TelemetryGUID() string {
	return ""
}

// InstanceName returns the instance name of this node.
func (n *P2PNetwork) InstanceName() string {
	return ""
}

// SupportedProtoVersions returns the supported protocol versions of this node.
func (n *P2PNetwork) SupportedProtoVersions() []string {
	return n.supportedProtocolVersions
}

// RandomID satisfies the interface but is not used in P2PNetwork.
func (n *P2PNetwork) RandomID() string {
	return ""
}

// PublicAddress satisfies the interface but is not used in P2PNetwork.
func (n *P2PNetwork) PublicAddress() string {
	return ""
}

// Config returns the configuration of this node.
func (n *P2PNetwork) Config() config.Local {
	return n.config
}

// StatefulVoteCompressionTableSize returns the validated/normalized vote compression table size.
func (n *P2PNetwork) StatefulVoteCompressionTableSize() uint {
	return n.voteCompressionTableSize
}

// VoteCompressionEnabled returns whether vote compression is enabled for this node.
func (n *P2PNetwork) VoteCompressionEnabled() bool {
	return n.config.EnableVoteCompression
}

// wsStreamHandler is a callback that the p2p package calls when a new peer connects and establishes a
// stream for the websocket protocol.
// TODO: remove after consensus v41 takes effect.
func (n *P2PNetwork) wsStreamHandlerV1(ctx context.Context, p2pPeer peer.ID, stream network.Stream, incoming bool) {
	if stream.Protocol() != p2p.AlgorandWsProtocolV1 {
		n.log.Warnf("unknown protocol %s from peer %s", stream.Protocol(), p2pPeer)
		return
	}

	if incoming {
		var initMsg [1]byte
		rn, err := stream.Read(initMsg[:])
		if rn == 0 || err != nil {
			n.log.Warnf("wsStreamHandlerV1: error reading initial message from peer %s (%s): %v", p2pPeer, stream.Conn().RemoteMultiaddr().String(), err)
			return
		}
	} else {
		_, err := stream.Write([]byte("1"))
		if err != nil {
			n.log.Warnf("wsStreamHandlerV1: error sending initial message: %v", err)
			return
		}
	}

	n.baseWsStreamHandler(ctx, p2pPeer, stream, incoming, peerMetaInfo{})
}

func (n *P2PNetwork) wsStreamHandlerV22(ctx context.Context, p2pPeer peer.ID, stream network.Stream, incoming bool) {
	if stream.Protocol() != p2p.AlgorandWsProtocolV22 {
		n.log.Warnf("unknown protocol %s from peer%s", stream.Protocol(), p2pPeer)
		return
	}

	var err error
	var pmi peerMetaInfo
	if incoming {
		pmi, err = readPeerMetaHeaders(stream, p2pPeer, n.supportedProtocolVersions)
		if err != nil {
			n.log.Warnf("wsStreamHandlerV22: error reading peer meta headers response from peer %s (%s): %v", p2pPeer, stream.Conn().RemoteMultiaddr().String(), err)
			_ = stream.Reset()
			return
		}
		err = writePeerMetaHeaders(stream, p2pPeer, pmi.version, n)
		if err != nil {
			n.log.Warnf("wsStreamHandlerV22: error writing peer meta headers response to peer %s (%s): %v", p2pPeer, stream.Conn().RemoteMultiaddr().String(), err)
			_ = stream.Reset()
			return
		}
	} else {
		err = writePeerMetaHeaders(stream, p2pPeer, n.protocolVersion, n)
		if err != nil {
			n.log.Warnf("wsStreamHandlerV22: error writing peer meta headers response to peer %s (%s): %v", p2pPeer, stream.Conn().RemoteMultiaddr().String(), err)
			_ = stream.Reset()
			return
		}
		// read the response
		pmi, err = readPeerMetaHeaders(stream, p2pPeer, n.supportedProtocolVersions)
		if err != nil {
			n.log.Warnf("wsStreamHandlerV22: error reading peer meta headers response from peer %s (%s): %v", p2pPeer, stream.Conn().RemoteMultiaddr().String(), err)
			_ = stream.Reset()
			return
		}
	}
	n.baseWsStreamHandler(ctx, p2pPeer, stream, incoming, pmi)
}

func (n *P2PNetwork) baseWsStreamHandler(ctx context.Context, p2pPeer peer.ID, stream network.Stream, incoming bool, pmi peerMetaInfo) {
	// get address for peer ID
	ma := stream.Conn().RemoteMultiaddr()
	addr := ma.String()
	if addr == "" {
		n.log.Warnf("Cannot get address for peer %s", p2pPeer)
	}

	// create a wsPeer for this stream and added it to the peers map.
	addrInfo := &peer.AddrInfo{ID: p2pPeer, Addrs: []multiaddr.Multiaddr{ma}}
	client, err := n.service.GetHTTPClient(addrInfo, n.pstore, limitcaller.DefaultQueueingTimeout)
	if err != nil {
		n.log.Warnf("Cannot construct HTTP Client for %s: %v", p2pPeer, err)
		client = nil
	}
	var netIdentPeerID algocrypto.PublicKey
	if p2pPeerPubKey, err0 := p2pPeer.ExtractPublicKey(); err0 == nil {
		if b, err0 := p2pPeerPubKey.Raw(); err0 == nil {
			netIdentPeerID = algocrypto.PublicKey(b)
		} else {
			n.log.Warnf("Cannot get raw pubkey for peer %s", p2pPeer)
		}
	} else {
		n.log.Warnf("Cannot get pubkey for peer %s", p2pPeer)
	}
	peerCore := makePeerCore(ctx, n, n.log, n.handler.readBuffer, addr, client, addr)
	wsp := &wsPeer{
		wsPeerCore:               peerCore,
		conn:                     &wsPeerConnP2P{stream: stream},
		outgoing:                 !incoming,
		identity:                 netIdentPeerID,
		peerType:                 peerTypeP2P,
		TelemetryGUID:            pmi.telemetryID,
		InstanceName:             pmi.instanceName,
		features:                 decodePeerFeatures(pmi.version, pmi.features),
		enableVoteCompression:    n.config.EnableVoteCompression,
		voteCompressionTableSize: n.voteCompressionTableSize,
	}
	if !incoming {
		throttledConnection := false
		if n.throttledOutgoingConnections.Add(int32(-1)) >= 0 {
			throttledConnection = true
		} else {
			n.throttledOutgoingConnections.Add(int32(1))
		}

		wsp.connMonitor = n.connPerfMonitor
		wsp.throttledOutgoingConnection = throttledConnection
	}

	localAddr, has := n.Address()
	if !has {
		n.log.Warn("Could not get local address")
	}
	n.wsPeersLock.Lock()
	ok := n.identityTracker.setIdentity(wsp)
	n.wsPeersLock.Unlock()
	if !ok {
		networkPeerIdentityDisconnect.Inc(nil)
		n.log.With("remote", addr).With("local", localAddr).Warn("peer deduplicated before adding because the identity is already known")
		stream.Close()
		return
	}

	wsp.init(n.config, outgoingMessagesBufferSize)
	n.wsPeersLock.Lock()
	if wsp.didSignalClose.Load() == 1 {
		networkPeerAlreadyClosed.Inc(nil)
		n.log.Debugf("peer closing %s", addr)
		n.wsPeersLock.Unlock()
		return
	}
	n.wsPeers[p2pPeer] = wsp
	n.wsPeersToIDs[wsp] = p2pPeer
	n.wsPeersLock.Unlock()
	n.wsPeersChangeCounter.Add(1)

	event := "ConnectedOut"
	msg := "Made outgoing connection to peer %s"
	if incoming {
		event = "ConnectedIn"
		msg = "Accepted incoming connection from peer %s"
	}
	n.log.With("event", event).With("remote", addr).With("local", localAddr).Infof(msg, p2pPeer.String())

	if n.log.GetLevel() >= logging.Debug {
		n.log.Debugf("streams for %s conn %s ", stream.Conn().Stat().Direction.String(), stream.Conn().ID())
		for _, s := range stream.Conn().GetStreams() {
			n.log.Debugf("%s stream %s protocol %s", s.Stat().Direction.String(), s.ID(), s.Protocol())
		}
	}
	n.log.EventWithDetails(telemetryspec.Network, telemetryspec.ConnectPeerEvent,
		telemetryspec.PeerEventDetails{
			Address:       addr,
			TelemetryGUID: wsp.TelemetryGUID,
			Incoming:      incoming,
			InstanceName:  wsp.InstanceName,
		})
}

// peerRemoteClose called from wsPeer to report that it has closed
func (n *P2PNetwork) peerRemoteClose(peer *wsPeer, reason disconnectReason) {
	remotePeerID := peer.conn.(*wsPeerConnP2P).stream.Conn().RemotePeer()
	n.removePeer(peer, remotePeerID, reason)
}

func (n *P2PNetwork) removePeer(peer *wsPeer, remotePeerID peer.ID, reason disconnectReason) {
	n.wsPeersLock.Lock()
	n.identityTracker.removeIdentity(peer)
	delete(n.wsPeers, remotePeerID)
	delete(n.wsPeersToIDs, peer)
	n.wsPeersLock.Unlock()
	n.wsPeersChangeCounter.Add(1)

	eventDetails := telemetryspec.PeerEventDetails{
		Address:       peer.GetAddress(), // p2p peers store p2p addresses
		TelemetryGUID: peer.TelemetryGUID,
		InstanceName:  peer.InstanceName,
		Incoming:      !peer.outgoing,
	}
	if peer.outgoing {
		eventDetails.Endpoint = peer.GetAddress()
		eventDetails.MessageDelay = peer.peerMessageDelay
	}

	n.log.EventWithDetails(telemetryspec.Network, telemetryspec.DisconnectPeerEvent,
		telemetryspec.DisconnectPeerEventDetails{
			PeerEventDetails: eventDetails,
			Reason:           string(reason),
			TXCount:          peer.txMessageCount.Load(),
			MICount:          peer.miMessageCount.Load(),
			AVCount:          peer.avMessageCount.Load(),
			PPCount:          peer.ppMessageCount.Load(),
		})
	if peer.throttledOutgoingConnection {
		n.throttledOutgoingConnections.Add(int32(1))
	}
}

func (n *P2PNetwork) peerSnapshot(dest []*wsPeer) ([]*wsPeer, int32) {
	n.wsPeersLock.RLock()
	defer n.wsPeersLock.RUnlock()
	// based on wn.peerSnapshot
	if cap(dest) >= len(n.wsPeers) {
		toClear := dest[len(n.wsPeers):cap(dest)]
		for i := range toClear {
			if toClear[i] == nil {
				break
			}
			toClear[i] = nil
		}
		dest = dest[:len(n.wsPeers)]
	} else {
		dest = make([]*wsPeer, len(n.wsPeers))
	}
	i := 0
	for _, p := range n.wsPeers {
		dest[i] = p
		i++
	}
	return dest, n.getPeersChangeCounter()
}

func (n *P2PNetwork) getPeersChangeCounter() int32 {
	return n.wsPeersChangeCounter.Load()
}

func (n *P2PNetwork) checkSlowWritingPeers()  {}
func (n *P2PNetwork) checkPeersConnectivity() {}

// txTopicHandleLoop reads messages from the pubsub topic for transactions.
func (n *P2PNetwork) txTopicHandleLoop() {
	defer n.wg.Done()
	sub, err := n.service.Subscribe(p2p.TXTopicName, n.txTopicValidator)
	if err != nil {
		n.log.Errorf("Failed to subscribe to topic %s: %v", p2p.TXTopicName, err)
		return
	}
	n.log.Debugf("Subscribed to topic %s", p2p.TXTopicName)

	const threads = incomingThreads / 2 // perf tests showed that 10 (half of incomingThreads) was optimal in terms of TPS (attempted 1, 5, 10, 20)
	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func(ctx context.Context, sub p2p.SubNextCancellable, wantTXGossip *atomic.Bool, peerID peer.ID, log logging.Logger) {
			defer wg.Done()
			for {
				// msg from sub.Next not used since all work done by txTopicValidator
				_, err := sub.Next(ctx)
				if err != nil {
					if err != pubsub.ErrSubscriptionCancelled && err != context.Canceled {
						log.Errorf("Error reading from subscription %v, peerId %s", err, peerID)
					}
					log.Debugf("Cancelling subscription to topic %s due Subscription.Next error: %v", p2p.TXTopicName, err)
					sub.Cancel()
					return
				}
				// participation or configuration change, cancel subscription and quit
				if !wantTXGossip.Load() {
					log.Debugf("Cancelling subscription to topic %s due to participation change", p2p.TXTopicName)
					sub.Cancel()
					return
				}
			}
		}(n.ctx, sub, &n.wantTXGossip, n.service.ID(), n.log)
	}
	wg.Wait()
}

type gsPeer struct {
	peerID peer.ID
	net    *P2PNetwork
}

func (p *gsPeer) GetNetwork() GossipNode {
	return p.net
}

func (p *gsPeer) RoutingAddr() []byte {
	return []byte(p.peerID)
}

// txTopicValidator calls txHandler to validate and process incoming transactions.
func (n *P2PNetwork) txTopicValidator(ctx context.Context, peerID peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	n.wsPeersLock.Lock()
	var sender DisconnectableAddressablePeer
	if wsp, ok := n.wsPeers[peerID]; ok {
		sender = wsp
	} else {
		// otherwise use the peerID to handle the case where this peer is not in the wsPeers map yet
		// this can happen when pubsub receives new peer notifications before the wsStreamHandler is called:
		// create a fake peer that is good enough for tx handler to work with.
		sender = &gsPeer{peerID: peerID, net: n}
	}
	n.wsPeersLock.Unlock()

	inmsg := IncomingMessage{
		Sender:   sender,
		Tag:      protocol.TxnTag,
		Data:     msg.Data,
		Net:      n,
		Received: time.Now().UnixNano(),
	}

	// if we sent the message, don't validate it
	if msg.ReceivedFrom == n.service.ID() {
		return pubsub.ValidationAccept
	}

	n.peerStatsMu.Lock()
	peerStats, ok := n.peerStats[peerID]
	if !ok {
		peerStats = &p2pPeerStats{}
		n.peerStats[peerID] = peerStats
	}
	peerStats.txReceived.Add(1)
	n.peerStatsMu.Unlock()

	outmsg := n.handler.ValidateHandle(inmsg)
	// there was a decision made in the handler about this message
	switch outmsg.Action {
	case Ignore:
		return pubsub.ValidationIgnore
	case Disconnect:
		return pubsub.ValidationReject
	case Accept:
		msg.ValidatorData = outmsg
		return pubsub.ValidationAccept
	default:
		n.log.Warnf("handler returned invalid action %d", outmsg.Action)
		return pubsub.ValidationIgnore
	}
}
