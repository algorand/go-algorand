// Copyright (C) 2019-2024 Algorand, Inc.
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
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/config"
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

// P2PNetwork implements the GossipNode interface
type P2PNetwork struct {
	service     p2p.Service
	log         logging.Logger
	config      config.Local
	genesisID   string
	networkID   protocol.NetworkID
	ctx         context.Context
	ctxCancel   context.CancelFunc
	peerStats   map[peer.ID]*p2pPeerStats
	peerStatsMu deadlock.Mutex

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

	relayMessages bool // True if we should relay messages from other nodes (nominally true for relays, false otherwise)
	wantTXGossip  atomic.Bool

	capabilitiesDiscovery *p2p.CapabilitiesDiscovery

	bootstrapperStart func()
	bootstrapperStop  func()
	nodeInfo          NodeInfo
	pstore            *peerstore.PeerStore
	httpServer        *p2p.HTTPServer
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

type gossipSubPeer struct {
	peerID peer.ID
	net    GossipNode
}

func (p gossipSubPeer) GetNetwork() GossipNode { return p.net }

func (p gossipSubPeer) OnClose(f func()) {
	net := p.GetNetwork().(*P2PNetwork)
	net.wsPeersLock.Lock()
	defer net.wsPeersLock.Unlock()
	if wsp, ok := net.wsPeers[p.peerID]; ok {
		wsp.OnClose(f)
	}
}

// NewP2PNetwork returns an instance of GossipNode that uses the p2p.Service
func NewP2PNetwork(log logging.Logger, cfg config.Local, datadir string, phonebookAddresses []string, genesisID string, networkID protocol.NetworkID, node NodeInfo) (*P2PNetwork, error) {
	const readBufferLen = 2048

	// create Peerstore and add phonebook addresses
	addrInfo, malformedAddrs := peerstore.PeerInfoFromAddrs(phonebookAddresses)
	for malAddr, malErr := range malformedAddrs {
		log.Infof("Ignoring malformed phonebook address %s: %s", malAddr, malErr)
	}
	pstore, err := peerstore.NewPeerStore(addrInfo, string(networkID))
	if err != nil {
		return nil, err
	}

	relayMessages := cfg.IsGossipServer() || cfg.ForceRelayMessages
	net := &P2PNetwork{
		log:           log,
		config:        cfg,
		genesisID:     genesisID,
		networkID:     networkID,
		topicTags:     map[protocol.Tag]string{protocol.TxnTag: p2p.TXTopicName},
		wsPeers:       make(map[peer.ID]*wsPeer),
		wsPeersToIDs:  make(map[*wsPeer]peer.ID),
		peerStats:     make(map[peer.ID]*p2pPeerStats),
		nodeInfo:      node,
		pstore:        pstore,
		relayMessages: relayMessages,
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
	}

	h, la, err := p2p.MakeHost(cfg, datadir, pstore)
	if err != nil {
		return nil, err
	}
	log.Infof("P2P host created: peer ID %s addrs %s", h.ID(), h.Addrs())

	net.service, err = p2p.MakeService(net.ctx, log, cfg, h, la, net.wsStreamHandler, addrInfo)
	if err != nil {
		return nil, err
	}

	bootstrapper := &bootstrapper{
		cfg:               cfg,
		networkID:         networkID,
		phonebookPeers:    addrInfo,
		resolveController: dnsaddr.NewMultiaddrDNSResolveController(cfg.DNSSecuritySRVEnforced(), ""),
		log:               net.log,
	}
	net.bootstrapperStart = bootstrapper.start
	net.bootstrapperStop = bootstrapper.stop

	if cfg.EnableDHTProviders {
		disc, err0 := p2p.MakeCapabilitiesDiscovery(net.ctx, cfg, h, networkID, net.log, bootstrapper.BootstrapFunc)
		if err0 != nil {
			log.Errorf("Failed to create dht node capabilities discovery: %v", err)
			return nil, err
		}
		net.capabilitiesDiscovery = disc
	}

	net.httpServer = p2p.MakeHTTPServer(h)

	err = net.setup()
	if err != nil {
		return nil, err
	}

	return net, nil
}

func (n *P2PNetwork) setup() error {
	if n.broadcaster.slowWritingPeerMonitorInterval == 0 {
		n.broadcaster.slowWritingPeerMonitorInterval = slowWritingPeerMonitorInterval
	}
	return nil
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
		go n.handler.messageHandlerThread(&n.wg, n.wsPeersConnectivityCheckTicker.C, n)
	}

	n.wg.Add(1)
	go n.httpdThread()

	n.wg.Add(1)
	go n.broadcaster.broadcastThread(&n.wg, n)

	n.wg.Add(1)
	go n.meshThread()

	if n.capabilitiesDiscovery != nil {
		n.capabilitiesDiscovery.AdvertiseCapabilities(n.nodeInfo.Capabilities()...)
	}

	return nil
}

// Stop closes sockets and stop threads.
func (n *P2PNetwork) Stop() {
	if n.capabilitiesDiscovery != nil {
		n.capabilitiesDiscovery.Close()
	}

	n.handler.ClearHandlers([]Tag{})
	if n.wsPeersConnectivityCheckTicker != nil {
		n.wsPeersConnectivityCheckTicker.Stop()
		n.wsPeersConnectivityCheckTicker = nil
	}
	n.innerStop()
	n.ctxCancel()
	n.service.Close()
	n.bootstrapperStop()
	n.httpServer.Close()
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

// meshThreadInner fetches nodes from DHT and attempts to connect to them
func (n *P2PNetwork) meshThreadInner() {
	defer n.service.DialPeersUntilTargetCount(n.config.GossipFanout)

	// fetch peers from DNS
	var dnsPeers, dhtPeers []peer.AddrInfo
	dnsPeers = dnsLookupBootstrapPeers(n.log, n.config, n.networkID, dnsaddr.NewMultiaddrDNSResolveController(n.config.DNSSecuritySRVEnforced(), ""))

	// discover peers from DHT
	if n.capabilitiesDiscovery != nil {
		var err error
		dhtPeers, err = n.capabilitiesDiscovery.PeersForCapability(p2p.Gossip, n.config.GossipFanout)
		if err != nil {
			n.log.Warnf("Error getting relay nodes from capabilities discovery: %v", err)
			return
		}
		n.log.Debugf("Discovered %d gossip peers from DHT", len(dhtPeers))
	}

	peers := mergeP2PAddrInfoResolvedAddresses(dnsPeers, dhtPeers)
	replace := make([]interface{}, 0, len(peers))
	for i := range peers {
		replace = append(replace, &peers[i])
	}
	n.pstore.ReplacePeerList(replace, string(n.networkID), phonebook.PhoneBookEntryRelayRole)
}

func (n *P2PNetwork) meshThread() {
	defer n.wg.Done()
	timer := time.NewTicker(1) // start immediately and reset after
	defer timer.Stop()
	var resetTimer bool
	for {
		select {
		case <-timer.C:
			n.meshThreadInner()
			if !resetTimer {
				timer.Reset(meshThreadInterval)
				resetTimer = true
			}
		case <-n.ctx.Done():
			return
		}

		// send the currently connected peers information to the
		// telemetry server; that would allow the telemetry server
		// to construct a cross-node map of all the nodes interconnections.
		n.peerStater.sendPeerConnectionsTelemetryStatus(n)
	}
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
	return n.genesisID
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
	return n.broadcaster.BroadcastArray(ctx, []protocol.Tag{tag}, [][]byte{data}, wait, except)
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
	var peerID peer.ID
	var wsp *wsPeer

	n.wsPeersLock.Lock()
	defer n.wsPeersLock.Unlock()
	switch p := badpeer.(type) {
	case gossipSubPeer: // Disconnect came from a message received via GossipSub
		peerID, wsp = p.peerID, n.wsPeers[p.peerID]
	case *wsPeer: // Disconnect came from a message received via wsPeer
		peerID, wsp = n.wsPeersToIDs[p], p
	default:
		n.log.Warnf("Unknown peer type %T", badpeer)
		return
	}
	if wsp != nil {
		wsp.CloseAndWait(time.Now().Add(peerDisconnectionAckDuration))
		delete(n.wsPeers, peerID)
		delete(n.wsPeersToIDs, wsp)
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

// RequestConnectOutgoing asks the system to actually connect to peers.
// `replace` optionally drops existing connections before making new ones.
// `quit` chan allows cancellation.
func (n *P2PNetwork) RequestConnectOutgoing(replace bool, quit <-chan struct{}) {
	n.meshThreadInner()
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

	maxIdleConnsPerHost := int(n.config.ConnectionsRateLimitingCount)
	client, err := p2p.MakeHTTPClientWithRateLimit(addrInfo, n.pstore, limitcaller.DefaultQueueingTimeout, maxIdleConnsPerHost)
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
			peerIDs := n.pstore.GetAddresses(maxNodes, phonebook.PhoneBookEntryRelayRole)
			for _, peerInfo := range peerIDs {
				peerInfo := peerInfo.(*peer.AddrInfo)
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
			// query known archival nodes from DHT if enabled
			if n.config.EnableDHTProviders {
				const nodesToFind = 5
				infos, err := n.capabilitiesDiscovery.PeersForCapability(p2p.Archival, nodesToFind)
				if err != nil {
					n.log.Warnf("Error getting archival nodes from capabilities discovery: %v", err)
					return peers
				}
				n.log.Debugf("Got %d archival node(s) from DHT", len(infos))
				for _, addrInfo := range infos {
					// TODO: remove after go1.22
					info := addrInfo
					if peerCore, ok := addrInfoToWsPeerCore(n, &info); ok {
						peers = append(peers, &peerCore)
					}
				}
				if n.log.GetLevel() >= logging.Debug && len(peers) > 0 {
					addrs := make([]string, 0, len(peers))
					for _, peer := range peers {
						addrs = append(addrs, peer.(*wsPeerCore).GetAddress())
					}
					n.log.Debugf("Archival node(s) from DHT: %v", addrs)
				}
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

// RegisterProcessors adds to the set of given message handlers.
func (n *P2PNetwork) RegisterProcessors(dispatch []TaggedMessageProcessor) {
	n.handler.RegisterProcessors(dispatch)
}

// ClearProcessors deregisters all the existing message handlers.
func (n *P2PNetwork) ClearProcessors() {
	n.handler.ClearProcessors([]Tag{})
}

// GetHTTPClient returns a http.Client with a suitable for the network Transport
// that would also limit the number of outgoing connections.
func (n *P2PNetwork) GetHTTPClient(address string) (*http.Client, error) {
	addrInfo, err := peer.AddrInfoFromString(address)
	if err != nil {
		return nil, err
	}
	maxIdleConnsPerHost := int(n.config.ConnectionsRateLimitingCount)
	return p2p.MakeHTTPClientWithRateLimit(addrInfo, n.pstore, limitcaller.DefaultQueueingTimeout, maxIdleConnsPerHost)
}

// OnNetworkAdvance notifies the network library that the agreement protocol was able to make a notable progress.
// this is the only indication that we have that we haven't formed a clique, where all incoming messages
// arrive very quickly, but might be missing some votes. The usage of this call is expected to have similar
// characteristics as with a watchdog timer.
func (n *P2PNetwork) OnNetworkAdvance() {
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

// GetHTTPRequestConnection returns the underlying connection for the given request. Note that the request must be the same
// request that was provided to the http handler ( or provide a fallback Context() to that )
func (n *P2PNetwork) GetHTTPRequestConnection(request *http.Request) (conn DeadlineSettable) {
	addr := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	peerID, err := peer.Decode(addr.String())
	if err != nil {
		n.log.Infof("GetHTTPRequestConnection failed to decode %s", addr.String())
		return nil
	}
	conn, ok := n.service.GetStream(peerID)
	if !ok {
		n.log.Warnf("GetHTTPRequestConnection no such stream for peer %s", peerID.String())
		return nil
	}
	return conn
}

// wsStreamHandler is a callback that the p2p package calls when a new peer connects and establishes a
// stream for the websocket protocol.
func (n *P2PNetwork) wsStreamHandler(ctx context.Context, p2pPeer peer.ID, stream network.Stream, incoming bool) {
	if stream.Protocol() != p2p.AlgorandWsProtocol {
		n.log.Warnf("unknown protocol %s from peer%s", stream.Protocol(), p2pPeer)
		return
	}

	if incoming {
		var initMsg [1]byte
		rn, err := stream.Read(initMsg[:])
		if rn == 0 || err != nil {
			n.log.Warnf("wsStreamHandler: error reading initial message: %s, peer %s", err, p2pPeer)
			return
		}
	} else {
		n.wsPeersLock.Lock()
		numOutgoingPeers := 0
		for _, peer := range n.wsPeers {
			if peer.outgoing {
				n.log.Debugf("outgoing peer orig=%s addr=%s", peer.OriginAddress(), peer.GetAddress())
				numOutgoingPeers++
			}
		}
		n.wsPeersLock.Unlock()
		if numOutgoingPeers >= n.config.GossipFanout {
			// this appears to be some auxiliary connection made by libp2p itself like DHT connection.
			// skip this connection since there are already enough peers
			n.log.Debugf("skipping outgoing connection to peer %s: num outgoing %d > fanout %d ", p2pPeer, numOutgoingPeers, n.config.GossipFanout)
			stream.Close()
			return
		}

		_, err := stream.Write([]byte("1"))
		if err != nil {
			n.log.Warnf("wsStreamHandler: error sending initial message: %s", err)
			return
		}
	}

	// get address for peer ID
	ma := stream.Conn().RemoteMultiaddr()
	addr := ma.String()
	if addr == "" {
		n.log.Warnf("Could not get address for peer %s", p2pPeer)
	}
	// create a wsPeer for this stream and added it to the peers map.

	addrInfo := &peer.AddrInfo{ID: p2pPeer, Addrs: []multiaddr.Multiaddr{ma}}
	maxIdleConnsPerHost := int(n.config.ConnectionsRateLimitingCount)
	client, err := p2p.MakeHTTPClientWithRateLimit(addrInfo, n.pstore, limitcaller.DefaultQueueingTimeout, maxIdleConnsPerHost)
	if err != nil {
		client = nil
	}
	peerCore := makePeerCore(ctx, n, n.log, n.handler.readBuffer, addr, client, addr)
	wsp := &wsPeer{
		wsPeerCore: peerCore,
		conn:       &wsPeerConnP2PImpl{stream: stream},
		outgoing:   !incoming,
	}
	protos, err := n.pstore.GetProtocols(p2pPeer)
	if err != nil {
		n.log.Warnf("Error getting protocols for peer %s: %v", p2pPeer, err)
	}
	wsp.TelemetryGUID, wsp.InstanceName = p2p.GetPeerTelemetryInfo(protos)

	wsp.init(n.config, outgoingMessagesBufferSize)
	n.wsPeersLock.Lock()
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
	localAddr, _ := n.Address()
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
	remotePeerID := peer.conn.(*wsPeerConnP2PImpl).stream.Conn().RemotePeer()
	n.wsPeersLock.Lock()
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

	for {
		msg, err := sub.Next(n.ctx)
		if err != nil {
			if err != pubsub.ErrSubscriptionCancelled && err != context.Canceled {
				n.log.Errorf("Error reading from subscription %v, peerId %s", err, n.service.ID())
			}
			n.log.Debugf("Cancelling subscription to topic %s due Subscription.Next error: %v", p2p.TXTopicName, err)
			sub.Cancel()
			return
		}
		// if there is a self-sent the message no need to process it.
		if msg.ReceivedFrom == n.service.ID() {
			continue
		}

		_ = n.handler.Process(msg.ValidatorData.(ValidatedMessage))

		// participation or configuration change, cancel subscription and quit
		if !n.wantTXGossip.Load() {
			n.log.Debugf("Cancelling subscription to topic %s due participation change", p2p.TXTopicName)
			sub.Cancel()
			return
		}
	}
}

// txTopicValidator calls txHandler to validate and process incoming transactions.
func (n *P2PNetwork) txTopicValidator(ctx context.Context, peerID peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	inmsg := IncomingMessage{
		Sender:   gossipSubPeer{peerID: msg.ReceivedFrom, net: n},
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

	outmsg := n.handler.Validate(inmsg)
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
