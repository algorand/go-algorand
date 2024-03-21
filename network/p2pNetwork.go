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
	"github.com/algorand/go-algorand/network/p2p"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-deadlock"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
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
	wsPeersLock                    deadlock.RWMutex
	wsPeersChangeCounter           atomic.Int32
	wsPeersConnectivityCheckTicker *time.Ticker
}

type p2pPeerStats struct {
	txReceived atomic.Uint64
}

// NewP2PNetwork returns an instance of GossipNode that uses the p2p.Service
func NewP2PNetwork(log logging.Logger, cfg config.Local, datadir string, phonebookAddresses []string, genesisID string, networkID protocol.NetworkID) (*P2PNetwork, error) {
	const readBufferLen = 2048

	// create Peerstore and add phonebook addresses
	addrInfo, malformedAddrs := peerstore.PeerInfoFromAddrs(phonebookAddresses)
	for malAddr, malErr := range malformedAddrs {
		log.Infof("Ignoring malformed phonebook address %s: %s", malAddr, malErr)
	}
	pstore, err := peerstore.NewPeerStore(addrInfo)
	if err != nil {
		return nil, err
	}

	net := &P2PNetwork{
		log:       log,
		config:    cfg,
		genesisID: genesisID,
		networkID: networkID,
		topicTags: map[protocol.Tag]string{"TX": p2p.TXTopicName},
		wsPeers:   make(map[peer.ID]*wsPeer),
		peerStats: make(map[peer.ID]*p2pPeerStats),
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

	net.service, err = p2p.MakeService(net.ctx, log, cfg, datadir, pstore, net.wsStreamHandler)
	if err != nil {
		return nil, err
	}

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

// Start threads, listen on sockets.
func (n *P2PNetwork) Start() {
	n.wg.Add(1)
	go n.txTopicHandleLoop()

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
	go n.broadcaster.broadcastThread(&n.wg, n)
	n.service.DialPeersUntilTargetCount(n.config.GossipFanout)

	n.wg.Add(1)
	go n.meshThread()
}

// Stop closes sockets and stop threads.
func (n *P2PNetwork) Stop() {
	n.handler.ClearHandlers([]Tag{})
	if n.wsPeersConnectivityCheckTicker != nil {
		n.wsPeersConnectivityCheckTicker.Stop()
		n.wsPeersConnectivityCheckTicker = nil
	}
	n.innerStop()
	n.ctxCancel()
	n.service.Close()
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
	}
	n.wsPeersLock.Unlock()
	closeGroup.Wait()
}

func (n *P2PNetwork) meshThread() {
	defer n.wg.Done()
	timer := time.NewTicker(meshThreadInterval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			n.service.DialPeersUntilTargetCount(n.config.GossipFanout)
		case <-n.ctx.Done():
			return
		}
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
	return n.Broadcast(ctx, tag, data, wait, except)
}

// Disconnect from a peer, probably due to protocol errors.
func (n *P2PNetwork) Disconnect(badnode Peer) {
	node, ok := badnode.(peer.ID)
	if !ok {
		n.log.Warnf("Unknown peer type %T", badnode)
		return
	}
	n.wsPeersLock.Lock()
	defer n.wsPeersLock.Unlock()
	if wsPeer, ok := n.wsPeers[node]; ok {
		wsPeer.CloseAndWait(time.Now().Add(peerDisconnectionAckDuration))
		delete(n.wsPeers, node)
	} else {
		n.log.Warnf("Could not find wsPeer reference for peer %s", node)
	}
	err := n.service.ClosePeer(node)
	if err != nil {
		n.log.Warnf("Error disconnecting from peer %s: %v", node, err)
	}
}

func (n *P2PNetwork) disconnectThread(badnode Peer, reason disconnectReason) {
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
}

// RequestConnectOutgoing asks the system to actually connect to peers.
// `replace` optionally drops existing connections before making new ones.
// `quit` chan allows cancellation.
func (n *P2PNetwork) RequestConnectOutgoing(replace bool, quit <-chan struct{}) {
}

// GetPeers returns a list of Peers we could potentially send a direct message to.
func (n *P2PNetwork) GetPeers(options ...PeerOption) []Peer {
	// currently returns same list of peers for all PeerOption filters.
	peers := make([]Peer, 0)
	n.wsPeersLock.RLock()
	for _, peer := range n.wsPeers {
		peers = append(peers, Peer(peer))
	}
	n.wsPeersLock.RUnlock()
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

// GetRoundTripper returns a Transport that would limit the number of outgoing connections.
func (n *P2PNetwork) GetRoundTripper() http.RoundTripper {
	return http.DefaultTransport
}

// OnNetworkAdvance notifies the network library that the agreement protocol was able to make a notable progress.
// this is the only indication that we have that we haven't formed a clique, where all incoming messages
// arrive very quickly, but might be missing some votes. The usage of this call is expected to have similar
// characteristics as with a watchdog timer.
func (n *P2PNetwork) OnNetworkAdvance() {}

// GetHTTPRequestConnection returns the underlying connection for the given request. Note that the request must be the same
// request that was provided to the http handler ( or provide a fallback Context() to that )
func (n *P2PNetwork) GetHTTPRequestConnection(request *http.Request) (conn net.Conn) { return nil }

// SubstituteGenesisID substitutes the "{genesisID}" with their network-specific genesisID.
func (n *P2PNetwork) SubstituteGenesisID(rawURL string) string {
	return strings.Replace(rawURL, "{genesisID}", n.genesisID, -1)
}

// wsStreamHandler is a callback that the p2p package calls when a new peer connects and establishes a
// stream for the websocket protocol.
func (n *P2PNetwork) wsStreamHandler(ctx context.Context, peer peer.ID, stream network.Stream, incoming bool) {
	if stream.Protocol() != p2p.AlgorandWsProtocol {
		n.log.Warnf("unknown protocol %s", stream.Protocol())
		return
	}

	if incoming {
		var initMsg [1]byte
		rn, err := stream.Read(initMsg[:])
		if rn == 0 || err != nil {
			n.log.Warnf("wsStreamHandler: error reading initial message: %s", err)
			return
		}
	} else {
		_, err := stream.Write([]byte("1"))
		if err != nil {
			n.log.Warnf("wsStreamHandler: error sending initial message: %s", err)
			return
		}
	}

	// get address for peer ID
	addr := stream.Conn().RemoteMultiaddr().String()
	if addr == "" {
		n.log.Warnf("Could not get address for peer %s", peer)
	}
	// create a wsPeer for this stream and added it to the peers map.
	wsp := &wsPeer{
		wsPeerCore: makePeerCore(ctx, n, n.log, n.handler.readBuffer, addr, n.GetRoundTripper(), addr),
		conn:       &wsPeerConnP2PImpl{stream: stream},
		outgoing:   !incoming,
	}
	wsp.init(n.config, outgoingMessagesBufferSize)
	n.wsPeersLock.Lock()
	n.wsPeers[peer] = wsp
	n.wsPeersLock.Unlock()
	n.wsPeersChangeCounter.Add(1)
}

// peerRemoteClose called from wsPeer to report that it has closed
func (n *P2PNetwork) peerRemoteClose(peer *wsPeer, reason disconnectReason) {
	remotePeerID := peer.conn.(*wsPeerConnP2PImpl).stream.Conn().RemotePeer()
	n.wsPeersLock.Lock()
	delete(n.wsPeers, remotePeerID)
	n.wsPeersLock.Unlock()
	n.wsPeersChangeCounter.Add(1)
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

	for {
		msg, err := sub.Next(n.ctx)
		if err != nil {
			if err != pubsub.ErrSubscriptionCancelled && err != context.Canceled {
				n.log.Errorf("Error reading from subscription %v, peerId %s", err, n.service.ID())
			}
			sub.Cancel()
			return
		}

		// discard TX message.
		// from gossipsub's point of view, it's just waiting to hear back from the validator,
		// and txHandler does all its work in the validator, so we don't need to do anything here
		_ = msg
	}
}

// txTopicValidator calls txHandler to validate and process incoming transactions.
func (n *P2PNetwork) txTopicValidator(ctx context.Context, peerID peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	inmsg := IncomingMessage{
		Sender:   msg.ReceivedFrom,
		Tag:      protocol.TxnTag,
		Data:     msg.Data,
		Net:      n,
		Received: time.Now().UnixNano(),
	}

	// if we sent the message, don't validate it
	if inmsg.Sender == n.service.ID() {
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

	outmsg := n.handler.Handle(inmsg)
	// there was a decision made in the handler about this message
	switch outmsg.Action {
	case Ignore:
		return pubsub.ValidationIgnore
	case Disconnect:
		return pubsub.ValidationReject
	case Broadcast: // TxHandler.processIncomingTxn does not currently return this Action
		return pubsub.ValidationAccept
	default:
		n.log.Warnf("handler returned invalid action %d", outmsg.Action)
		return pubsub.ValidationIgnore
	}
}
