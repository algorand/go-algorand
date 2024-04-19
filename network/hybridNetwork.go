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
	"fmt"
	"net/http"
	"sync"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/addr"
	"github.com/algorand/go-algorand/protocol"
)

// HybridP2PNetwork runs both P2PNetwork and WebsocketNetwork to implement the GossipNode interface
type HybridP2PNetwork struct {
	p2pNetwork *P2PNetwork
	wsNetwork  *WebsocketNetwork
	genesisID  string

	useP2PAddress bool
}

// NewHybridP2PNetwork constructs a GossipNode that combines P2PNetwork and WebsocketNetwork
func NewHybridP2PNetwork(log logging.Logger, cfg config.Local, datadir string, phonebookAddresses []string, genesisID string, networkID protocol.NetworkID, nodeInfo NodeInfo) (*HybridP2PNetwork, error) {
	// supply alternate NetAddress for P2P network
	p2pcfg := cfg
	p2pcfg.NetAddress = cfg.P2PListenAddress
	p2pnet, err := NewP2PNetwork(log, p2pcfg, datadir, phonebookAddresses, genesisID, networkID, nodeInfo)
	if err != nil {
		return nil, err
	}
	wsnet, err := NewWebsocketNetwork(log, cfg, phonebookAddresses, genesisID, networkID, nodeInfo, p2pnet.PeerID(), p2pnet.PeerIDSigner())
	if err != nil {
		return nil, err
	}
	return &HybridP2PNetwork{
		p2pNetwork: p2pnet,
		wsNetwork:  wsnet,
		genesisID:  genesisID,
	}, nil
}

// Address implements GossipNode
func (n *HybridP2PNetwork) Address() (string, bool) {
	// TODO map from configuration? used for REST API, goal status, algod.net, etc
	if n.useP2PAddress {
		return n.p2pNetwork.Address()
	}
	return n.wsNetwork.Address()
}

type hybridNetworkError struct{ p2pErr, wsErr error }

func (e *hybridNetworkError) Error() string {
	return fmt.Sprintf("p2pErr: %s, wsErr: %s", e.p2pErr, e.wsErr)
}
func (e *hybridNetworkError) Unwrap() []error { return []error{e.p2pErr, e.wsErr} }

func (n *HybridP2PNetwork) runParallel(fn func(net GossipNode) error) error {
	var wg sync.WaitGroup
	var p2pErr, wsErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		p2pErr = fn(n.p2pNetwork)
	}()
	go func() {
		defer wg.Done()
		wsErr = fn(n.wsNetwork)
	}()
	wg.Wait()

	if p2pErr != nil && wsErr != nil {
		return &hybridNetworkError{p2pErr, wsErr}
	}
	if p2pErr != nil {
		return p2pErr
	}
	if wsErr != nil {
		return wsErr
	}
	return nil
}

// Broadcast implements GossipNode
func (n *HybridP2PNetwork) Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error {
	return n.runParallel(func(net GossipNode) error {
		return net.Broadcast(ctx, tag, data, wait, except)
	})
}

// Relay implements GossipNode
func (n *HybridP2PNetwork) Relay(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error {
	return n.runParallel(func(net GossipNode) error {
		return net.Relay(ctx, tag, data, wait, except)
	})
}

// Disconnect implements GossipNode
func (n *HybridP2PNetwork) Disconnect(badnode DisconnectablePeer) {
	net := badnode.GetNetwork()
	if net == n.p2pNetwork {
		n.p2pNetwork.Disconnect(badnode)
	} else if net == n.wsNetwork {
		n.wsNetwork.Disconnect(badnode)
	} else {
		panic("badnode.GetNetwork() returned a network that is not part of this HybridP2PNetwork")
	}
}

// DisconnectPeers implements GossipNode
func (n *HybridP2PNetwork) DisconnectPeers() {
	_ = n.runParallel(func(net GossipNode) error {
		net.DisconnectPeers()
		return nil
	})
}

// RegisterHTTPHandler implements GossipNode
func (n *HybridP2PNetwork) RegisterHTTPHandler(path string, handler http.Handler) {
	n.p2pNetwork.RegisterHTTPHandler(path, handler)
	n.wsNetwork.RegisterHTTPHandler(path, handler)
}

// RequestConnectOutgoing implements GossipNode
func (n *HybridP2PNetwork) RequestConnectOutgoing(replace bool, quit <-chan struct{}) {}

// GetPeers implements GossipNode
func (n *HybridP2PNetwork) GetPeers(options ...PeerOption) []Peer {
	// TODO better way of combining data from peerstore and returning in GetPeers
	var peers []Peer
	peers = append(peers, n.p2pNetwork.GetPeers(options...)...)
	peers = append(peers, n.wsNetwork.GetPeers(options...)...)
	return peers
}

// Start implements GossipNode
func (n *HybridP2PNetwork) Start() error {
	err := n.runParallel(func(net GossipNode) error {
		return net.Start()
	})
	return err
}

// Stop implements GossipNode
func (n *HybridP2PNetwork) Stop() {
	_ = n.runParallel(func(net GossipNode) error {
		net.Stop()
		return nil
	})
}

// RegisterHandlers adds to the set of given message handlers.
func (n *HybridP2PNetwork) RegisterHandlers(dispatch []TaggedMessageHandler) {
	n.p2pNetwork.RegisterHandlers(dispatch)
	n.wsNetwork.RegisterHandlers(dispatch)
}

// ClearHandlers deregisters all the existing message handlers.
func (n *HybridP2PNetwork) ClearHandlers() {
	n.p2pNetwork.ClearHandlers()
	n.wsNetwork.ClearHandlers()
}

// RegisterHandlers adds to the set of given message handlers.
func (n *HybridP2PNetwork) RegisterProcessors(dispatch []TaggedMessageProcessor) {
	n.p2pNetwork.RegisterProcessors(dispatch)
	n.wsNetwork.RegisterProcessors(dispatch)
}

// ClearHandlers deregisters all the existing message handlers.
func (n *HybridP2PNetwork) ClearProcessors() {
	n.p2pNetwork.ClearProcessors()
	n.wsNetwork.ClearProcessors()
}

// GetHTTPClient returns a http.Client with a suitable for the network Transport
// that would also limit the number of outgoing connections.
func (n *HybridP2PNetwork) GetHTTPClient(address string) (*http.Client, error) {
	if addr.IsMultiaddr(address) {
		return n.p2pNetwork.GetHTTPClient(address)
	}
	return n.wsNetwork.GetHTTPClient(address)
}

// OnNetworkAdvance notifies the network library that the agreement protocol was able to make a notable progress.
// this is the only indication that we have that we haven't formed a clique, where all incoming messages
// arrive very quickly, but might be missing some votes. The usage of this call is expected to have similar
// characteristics as with a watchdog timer.
func (n *HybridP2PNetwork) OnNetworkAdvance() {
	_ = n.runParallel(func(net GossipNode) error {
		net.OnNetworkAdvance()
		return nil
	})
}

// GetHTTPRequestConnection returns the underlying connection for the given request. Note that the request must be the same
// request that was provided to the http handler ( or provide a fallback Context() to that )
func (n *HybridP2PNetwork) GetHTTPRequestConnection(request *http.Request) (conn DeadlineSettable) {
	conn = n.wsNetwork.GetHTTPRequestConnection(request)
	if conn != nil {
		return conn
	}
	return n.p2pNetwork.GetHTTPRequestConnection(request)
}

// GetGenesisID returns the network-specific genesisID.
func (n *HybridP2PNetwork) GetGenesisID() string {
	return n.genesisID
}

// called from wsPeer to report that it has closed
func (n *HybridP2PNetwork) peerRemoteClose(peer *wsPeer, reason disconnectReason) {
	panic("wsPeer should only call WebsocketNetwork.peerRemoteClose or P2PNetwork.peerRemoteClose")
}
