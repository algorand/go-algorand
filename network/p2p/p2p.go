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

package p2p

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	pstore "github.com/algorand/go-algorand/network/p2p/peerstore"
	"github.com/algorand/go-algorand/network/phonebook"
	"github.com/algorand/go-deadlock"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	libp2phttp "github.com/libp2p/go-libp2p/p2p/http"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
)

// SubNextCancellable is an abstraction for pubsub.Subscription
type SubNextCancellable interface {
	Next(ctx context.Context) (*pubsub.Message, error)
	Cancel()
}

// Service defines the interface used by the network integrating with underlying p2p implementation
type Service interface {
	Start() error
	Close() error
	ID() peer.ID // return peer.ID for self
	IDSigner() *PeerIDChallengeSigner
	AddrInfo() peer.AddrInfo // return addrInfo for self

	DialNode(context.Context, *peer.AddrInfo) error
	DialPeersUntilTargetCount(targetConnCount int)
	ClosePeer(peer.ID) error

	Conns() []network.Conn
	ListPeersForTopic(topic string) []peer.ID
	Subscribe(topic string, val pubsub.ValidatorEx) (SubNextCancellable, error)
	Publish(ctx context.Context, topic string, data []byte) error

	GetStream(peer.ID) (network.Stream, bool)
}

// serviceImpl manages integration with libp2p and implements the Service interface
type serviceImpl struct {
	log        logging.Logger
	listenAddr string
	host       host.Host
	streams    *streamManager
	pubsub     *pubsub.PubSub
	pubsubCtx  context.Context
	privKey    crypto.PrivKey

	topics   map[string]*pubsub.Topic
	topicsMu deadlock.RWMutex
}

// AlgorandWsProtocol defines a libp2p protocol name for algorand's websockets messages
const AlgorandWsProtocol = "/algorand-ws/1.0.0"

const dialTimeout = 30 * time.Second

// MakeHost creates a libp2p host but does not start listening.
// Use host.Network().Listen() on the returned address to start listening.
func MakeHost(cfg config.Local, datadir string, pstore *pstore.PeerStore) (host.Host, string, error) {
	// load stored peer ID, or make ephemeral peer ID
	privKey, err := GetPrivKey(cfg, datadir)
	if err != nil {
		return nil, "", err
	}

	// muxer supports tweaking fields from yamux.Config
	ymx := *yamux.DefaultTransport
	// user-agent copied from wsNetwork.go
	version := config.GetCurrentVersion()
	ua := fmt.Sprintf("algod/%d.%d (%s; commit=%s; %d) %s(%s)", version.Major, version.Minor, version.Channel, version.CommitHash, version.BuildNumber, runtime.GOOS, runtime.GOARCH)

	var listenAddr string
	if cfg.NetAddress != "" {
		if parsedListenAddr, perr := netAddressToListenAddress(cfg.NetAddress); perr == nil {
			listenAddr = parsedListenAddr
		}
	} else {
		listenAddr = "/ip4/0.0.0.0/tcp/0"
	}

	// the libp2p.NoListenAddrs builtin disables relays but this one does not
	var noListenAddrs = func(cfg *libp2p.Config) error {
		cfg.ListenAddrs = []multiaddr.Multiaddr{}
		return nil
	}

	host, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.UserAgent(ua),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Muxer("/yamux/1.0.0", &ymx),
		libp2p.Peerstore(pstore),
		noListenAddrs,
		libp2p.Security(noise.ID, noise.New),
	)
	return &StreamChainingHost{
		Host:     host,
		handlers: map[protocol.ID][]network.StreamHandler{},
	}, listenAddr, err
}

// StreamChainingHost is a wrapper around host.Host that overrides SetStreamHandler
// to allow chaining multiple handlers for the same protocol.
// Note, there should be probably only single handler that writes/reads streams.
type StreamChainingHost struct {
	host.Host
	handlers map[protocol.ID][]network.StreamHandler
	mutex    deadlock.Mutex
}

// SetStreamHandler overrides the host.Host.SetStreamHandler method for chaining multiple handlers.
// Function objects are not comparable so theoretically it could have duplicates.
// The main use case is to track HTTP streams for ProtocolIDForMultistreamSelect = "/http/1.1"
// so it could just filter for such protocol if there any issues with other protocols like kad or mesh.
func (h *StreamChainingHost) SetStreamHandler(pid protocol.ID, handler network.StreamHandler) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	handlers := h.handlers[pid]
	if len(handlers) == 0 {
		// no other handlers, do not set a proxy handler
		h.Host.SetStreamHandler(pid, handler)
		h.handlers[pid] = append(handlers, handler)
		return
	}
	// otherwise chain the handlers with a copy of the existing handlers
	handlers = append(handlers, handler)
	// copy to save it in the closure and call lock free
	currentHandlers := make([]network.StreamHandler, len(handlers))
	copy(currentHandlers, handlers)
	h.Host.SetStreamHandler(pid, func(s network.Stream) {
		for _, h := range currentHandlers {
			h(s)
		}
	})
	h.handlers[pid] = handlers
}

// MakeService creates a P2P service instance
func MakeService(ctx context.Context, log logging.Logger, cfg config.Local, h host.Host, listenAddr string, wsStreamHandler StreamHandler, bootstrapPeers []*peer.AddrInfo) (*serviceImpl, error) {

	sm := makeStreamManager(ctx, log, h, wsStreamHandler)
	h.Network().Notify(sm)
	h.SetStreamHandler(AlgorandWsProtocol, sm.streamHandler)
	h.SetStreamHandler(libp2phttp.ProtocolIDForMultistreamSelect, sm.streamHandlerHTTP)

	ps, err := makePubSub(ctx, cfg, h)
	if err != nil {
		return nil, err
	}

	return &serviceImpl{
		log:        log,
		listenAddr: listenAddr,
		host:       h,
		streams:    sm,
		pubsub:     ps,
		pubsubCtx:  ctx,
		privKey:    h.Peerstore().PrivKey(h.ID()),
		topics:     make(map[string]*pubsub.Topic),
	}, nil
}

// Close shuts down the P2P service
func (s *serviceImpl) Start() error {
	listenAddr, err := multiaddr.NewMultiaddr(s.listenAddr)
	if err != nil {
		s.log.Errorf("failed to create multiaddress: %s", err)
		return err
	}

	return s.host.Network().Listen(listenAddr)
}

// Close shuts down the P2P service
func (s *serviceImpl) Close() error {
	return s.host.Close()
}

// ID returns the peer.ID for self
func (s *serviceImpl) ID() peer.ID {
	return s.host.ID()
}

// IDSigner returns a PeerIDChallengeSigner that implements the network identityChallengeSigner interface
func (s *serviceImpl) IDSigner() *PeerIDChallengeSigner {
	return &PeerIDChallengeSigner{key: s.privKey}
}

// DialPeersUntilTargetCount attempts to establish connections to the provided phonebook addresses
func (s *serviceImpl) DialPeersUntilTargetCount(targetConnCount int) {
	ps := s.host.Peerstore().(*pstore.PeerStore)
	peerIDs := ps.GetAddresses(targetConnCount, phonebook.PhoneBookEntryRelayRole)
	for _, peerInfo := range peerIDs {
		peerInfo := peerInfo.(*peer.AddrInfo)
		// if we are at our target count stop trying to connect
		if len(s.host.Network().Conns()) == targetConnCount {
			return
		}
		// if we are already connected to this peer, skip it
		if len(s.host.Network().ConnsToPeer(peerInfo.ID)) > 0 {
			continue
		}
		err := s.DialNode(context.Background(), peerInfo) // leaving the calls as blocking for now, to not over-connect beyond fanout
		if err != nil {
			s.log.Warnf("failed to connect to peer %s: %v", peerInfo.ID, err)
		}
	}
}

// DialNode attempts to establish a connection to the provided peer
func (s *serviceImpl) DialNode(ctx context.Context, peer *peer.AddrInfo) error {
	// don't try connecting to ourselves
	if peer.ID == s.host.ID() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return s.host.Connect(ctx, *peer)
}

// AddrInfo returns the peer.AddrInfo for self
func (s *serviceImpl) AddrInfo() peer.AddrInfo {
	return peer.AddrInfo{
		ID:    s.host.ID(),
		Addrs: s.host.Addrs(),
	}
}

// Conns returns the current connections
func (s *serviceImpl) Conns() []network.Conn {
	return s.host.Network().Conns()
}

// ClosePeer closes a connection to the provided peer
func (s *serviceImpl) ClosePeer(peer peer.ID) error {
	return s.host.Network().ClosePeer(peer)
}

func (s *serviceImpl) GetStream(peerID peer.ID) (network.Stream, bool) {
	return s.streams.getStream(peerID)
}

// netAddressToListenAddress converts a netAddress in "ip:port" format to a listen address
// that can be passed in to libp2p.ListenAddrStrings
func netAddressToListenAddress(netAddress string) (string, error) {
	// split the string on ":"
	// if there are more than 2 parts, return an error
	parts := strings.Split(netAddress, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid netAddress %s; required format is \"ip:port\"", netAddress)
	}
	ip := "0.0.0.0"
	if parts[0] != "" {
		ip = parts[0]
	}
	if parts[1] == "" {
		return "", fmt.Errorf("invalid netAddress %s, port is required", netAddress)
	}

	return fmt.Sprintf("/ip4/%s/tcp/%s", ip, parts[1]), nil
}
