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
	"github.com/algorand/go-deadlock"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
)

// Service defines the interface used by the network integrating with underlying p2p implementation
type Service interface {
	Close() error
	ID() peer.ID             // return peer.ID for self
	AddrInfo() peer.AddrInfo // return addrInfo for self

	DialNode(context.Context, *peer.AddrInfo) error
	DialPeersUntilTargetCount(targetConnCount int)
	ClosePeer(peer.ID) error

	Conns() []network.Conn
	ListPeersForTopic(topic string) []peer.ID
	Subscribe(topic string, val pubsub.ValidatorEx) (*pubsub.Subscription, error)
	Publish(ctx context.Context, topic string, data []byte) error
}

// serviceImpl manages integration with libp2p and implements the Service interface
type serviceImpl struct {
	log       logging.Logger
	host      host.Host
	streams   *streamManager
	pubsub    *pubsub.PubSub
	pubsubCtx context.Context

	topics   map[string]*pubsub.Topic
	topicsMu deadlock.RWMutex
}

// AlgorandWsProtocol defines a libp2p protocol name for algorand's websockets messages
const AlgorandWsProtocol = "/algorand-ws/1.0.0"

const dialTimeout = 30 * time.Second

// MakeService creates a P2P service instance
func MakeService(ctx context.Context, log logging.Logger, cfg config.Local, datadir string, pstore peerstore.Peerstore, wsStreamHandler StreamHandler) (*serviceImpl, error) {
	// load stored peer ID, or make ephemeral peer ID
	privKey, err := GetPrivKey(cfg, datadir)
	if err != nil {
		return nil, err
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

	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.UserAgent(ua),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Muxer("/yamux/1.0.0", &ymx),
		libp2p.Peerstore(pstore),
		libp2p.ListenAddrStrings(listenAddr),
	)
	if err != nil {
		return nil, err
	}
	log.Infof("P2P service started: peer ID %s addrs %s", h.ID(), h.Addrs())

	sm := makeStreamManager(ctx, log, h, wsStreamHandler)
	h.Network().Notify(sm)
	h.SetStreamHandler(AlgorandWsProtocol, sm.streamHandler)

	ps, err := makePubSub(ctx, cfg, h)
	if err != nil {
		return nil, err
	}

	return &serviceImpl{
		log:       log,
		host:      h,
		streams:   sm,
		pubsub:    ps,
		pubsubCtx: ctx,
		topics:    make(map[string]*pubsub.Topic),
	}, nil
}

// Close shuts down the P2P service
func (s *serviceImpl) Close() error {
	return s.host.Close()
}

// ID returns the peer.ID for self
func (s *serviceImpl) ID() peer.ID {
	return s.host.ID()
}

// DialPeersUntilTargetCount attempts to establish connections to the provided phonebook addresses
func (s *serviceImpl) DialPeersUntilTargetCount(targetConnCount int) {
	peerIDs := s.host.Peerstore().Peers()
	for _, peerID := range peerIDs {
		// if we are at our target count stop trying to connect
		if len(s.host.Network().Conns()) == targetConnCount {
			return
		}
		// if we are already connected to this peer, skip it
		if len(s.host.Network().ConnsToPeer(peerID)) > 0 {
			continue
		}
		peerInfo := s.host.Peerstore().PeerInfo(peerID)
		err := s.DialNode(context.Background(), &peerInfo) // leaving the calls as blocking for now, to not over-connect beyond fanout
		if err != nil {
			s.log.Warnf("failed to connect to peer %s: %v", peerID, err)
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
