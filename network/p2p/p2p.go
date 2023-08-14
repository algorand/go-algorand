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

package p2p

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-deadlock"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
)

// Service manages integration with libp2p
type Service struct {
	log       logging.Logger
	host      host.Host
	streams   *streamManager
	pubsub    *pubsub.PubSub
	pubsubCtx context.Context

	topics   map[string]*pubsub.Topic
	topicsMu deadlock.Mutex
}

// AlgorandWsProtocol defines a libp2p protocol name for algorand's websockets messages
const AlgorandWsProtocol = "/algorand-ws/1.0.0"

const dialTimeout = 30 * time.Second

// MakeService creates a P2P service instance
func MakeService(ctx context.Context, log logging.Logger, cfg config.Local, datadir string, pstore peerstore.Peerstore, wsStreamHandler StreamHandler) (*Service, error) {
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

	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.UserAgent(ua),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Muxer("/yamux/1.0.0", &ymx),
		libp2p.Peerstore(pstore),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
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

	return &Service{
		log:       log,
		host:      h,
		streams:   sm,
		pubsub:    ps,
		pubsubCtx: ctx,
		topics:    make(map[string]*pubsub.Topic),
	}, nil
}

// Close shuts down the P2P service
func (s *Service) Close() error {
	return s.host.Close()
}

// Host returns the libp2p host
func (s *Service) Host() host.Host {
	return s.host
}

// DialPeers attempts to establish connections to the provided phonebook addresses
func (s *Service) DialPeers(targetConnCount int) {
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
func (s *Service) DialNode(ctx context.Context, peer *peer.AddrInfo) error {
	// don't try connecting to ourselves
	if peer.ID == s.host.ID() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return s.host.Connect(ctx, *peer)
}
