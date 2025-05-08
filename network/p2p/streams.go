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

package p2p

import (
	"context"
	"io"
	"slices"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-deadlock"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

// streamManager implements network.Notifiee to create and manage streams for use with non-gossipsub protocols.
type streamManager struct {
	ctx                 context.Context
	log                 logging.Logger
	host                host.Host
	handlers            StreamHandlerMap
	allowIncomingGossip bool

	streams     map[peer.ID]network.Stream
	streamsLock deadlock.Mutex
}

// StreamHandler is called when a new bidirectional stream for a given protocol and peer is opened.
type StreamHandler func(ctx context.Context, pid peer.ID, s network.Stream, incoming bool)

func makeStreamManager(ctx context.Context, log logging.Logger, h host.Host, handlers StreamHandlerMap, allowIncomingGossip bool) *streamManager {
	return &streamManager{
		ctx:                 ctx,
		log:                 log,
		host:                h,
		handlers:            handlers,
		allowIncomingGossip: allowIncomingGossip,
		streams:             make(map[peer.ID]network.Stream),
	}
}

// streamHandler is called by libp2p when a new stream is accepted
func (n *streamManager) streamHandler(stream network.Stream) {
	if stream.Conn().Stat().Direction == network.DirInbound && !n.allowIncomingGossip {
		n.log.Debugf("rejecting stream from incoming connection from %s", stream.Conn().RemotePeer().String())
		stream.Close()
		return
	}

	n.streamsLock.Lock()
	defer n.streamsLock.Unlock()

	// could use stream.ID() for tracking; unique across all conns and peers
	remotePeer := stream.Conn().RemotePeer()

	if oldStream, ok := n.streams[remotePeer]; ok {
		// there's already a stream, for some reason, check if it's still open
		buf := []byte{} // empty buffer for checking
		_, err := oldStream.Read(buf)
		if err != nil {
			if err == io.EOF {
				// old stream was closed by the peer
				n.log.Infof("Old stream with %s was closed", remotePeer)
			} else {
				// an error occurred while checking the old stream
				n.log.Infof("Failed to check old stream with %s: %v", remotePeer, err)
			}
			n.streams[stream.Conn().RemotePeer()] = stream

			incoming := stream.Conn().Stat().Direction == network.DirInbound
			n.dispatch(n.ctx, remotePeer, stream, incoming)
			return
		}
		// otherwise, the old stream is still open, so we can close the new one
		stream.Close()
		return
	}
	// no old stream
	n.streams[stream.Conn().RemotePeer()] = stream
	incoming := stream.Conn().Stat().Direction == network.DirInbound
	n.dispatch(n.ctx, remotePeer, stream, incoming)
}

// dispatch the stream to the appropriate handler
func (n *streamManager) dispatch(ctx context.Context, remotePeer peer.ID, stream network.Stream, incoming bool) {
	if handler, ok := n.handlers[stream.Protocol()]; ok {
		handler(ctx, remotePeer, stream, incoming)
	} else {
		n.log.Errorf("No handler for protocol %s, peer %s", stream.Protocol(), remotePeer)
		_ = stream.Reset()
	}
}

func (n *streamManager) peerWatcher(ctx context.Context, sub event.Subscription) {
	defer sub.Close()
	for e := range sub.Out() {
		evt := e.(event.EvtPeerIdentificationCompleted)
		conn := evt.Conn

		remotePeer := conn.RemotePeer()
		localPeer := n.host.ID()

		if conn.Stat().Direction == network.DirInbound && !n.allowIncomingGossip {
			n.log.Debugf("%s: ignoring incoming connection from %s", localPeer.String(), remotePeer.String())
			continue
		}

		// ensure that only one of the peers initiates the stream
		if localPeer > remotePeer {
			n.log.Debugf("%s: ignoring a lesser peer ID %s", localPeer.String(), remotePeer.String())
			continue
		}

		n.streamsLock.Lock()
		_, ok := n.streams[remotePeer]
		if ok {
			n.streamsLock.Unlock()
			n.log.Debugf("%s: already have a stream to/from %s", localPeer.String(), remotePeer.String())
			continue // there's already an active stream with this peer for our protocol
		}

		protos := evt.Protocols
		var targetProto protocol.ID = AlgorandWsProtocolV1
		// n.handlers[AlgorandWsProtocolV22] check works on pair with disableV22Protocol for testing
		if slices.Contains(protos, AlgorandWsProtocolV22) && n.handlers[AlgorandWsProtocolV22] != nil {
			targetProto = AlgorandWsProtocolV22
		}

		stream, err := n.host.NewStream(n.ctx, remotePeer, targetProto)
		if err != nil {
			n.log.Infof("%s: failed to open stream to %s (%s): %v", localPeer.String(), remotePeer, conn.RemoteMultiaddr().String(), err)
			n.streamsLock.Unlock()
			continue
		}
		n.streams[remotePeer] = stream
		n.streamsLock.Unlock()

		incoming := stream.Conn().Stat().Direction == network.DirInbound
		if handler, ok := n.handlers[targetProto]; ok {
			handler(n.ctx, remotePeer, stream, incoming)
		} else {
			n.log.Errorf("%s: no handler for protocol %s, peer %s", localPeer.String(), targetProto, remotePeer)
			_ = stream.Reset()
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// Connected is called when a connection is opened
// for both incoming (listener -> addConn) and outgoing (dialer -> addConn) connections.
func (n *streamManager) Connected(net network.Network, conn network.Conn) {
}

// Disconnected is called when a connection is closed
func (n *streamManager) Disconnected(net network.Network, conn network.Conn) {
	n.streamsLock.Lock()
	defer n.streamsLock.Unlock()

	stream, ok := n.streams[conn.RemotePeer()]
	if ok {
		stream.Close()
		delete(n.streams, conn.RemotePeer())
	}
}

// Listen is called when network starts listening on an addr
func (n *streamManager) Listen(net network.Network, addr multiaddr.Multiaddr) {}

// ListenClose is called when network stops listening on an addr
func (n *streamManager) ListenClose(net network.Network, addr multiaddr.Multiaddr) {}
