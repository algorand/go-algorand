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
	"io"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-deadlock"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// streamManager implements network.Notifiee to create and manage streams for use with non-gossipsub protocols.
type streamManager struct {
	ctx                 context.Context
	log                 logging.Logger
	host                host.Host
	handler             StreamHandler
	allowIncomingGossip bool

	streams     map[peer.ID]network.Stream
	streamsLock deadlock.Mutex
}

// StreamHandler is called when a new bidirectional stream for a given protocol and peer is opened.
type StreamHandler func(ctx context.Context, pid peer.ID, s network.Stream, incoming bool)

func makeStreamManager(ctx context.Context, log logging.Logger, h host.Host, handler StreamHandler, allowIncomingGossip bool) *streamManager {
	return &streamManager{
		ctx:                 ctx,
		log:                 log,
		host:                h,
		handler:             handler,
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
			n.handler(n.ctx, remotePeer, stream, incoming)
			return
		}
		// otherwise, the old stream is still open, so we can close the new one
		stream.Close()
		return
	}
	// no old stream
	n.streams[stream.Conn().RemotePeer()] = stream
	incoming := stream.Conn().Stat().Direction == network.DirInbound
	n.handler(n.ctx, remotePeer, stream, incoming)
}

// Connected is called when a connection is opened
// for both incoming (listener -> addConn) and outgoing (dialer -> addConn) connections.
func (n *streamManager) Connected(net network.Network, conn network.Conn) {
	if conn.Stat().Direction == network.DirInbound && !n.allowIncomingGossip {
		n.log.Debugf("ignoring incoming connection from %s", conn.RemotePeer().String())
		return
	}

	remotePeer := conn.RemotePeer()
	localPeer := n.host.ID()

	// ensure that only one of the peers initiates the stream
	if localPeer > remotePeer {
		return
	}

	needUnlock := true
	n.streamsLock.Lock()
	defer func() {
		if needUnlock {
			n.streamsLock.Unlock()
		}
	}()
	_, ok := n.streams[remotePeer]
	if ok {
		return // there's already an active stream with this peer for our protocol
	}

	stream, err := n.host.NewStream(n.ctx, remotePeer, AlgorandWsProtocol)
	if err != nil {
		n.log.Infof("Failed to open stream to %s (%s): %v", remotePeer, conn.RemoteMultiaddr().String(), err)
		return
	}
	n.streams[remotePeer] = stream

	// release the lock to let handler do its thing
	// otherwise reading/writing to the stream will deadlock
	needUnlock = false
	n.streamsLock.Unlock()

	incoming := stream.Conn().Stat().Direction == network.DirInbound
	n.handler(n.ctx, remotePeer, stream, incoming)
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
