// Copyright (C) 2019-2026 Algorand, Inc.
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
	"io"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/logging"
)

// streamManager implements network.Notifiee to create and manage streams for use with non-gossipsub protocols.
type streamManager struct {
	ctx                 context.Context
	log                 logging.Logger
	host                host.Host
	handlers            StreamHandlers
	allowIncomingGossip bool

	streams     map[peer.ID]network.Stream
	streamsLock deadlock.Mutex
}

// StreamHandler is called when a new bidirectional stream for a given protocol and peer is opened.
type StreamHandler func(ctx context.Context, pid peer.ID, s network.Stream, incoming bool) error

func makeStreamManager(ctx context.Context, log logging.Logger, h host.Host, handlers StreamHandlers, allowIncomingGossip bool) *streamManager {
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
	dispatched := false
	remotePeer := stream.Conn().RemotePeer()

	defer func() {
		if !dispatched {
			n.host.ConnManager().Unprotect(remotePeer, cnmgrTag)
		}
	}()

	if stream.Conn().Stat().Direction == network.DirInbound && !n.allowIncomingGossip {
		n.log.Debugf("rejecting stream from incoming connection from %s", remotePeer.String())
		stream.Close()
		return
	}
	// reject streams on connections not explicitly dialed by us
	if stream.Conn().Stat().Direction == network.DirOutbound && stream.Stat().Direction == network.DirInbound {
		if !n.host.ConnManager().IsProtected(remotePeer, cnmgrTag) {
			n.log.Debugf("%s: ignoring incoming stream from non-dialed outgoing peer ID %s", stream.Conn().LocalPeer().String(), remotePeer.String())
			stream.Close()
			return
		}
	}

	n.streamsLock.Lock()
	defer n.streamsLock.Unlock()

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
			if err1 := n.dispatch(n.ctx, remotePeer, stream, incoming); err1 != nil {
				n.log.Errorln(err1.Error())
				_ = stream.Reset()
				return
			}
			dispatched = true
			return
		}
		// otherwise, the old stream is still open, so we can close the new one
		stream.Close()
		dispatched = true
		return
	}
	// no old stream
	n.streams[stream.Conn().RemotePeer()] = stream
	incoming := stream.Conn().Stat().Direction == network.DirInbound
	if err := n.dispatch(n.ctx, remotePeer, stream, incoming); err != nil {
		n.log.Errorln(err.Error())
		_ = stream.Reset()
		return
	}

	dispatched = true
}

// dispatch the stream to the appropriate handler
func (n *streamManager) dispatch(ctx context.Context, remotePeer peer.ID, stream network.Stream, incoming bool) error {
	for _, pair := range n.handlers {
		if pair.ProtoID == stream.Protocol() {
			return pair.Handler(ctx, remotePeer, stream, incoming)
		}
	}
	n.log.Errorf("No handler for protocol %s, peer %s", stream.Protocol(), remotePeer)
	return fmt.Errorf("%s: no handler for protocol %s, peer %s", n.host.ID().String(), stream.Protocol(), remotePeer)
}

// Connected is called when a connection is opened
// for both incoming (listener -> addConn) and outgoing (dialer -> addConn) connections.
// This is invoked from libp2p's Swarm.notifyAll which holds a read lock on the notifiees list.
// We do some read/write operations in this handler for metadata exchange that creates a race condition
// with StopNotify on network shutdown. To avoid, run the handler as a goroutine.
func (n *streamManager) Connected(net network.Network, conn network.Conn) {
	go n.handleConnected(conn)
}

func (n *streamManager) handleConnected(conn network.Conn) {
	dispatched := false
	defer func() {
		if !dispatched {
			n.host.ConnManager().Unprotect(conn.RemotePeer(), cnmgrTag)
		}
	}()
	remotePeer := conn.RemotePeer()
	localPeer := n.host.ID()

	if conn.Stat().Direction == network.DirInbound && !n.allowIncomingGossip {
		n.log.Debugf("%s: ignoring incoming connection from %s", localPeer.String(), remotePeer.String())
		return
	}

	// ensure that only one of the peers initiates the stream.
	// the remote peer will open the stream and our streamHandler will handle it,
	// so mark dispatched to preserve the cnmgr protection set by dialNode.
	if localPeer > remotePeer {
		n.log.Debugf("%s: ignoring a lesser peer ID %s", localPeer.String(), remotePeer.String())
		dispatched = true
		return
	}

	// check if this is outgoing connection but made not by us (serviceImpl.dialNode)
	// then it was made by some sub component like pubsub, ignore
	if conn.Stat().Direction == network.DirOutbound {
		if !n.host.ConnManager().IsProtected(remotePeer, cnmgrTag) {
			n.log.Debugf("%s: ignoring non-dialed outgoing peer ID %s", localPeer.String(), remotePeer.String())
			return
		}
	}

	n.streamsLock.Lock()
	_, ok := n.streams[remotePeer]
	if ok {
		n.streamsLock.Unlock()
		n.log.Debugf("%s: already have a stream to/from %s", localPeer.String(), remotePeer.String())
		dispatched = true
		return // there's already an active stream with this peer for our protocol
	}

	protos := []protocol.ID{}
	for _, pair := range n.handlers {
		protos = append(protos, pair.ProtoID)
	}
	stream, err := n.host.NewStream(n.ctx, remotePeer, protos...)
	if err != nil {
		n.log.Infof("%s: failed to open stream to %s (%s): %v", localPeer.String(), remotePeer, conn.RemoteMultiaddr().String(), err)
		n.streamsLock.Unlock()
		return
	}
	n.streams[remotePeer] = stream
	n.streamsLock.Unlock()

	n.log.Infof("%s: using protocol %s with peer %s", localPeer.String(), stream.Protocol(), remotePeer.String())

	incoming := stream.Conn().Stat().Direction == network.DirInbound
	if err = n.dispatch(n.ctx, remotePeer, stream, incoming); err != nil {
		n.log.Errorln(err.Error())
		_ = stream.Reset()
		return
	}

	dispatched = true
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
