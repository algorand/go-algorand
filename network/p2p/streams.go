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
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/logging"
)

// StreamHandlerLoggedError is an error with an associated log level.
// Stream handlers return this to indicate the severity of the error
// so that callers can log at the appropriate level instead of always
// logging at Error level.
type StreamHandlerLoggedError struct {
	Err   error
	Level logging.Level
}

func (e *StreamHandlerLoggedError) Error() string { return e.Err.Error() }
func (e *StreamHandlerLoggedError) Unwrap() error { return e.Err }

// streamManager implements network.Notifiee to create and manage streams for use with non-gossipsub protocols.
type streamManager struct {
	ctx                 context.Context
	log                 logging.Logger
	host                host.Host
	handlers            StreamHandlers
	allowIncomingGossip bool

	streams     map[peer.ID]network.Stream
	inflight    map[peer.ID]int
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
		inflight:            make(map[peer.ID]int),
	}
}

func (n *streamManager) beginPeerAttempt(remotePeer peer.ID) {
	n.streamsLock.Lock()
	n.inflight[remotePeer]++
	n.streamsLock.Unlock()
}

func (n *streamManager) endPeerAttempt(remotePeer peer.ID) {
	shouldUnprotect := false

	n.streamsLock.Lock()
	if count := n.inflight[remotePeer]; count <= 1 {
		delete(n.inflight, remotePeer)
	} else {
		n.inflight[remotePeer] = count - 1
	}
	_, hasStream := n.streams[remotePeer]
	_, hasInflight := n.inflight[remotePeer]
	shouldUnprotect = !hasStream && !hasInflight
	n.streamsLock.Unlock()

	if shouldUnprotect {
		n.host.ConnManager().Unprotect(remotePeer, cnmgrTag)
	}
}

// streamHandler is called by libp2p when a new stream is accepted
func (n *streamManager) streamHandler(stream network.Stream) {
	remotePeer := stream.Conn().RemotePeer()
	n.beginPeerAttempt(remotePeer)
	defer n.endPeerAttempt(remotePeer)

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

	// Never do blocking I/O (like stream.Read) while holding streamsLock —
	// that causes a deadlock with Disconnected which also needs the lock to
	// close the old stream.
	//
	// Dispatch the new stream first (outside the lock), then swap the map
	// entry only on success. This avoids dropping a healthy old stream when
	// the replacement fails dispatch.
	incoming := stream.Conn().Stat().Direction == network.DirInbound
	if err := n.dispatch(n.ctx, remotePeer, stream, incoming); err != nil {
		n.logDispatchError(err)
		_ = stream.Reset()
		return
	}

	n.streamsLock.Lock()
	// If the connection closed while we were dispatching, Disconnected has
	// already fired (or will fire) and won't find this entry to clean up.
	// Avoid adding a stale stream to the map.
	if stream.Conn().IsClosed() {
		n.streamsLock.Unlock()
		_ = stream.Reset()
		return
	}
	oldStream := n.streams[remotePeer]
	n.streams[remotePeer] = stream
	n.streamsLock.Unlock()

	if oldStream != nil {
		n.log.Infof("Replacing old stream with %s", remotePeer)
		oldStream.Close()
	}
}

// logDispatchError logs an error returned by dispatch at the appropriate level.
// StreamHandlerLoggedError errors are logged at their specified level;
// unwrapped errors are logged at Error level.
func (n *streamManager) logDispatchError(err error) {
	var le *StreamHandlerLoggedError
	if errors.As(err, &le) {
		switch le.Level {
		case logging.Debug:
			n.log.Debugln(le.Error())
		case logging.Info:
			n.log.Infoln(le.Error())
		case logging.Warn:
			n.log.Warnln(le.Error())
		default:
			n.log.Errorln(le.Error())
		}
		return
	}
	n.log.Errorln(err.Error())
}

// dispatch the stream to the appropriate handler
func (n *streamManager) dispatch(ctx context.Context, remotePeer peer.ID, stream network.Stream, incoming bool) error {
	for _, pair := range n.handlers {
		if pair.ProtoID == stream.Protocol() {
			return pair.Handler(ctx, remotePeer, stream, incoming)
		}
	}
	return fmt.Errorf("%s: no handler for protocol %s, peer %s", n.host.ID().String(), stream.Protocol(), remotePeer)
}

// Connected is called when a connection is opened
// for both incoming (listener -> addConn) and outgoing (dialer -> addConn) connections.
// This is invoked from libp2p's Swarm.notifyAll which holds a read lock on the notifiees list.
// We do some read/write operations in this handler for metadata exchange that creates a race condition
// with StopNotify on network shutdown. To avoid, run the handler as a goroutine.
func (n *streamManager) Connected(net network.Network, conn network.Conn) {
	remotePeer := conn.RemotePeer()
	localPeer := n.host.ID()

	if conn.Stat().Direction == network.DirInbound && !n.allowIncomingGossip {
		n.log.Debugf("%s: ignoring incoming connection from %s", localPeer.String(), remotePeer.String())
		n.host.ConnManager().Unprotect(conn.RemotePeer(), cnmgrTag)
		return
	}

	// ensure that only one of the peers initiates the stream.
	// the remote peer will open the stream and our streamHandler will handle it,
	// so mark dispatched to preserve the cnmgr protection set by dialNode.
	if localPeer > remotePeer {
		n.log.Debugf("%s: ignoring a lesser peer ID %s", localPeer.String(), remotePeer.String())
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

	go n.handleConnected(conn)
}

func (n *streamManager) handleConnected(conn network.Conn) {
	remotePeer := conn.RemotePeer()
	localPeer := n.host.ID()
	n.beginPeerAttempt(remotePeer)
	defer n.endPeerAttempt(remotePeer)

	n.streamsLock.Lock()
	_, ok := n.streams[remotePeer]
	n.streamsLock.Unlock()
	if ok {
		n.log.Debugf("%s: already have a stream to/from %s", localPeer.String(), remotePeer.String())
		return // there's already an active stream with this peer for our protocol
	}

	protos := []protocol.ID{}
	for _, pair := range n.handlers {
		protos = append(protos, pair.ProtoID)
	}
	stream, err := n.host.NewStream(n.ctx, remotePeer, protos...)
	if err != nil {
		n.log.Infof("%s: failed to open stream to %s (%s): %v", localPeer.String(), remotePeer, conn.RemoteMultiaddr().String(), err)
		return
	}
	n.log.Infof("%s: using protocol %s with peer %s", localPeer.String(), stream.Protocol(), remotePeer.String())

	incoming := stream.Conn().Stat().Direction == network.DirInbound
	if err = n.dispatch(n.ctx, remotePeer, stream, incoming); err != nil {
		n.logDispatchError(err)
		_ = stream.Reset()
		return
	}

	n.streamsLock.Lock()
	defer n.streamsLock.Unlock()
	if _, exists := n.streams[remotePeer]; exists {
		// another stream was added in the meantime, close this one and keep the existing one
		_ = stream.Reset()
		return
	}
	// don't add disconnected / died conns, so Disconnect won't need to clean up
	if stream.Conn().IsClosed() {
		_ = stream.Reset()
		return
	}
	n.streams[remotePeer] = stream
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
