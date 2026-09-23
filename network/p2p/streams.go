// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"sync"
	"time"

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

// handlersCloseTimeout bounds how long streamManager.close waits for in-flight
// stream handlers on shutdown. It matches peerDisconnectionAckDuration in the
// network package (which cannot be imported from here): by the time close runs
// the host is already closed, so handler I/O has been interrupted and anything
// still running this long is stuck, not slow. Rather than hang algod shutdown,
// close gives up and logs a warning naming the peers involved.
const handlersCloseTimeout = 5 * time.Second

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

	// handlersWg tracks handler goroutines (handleConnected, streamHandler) that run
	// outside of libp2p's notifiee lock so that close() can wait for them.
	// closed is guarded by closeLock and prevents new handlers from starting
	// once close() has begun. The lock makes the closed check and the Add atomic
	// with respect to close(), so Add never races with Wait.
	// closeTimeout bounds the wait in close(); it is a field so tests can shorten it.
	handlersWg   sync.WaitGroup
	closeLock    deadlock.Mutex
	closed       bool
	closeTimeout time.Duration
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
		closeTimeout:        handlersCloseTimeout,
	}
}

// beginHandler registers a new handler goroutine with handlersWg.
// It returns false if the stream manager is closing and no new work should start.
func (n *streamManager) beginHandler() bool {
	n.closeLock.Lock()
	defer n.closeLock.Unlock()
	if n.closed {
		return false
	}
	n.handlersWg.Add(1)
	return true
}

// endHandler marks a handler registered with beginHandler as finished.
func (n *streamManager) endHandler() {
	n.handlersWg.Done()
}

// goHandleConnected runs handleConnected for conn in a new goroutine tracked by handlersWg,
// so that close() waits for it. It returns false without spawning anything if the
// stream manager is closing. This is the only way handleConnected should be started
// asynchronously: an untracked goroutine can outlive the service and log after shutdown.
func (n *streamManager) goHandleConnected(conn network.Conn) bool {
	if !n.beginHandler() {
		return false
	}
	go func() {
		defer n.endHandler()
		n.handleConnected(conn)
	}()
	return true
}

// close prevents new handlers from starting and waits for in-flight ones to finish.
// It must be called after the host has been closed (or the context cancelled) so that
// any blocking stream I/O inside handlers is interrupted, and after StopNotify so that
// no new Connected callbacks arrive.
// The wait is bounded by closeTimeout: a handler still running past that point is
// considered stuck and is abandoned with a warning so that shutdown can proceed.
func (n *streamManager) close() {
	n.closeLock.Lock()
	n.closed = true
	n.closeLock.Unlock()

	done := make(chan struct{})
	go func() {
		n.handlersWg.Wait()
		close(done)
	}()

	timer := time.NewTimer(n.closeTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		n.log.Warnf("%s: timed out after %v waiting for stream handlers to finish, in-flight peers: %v",
			n.host.ID().String(), n.closeTimeout, n.inflightPeers())
	}
}

// inflightPeers returns the peers that currently have a stream handler attempt in progress.
// It is used for diagnostics only.
func (n *streamManager) inflightPeers() []peer.ID {
	n.streamsLock.Lock()
	defer n.streamsLock.Unlock()
	peers := make([]peer.ID, 0, len(n.inflight))
	for p := range n.inflight {
		peers = append(peers, p)
	}
	return peers
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
	if !n.beginHandler() {
		// shutting down, do not start handling new streams
		_ = stream.Reset()
		return
	}
	defer n.endHandler()

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
// The goroutine is tracked by handlersWg so that close() can wait for it: otherwise it may
// outlive the service and log (or touch state) after shutdown has completed.
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

	if !n.goHandleConnected(conn) {
		n.log.Debugf("%s: ignoring connection from %s, shutting down", localPeer.String(), remotePeer.String())
	}
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
