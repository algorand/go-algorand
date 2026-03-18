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
	"io"
	"testing"
	"time"

	connmgrcore "github.com/libp2p/go-libp2p/core/connmgr"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// errDispatchFailed is the sentinel error returned by the failing test handler.
var errDispatchFailed = errors.New("dispatch failed")

const testProto = protocol.ID("/algorand-test/1.0.0")

// mockConnMgr implements connmgrcore.ConnManager for testing.
type mockConnMgr struct {
	mu        deadlock.Mutex
	protected map[peer.ID]map[string]bool
	unprotect map[peer.ID]int
}

func newMockConnMgr() *mockConnMgr {
	return &mockConnMgr{
		protected: make(map[peer.ID]map[string]bool),
		unprotect: make(map[peer.ID]int),
	}
}

func (m *mockConnMgr) Protect(id peer.ID, tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.protected[id] == nil {
		m.protected[id] = make(map[string]bool)
	}
	m.protected[id][tag] = true
}

func (m *mockConnMgr) Unprotect(id peer.ID, tag string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unprotect[id]++
	if m.protected[id] != nil {
		delete(m.protected[id], tag)
	}
	return len(m.protected[id]) > 0
}

func (m *mockConnMgr) IsProtected(id peer.ID, tag string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.protected[id] != nil && m.protected[id][tag]
}

func (m *mockConnMgr) UnprotectCalls(id peer.ID) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unprotect[id]
}

func (m *mockConnMgr) TagPeer(peer.ID, string, int)                {}
func (m *mockConnMgr) UntagPeer(peer.ID, string)                   {}
func (m *mockConnMgr) UpsertTag(peer.ID, string, func(int) int)    {}
func (m *mockConnMgr) GetTagInfo(peer.ID) *connmgrcore.TagInfo     { return nil }
func (m *mockConnMgr) TrimOpenConns(context.Context)               {}
func (m *mockConnMgr) Notifee() network.Notifiee                   { return nil }
func (m *mockConnMgr) CheckLimit(connmgrcore.GetConnLimiter) error { return nil }
func (m *mockConnMgr) Close() error                                { return nil }

// mockHost implements host.Host with only the methods used by streamManager.
type mockHost struct {
	id          peer.ID
	cm          *mockConnMgr
	newStreamFn func(context.Context, peer.ID, ...protocol.ID) (network.Stream, error)
}

func (h *mockHost) ID() peer.ID                          { return h.id }
func (h *mockHost) ConnManager() connmgrcore.ConnManager { return h.cm }
func (h *mockHost) NewStream(ctx context.Context, p peer.ID, pids ...protocol.ID) (network.Stream, error) {
	return h.newStreamFn(ctx, p, pids...)
}

func (h *mockHost) Peerstore() peerstore.Peerstore                      { panic("unused") }
func (h *mockHost) Addrs() []ma.Multiaddr                               { panic("unused") }
func (h *mockHost) Network() network.Network                            { panic("unused") }
func (h *mockHost) Mux() protocol.Switch                                { panic("unused") }
func (h *mockHost) Connect(context.Context, peer.AddrInfo) error        { panic("unused") }
func (h *mockHost) SetStreamHandler(protocol.ID, network.StreamHandler) {}
func (h *mockHost) SetStreamHandlerMatch(protocol.ID, func(protocol.ID) bool, network.StreamHandler) {
}
func (h *mockHost) RemoveStreamHandler(protocol.ID) {}
func (h *mockHost) Close() error                    { return nil }
func (h *mockHost) EventBus() event.Bus             { panic("unused") }

// Verify interface satisfaction at compile time.
var _ host.Host = (*mockHost)(nil)

// mockConn implements network.Conn with controllable direction and peer IDs.
type mockConn struct {
	remotePeerID peer.ID
	localPeerID  peer.ID
	dir          network.Direction
}

func newMockConn(local, remote peer.ID, dir network.Direction) *mockConn {
	return &mockConn{localPeerID: local, remotePeerID: remote, dir: dir}
}

func (c *mockConn) Close() error                       { return nil }
func (c *mockConn) LocalPeer() peer.ID                 { return c.localPeerID }
func (c *mockConn) RemotePeer() peer.ID                { return c.remotePeerID }
func (c *mockConn) RemotePublicKey() ic.PubKey         { return nil }
func (c *mockConn) ConnState() network.ConnectionState { return network.ConnectionState{} }
func (c *mockConn) LocalMultiaddr() ma.Multiaddr       { return ma.StringCast("/ip4/127.0.0.1/tcp/4190") }
func (c *mockConn) RemoteMultiaddr() ma.Multiaddr      { return ma.StringCast("/ip4/1.2.3.4/tcp/4190") }
func (c *mockConn) Stat() network.ConnStats {
	return network.ConnStats{Stats: network.Stats{Direction: c.dir}}
}
func (c *mockConn) Scope() network.ConnScope                          { return nil }
func (c *mockConn) ID() string                                        { return "mock-conn" }
func (c *mockConn) NewStream(context.Context) (network.Stream, error) { panic("unused") }
func (c *mockConn) GetStreams() []network.Stream                      { return nil }
func (c *mockConn) IsClosed() bool                                    { return false }
func (c *mockConn) CloseWithError(network.ConnErrorCode) error        { return nil }
func (c *mockConn) As(any) bool                                       { return false }

var _ network.Conn = (*mockConn)(nil)

// mockStream implements network.Stream with controllable behavior.
type mockStream struct {
	mu          deadlock.Mutex
	conn        *mockConn
	proto       protocol.ID
	dir         network.Direction
	readErr     error // error returned by Read
	resetCalled bool
	closeCalled bool
}

func newMockStream(conn *mockConn, proto protocol.ID, dir network.Direction) *mockStream {
	return &mockStream{conn: conn, proto: proto, dir: dir}
}

func (s *mockStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return 0, s.readErr
	}
	return 0, nil
}

func (s *mockStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *mockStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCalled = true
	return nil
}

func (s *mockStream) CloseRead() error  { return nil }
func (s *mockStream) CloseWrite() error { return nil }

func (s *mockStream) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetCalled = true
	return nil
}

func (s *mockStream) ResetWithError(network.StreamErrorCode) error {
	return s.Reset()
}

func (s *mockStream) SetDeadline(time.Time) error      { return nil }
func (s *mockStream) SetReadDeadline(time.Time) error  { return nil }
func (s *mockStream) SetWriteDeadline(time.Time) error { return nil }
func (s *mockStream) Protocol() protocol.ID            { return s.proto }
func (s *mockStream) SetProtocol(protocol.ID) error    { return nil }
func (s *mockStream) Stat() network.Stats              { return network.Stats{Direction: s.dir} }
func (s *mockStream) Conn() network.Conn               { return s.conn }
func (s *mockStream) ID() string                       { return "mock-stream" }
func (s *mockStream) Scope() network.StreamScope       { return nil }

func (s *mockStream) wasReset() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resetCalled
}

var _ network.Stream = (*mockStream)(nil)

// failingHandler is a StreamHandler that always returns errDispatchFailed.
func failingHandler(_ context.Context, _ peer.ID, _ network.Stream, _ bool) error {
	return errDispatchFailed
}

// newTestStreamManager creates a streamManager with a failing handler for testProto.
func newTestStreamManager(localID peer.ID, allowIncoming bool) (*streamManager, *mockHost) {
	return newTestStreamManagerWithHandler(localID, allowIncoming, failingHandler)
}

func newTestStreamManagerWithHandler(localID peer.ID, allowIncoming bool, handler StreamHandler) (*streamManager, *mockHost) {
	cm := newMockConnMgr()
	h := &mockHost{id: localID, cm: cm}
	handlers := StreamHandlers{
		{ProtoID: testProto, Handler: handler},
	}
	logger := logging.NewLogger()
	logger.SetLevel(logging.Debug)
	sm := makeStreamManager(context.Background(), logger, h, handlers, allowIncoming)
	return sm, h
}

// assertStreamMapEmpty checks that sm.streams has no entry for remotePeer.
func assertStreamMapEmpty(t *testing.T, sm *streamManager, remotePeer peer.ID) {
	t.Helper()
	sm.streamsLock.Lock()
	defer sm.streamsLock.Unlock()
	_, exists := sm.streams[remotePeer]
	require.False(t, exists, "expected n.streams[%s] to be cleaned up after dispatch failure", remotePeer)
}

// --- test cases ---

// TestStream_MapCleanupOnDispatchFailure verifies that n.streams is cleaned up
// when dispatch (V22 handshake) fails, across all 8 combinations:
//
//	directions (inbound/outbound) ×
//	peer ID orderings (local < remote / local > remote) ×
//	dial origins (dialNode / DHT-pubsub)
func TestStream_MapCleanupOnDispatchFailure(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// deterministic peer IDs
	lowPeer := peer.ID("AAAA-low-peer")
	highPeer := peer.ID("ZZZZ-high-peer")
	require.True(t, lowPeer < highPeer)

	// handleConnected path — local node initiates the stream

	// case 1: outbound, localPeer < remotePeer, dialNode
	//  Connected, peer ID passes, protected, handleConnected, dispatch fails
	t.Run("outbound_localLow_dialNode", func(t *testing.T) {
		t.Parallel()
		sm, h := newTestStreamManager(lowPeer, true)
		conn := newMockConn(lowPeer, highPeer, network.DirOutbound)
		stream := newMockStream(conn, testProto, network.DirOutbound)
		h.newStreamFn = func(context.Context, peer.ID, ...protocol.ID) (network.Stream, error) {
			return stream, nil
		}
		// dialNode would have protected the peer before dialing
		h.cm.Protect(highPeer, cnmgrTag)

		sm.handleConnected(conn)

		assertStreamMapEmpty(t, sm, highPeer)
		require.True(t, stream.wasReset())
		require.False(t, h.cm.IsProtected(highPeer, cnmgrTag))
	})

	// case 2: outbound, localPeer < remotePeer, DHT dial
	//  Connected skips (unprotected). DialPeersUntilTargetCount, Protect, handleConnected, dispatch fails
	t.Run("outbound_localLow_dhtDial", func(t *testing.T) {
		t.Parallel()
		sm, h := newTestStreamManager(lowPeer, true)
		conn := newMockConn(lowPeer, highPeer, network.DirOutbound)
		stream := newMockStream(conn, testProto, network.DirOutbound)
		h.newStreamFn = func(context.Context, peer.ID, ...protocol.ID) (network.Stream, error) {
			return stream, nil
		}
		// DialPeersUntilTargetCount protects then calls handleConnected
		h.cm.Protect(highPeer, cnmgrTag)

		sm.handleConnected(conn)

		assertStreamMapEmpty(t, sm, highPeer)
		require.True(t, stream.wasReset())
		require.False(t, h.cm.IsProtected(highPeer, cnmgrTag))
	})

	// case 3: outbound, localPeer > remotePeer, DHT dial
	//  Connected defers (peer ID). Remote's stream rejected (unprotected outbound).
	//  DialPeersUntilTargetCount, Protect, handleConnected (new code skips peer ID check), dispatch fails
	t.Run("outbound_localHigh_dhtDial", func(t *testing.T) {
		t.Parallel()
		sm, h := newTestStreamManager(highPeer, true)
		conn := newMockConn(highPeer, lowPeer, network.DirOutbound)
		stream := newMockStream(conn, testProto, network.DirOutbound)
		h.newStreamFn = func(context.Context, peer.ID, ...protocol.ID) (network.Stream, error) {
			return stream, nil
		}
		h.cm.Protect(lowPeer, cnmgrTag)

		sm.handleConnected(conn)

		assertStreamMapEmpty(t, sm, lowPeer)
		require.True(t, stream.wasReset())
		require.False(t, h.cm.IsProtected(lowPeer, cnmgrTag))
	})

	// case 4: inbound, localPeer < remotePeer, remote's dialNode dialed
	//  Connected, inbound gossip OK, peer ID passes, handleConnected, dispatch fails
	t.Run("inbound_localLow_remoteDial", func(t *testing.T) {
		t.Parallel()
		sm, h := newTestStreamManager(lowPeer, true)
		conn := newMockConn(lowPeer, highPeer, network.DirInbound)
		stream := newMockStream(conn, testProto, network.DirInbound)
		h.newStreamFn = func(context.Context, peer.ID, ...protocol.ID) (network.Stream, error) {
			return stream, nil
		}

		sm.handleConnected(conn)

		assertStreamMapEmpty(t, sm, highPeer)
		require.True(t, stream.wasReset())
	})

	// case 5: inbound, localPeer < remotePeer, remote's DHT dialed
	t.Run("inbound_localLow_remoteDHT", func(t *testing.T) {
		t.Parallel()
		sm, h := newTestStreamManager(lowPeer, true)
		conn := newMockConn(lowPeer, highPeer, network.DirInbound)
		stream := newMockStream(conn, testProto, network.DirInbound)
		h.newStreamFn = func(context.Context, peer.ID, ...protocol.ID) (network.Stream, error) {
			return stream, nil
		}
		// No protection from our side (remote's inbound conn)

		sm.handleConnected(conn)

		assertStreamMapEmpty(t, sm, highPeer)
		require.True(t, stream.wasReset())
		// Unprotect was called but was a no-op (nothing was protected)
		require.False(t, h.cm.IsProtected(highPeer, cnmgrTag))
	})

	// streamHandler path — remote peer creates the stream, our node handles it

	// case 6: outbound, localPeer > remotePeer, our dialNode
	//  Connected defers (peer ID). Remote opens stream, our streamHandler, dispatch fails
	t.Run("outbound_localHigh_ourDial", func(t *testing.T) {
		t.Parallel()
		sm, h := newTestStreamManager(highPeer, true)
		// Connection is outbound (we dialed), stream is inbound (remote initiated)
		conn := newMockConn(highPeer, lowPeer, network.DirOutbound)
		stream := newMockStream(conn, testProto, network.DirInbound)
		// Our dialNode protected this peer
		h.cm.Protect(lowPeer, cnmgrTag)

		sm.streamHandler(stream)

		assertStreamMapEmpty(t, sm, lowPeer)
		require.True(t, stream.wasReset())
		// dispatched=false => Unprotect called
		require.False(t, h.cm.IsProtected(lowPeer, cnmgrTag))
	})

	// case 7: inbound, localPeer > remotePeer, remote's dialNode dialed us
	//  Connected defers (peer ID). Remote opens stream, our streamHandler, dispatch fails
	t.Run("inbound_localHigh_remoteDial", func(t *testing.T) {
		t.Parallel()
		sm, h := newTestStreamManager(highPeer, true)
		// Connection is inbound (remote dialed us), stream is inbound (remote initiated)
		conn := newMockConn(highPeer, lowPeer, network.DirInbound)
		stream := newMockStream(conn, testProto, network.DirInbound)

		sm.streamHandler(stream)

		assertStreamMapEmpty(t, sm, lowPeer)
		require.True(t, stream.wasReset())
		// No protection was set, so Unprotect is a no-op
		require.False(t, h.cm.IsProtected(lowPeer, cnmgrTag))
	})

	// case 8: inbound, localPeer > remotePeer, remote's DHT dialed us
	//  Connected defers (peer ID). Remote's DHT connection;
	//  remote opens stream, our streamHandler, dispatch fails
	t.Run("inbound_localHigh_remoteDHT", func(t *testing.T) {
		t.Parallel()
		sm, h := newTestStreamManager(highPeer, true)
		conn := newMockConn(highPeer, lowPeer, network.DirInbound)
		stream := newMockStream(conn, testProto, network.DirInbound)

		sm.streamHandler(stream)

		assertStreamMapEmpty(t, sm, lowPeer)
		require.True(t, stream.wasReset())
		require.False(t, h.cm.IsProtected(lowPeer, cnmgrTag))
	})
}

// TestStream_HandlerKeepsOldStreamOnDispatchFailure verifies that when a new
// stream arrives but dispatch fails, the existing stream is preserved.
func TestStream_HandlerKeepsOldStreamOnDispatchFailure(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	localID := peer.ID("ZZZZ-high-peer")
	remoteID := peer.ID("AAAA-low-peer")
	sm, h := newTestStreamManager(localID, true)

	// Pre-populate n.streams with an existing stream
	conn := newMockConn(localID, remoteID, network.DirInbound)
	oldStream := newMockStream(conn, testProto, network.DirInbound)
	sm.streams[remoteID] = oldStream

	// Protect so that Unprotect tracking works
	h.cm.Protect(remoteID, cnmgrTag)
	// New stream arrives from remote peer, dispatch will fail
	newStream := newMockStream(conn, testProto, network.DirInbound)
	sm.streamHandler(newStream)

	// Old stream is kept because new dispatch failed
	sm.streamsLock.Lock()
	current, exists := sm.streams[remoteID]
	sm.streamsLock.Unlock()
	require.True(t, exists, "old stream should still be in the map")
	require.Equal(t, oldStream, current, "map should still reference the old stream")
	require.False(t, oldStream.closeCalled, "old stream should not be closed")
	require.True(t, newStream.wasReset(), "new stream should be reset on dispatch failure")
	require.True(t, h.cm.IsProtected(remoteID, cnmgrTag), "peer should remain conn-manager protected after failed replacement")
}

// blockingMockStream wraps mockStream but makes Read block until the stream is
// explicitly unblocked or closed, simulating a live yamux stream with no data.
type blockingMockStream struct {
	mockStream
	readStarted chan struct{}
	unblockRead chan struct{}
}

func newBlockingMockStream(conn *mockConn, proto protocol.ID, dir network.Direction) *blockingMockStream {
	return &blockingMockStream{
		mockStream:  mockStream{conn: conn, proto: proto, dir: dir},
		readStarted: make(chan struct{}),
		unblockRead: make(chan struct{}),
	}
}

func (s *blockingMockStream) Read(p []byte) (int, error) {
	select {
	case <-s.readStarted:
	default:
		close(s.readStarted)
	}
	<-s.unblockRead
	return 0, io.EOF
}

func (s *blockingMockStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCalled = true
	// Unblock any pending Read.
	select {
	case <-s.unblockRead:
	default:
		close(s.unblockRead)
	}
	return nil
}

func (s *blockingMockStream) readWasStarted() bool {
	select {
	case <-s.readStarted:
		return true
	default:
		return false
	}
}

func closeSignal(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

// TestStream_HandlerDispatchesBeforeTouchingOldStream verifies that
// streamHandler starts dispatch before interacting with any existing stream.
// The pre-fix code called oldStream.Read while holding streamsLock, so this
// test fails immediately if that regression returns.
func TestStream_HandlerDispatchesBeforeTouchingOldStream(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	localID := peer.ID("ZZZZ-high-peer")
	remoteID := peer.ID("AAAA-low-peer")
	dispatchStarted := make(chan struct{})
	dispatchRelease := make(chan struct{})
	handler := func(_ context.Context, _ peer.ID, _ network.Stream, _ bool) error {
		closeSignal(dispatchStarted)
		<-dispatchRelease
		return nil
	}
	sm, h := newTestStreamManagerWithHandler(localID, true, handler)
	conn := newMockConn(localID, remoteID, network.DirInbound)

	oldStream := newBlockingMockStream(conn, testProto, network.DirInbound)
	sm.streams[remoteID] = oldStream
	h.cm.Protect(remoteID, cnmgrTag)
	t.Cleanup(func() {
		closeSignal(dispatchRelease)
		_ = oldStream.Close()
	})

	newStream := newMockStream(conn, testProto, network.DirInbound)
	streamHandlerDone := make(chan struct{})
	go func() {
		sm.streamHandler(newStream)
		close(streamHandlerDone)
	}()

	select {
	case <-dispatchStarted:
	case <-oldStream.readStarted:
		t.Fatal("streamHandler tried to read the old stream before starting dispatch")
	case <-time.After(2 * time.Second):
		t.Fatal("streamHandler did not start dispatch")
	}

	closeSignal(dispatchRelease)

	require.False(t, oldStream.readWasStarted(), "old stream should never be read")
	select {
	case <-streamHandlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("streamHandler did not complete after dispatch was released")
	}
	require.False(t, oldStream.readWasStarted(), "old stream should never be read")

	sm.streamsLock.Lock()
	current, exists := sm.streams[remoteID]
	sm.streamsLock.Unlock()
	require.True(t, exists, "replacement stream should be tracked")
	require.Equal(t, newStream, current, "replacement stream should be installed in the map")
	require.True(t, oldStream.closeCalled, "old stream should be closed after replacement")
}

// TestStream_DisconnectedCanRunWhileDispatchIsBlocked verifies that
// Disconnected is not blocked by streamHandler while the new stream's dispatch
// is in progress. The pre-fix implementation held streamsLock across a blocking
// Read on the old stream, which prevented Disconnected from making progress.
func TestStream_DisconnectedCanRunWhileDispatchIsBlocked(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	localID := peer.ID("ZZZZ-high-peer")
	remoteID := peer.ID("AAAA-low-peer")
	dispatchStarted := make(chan struct{})
	dispatchRelease := make(chan struct{})
	handler := func(_ context.Context, _ peer.ID, _ network.Stream, _ bool) error {
		closeSignal(dispatchStarted)
		<-dispatchRelease
		return nil
	}
	sm, h := newTestStreamManagerWithHandler(localID, true, handler)
	conn := newMockConn(localID, remoteID, network.DirInbound)

	oldStream := newBlockingMockStream(conn, testProto, network.DirInbound)
	sm.streams[remoteID] = oldStream
	h.cm.Protect(remoteID, cnmgrTag)
	t.Cleanup(func() {
		closeSignal(dispatchRelease)
		_ = oldStream.Close()
	})

	newStream := newMockStream(conn, testProto, network.DirInbound)
	streamHandlerDone := make(chan struct{})
	go func() {
		sm.streamHandler(newStream)
		close(streamHandlerDone)
	}()

	select {
	case <-dispatchStarted:
	case <-oldStream.readStarted:
		t.Fatal("streamHandler tried to read the old stream before starting dispatch")
	case <-time.After(2 * time.Second):
		t.Fatal("streamHandler did not start dispatch")
	}

	disconnectedDone := make(chan struct{})
	go func() {
		sm.Disconnected(nil, conn)
		close(disconnectedDone)
	}()

	select {
	case <-disconnectedDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnected blocked while streamHandler was dispatching")
	}

	require.False(t, oldStream.readWasStarted(), "old stream should never be read")
	sm.streamsLock.Lock()
	_, exists := sm.streams[remoteID]
	sm.streamsLock.Unlock()
	require.False(t, exists, "Disconnected should remove the old stream while dispatch is blocked")

	closeSignal(dispatchRelease)

	select {
	case <-streamHandlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("streamHandler did not complete after dispatch was released")
	}

	require.False(t, oldStream.readWasStarted(), "old stream should never be read")
	sm.streamsLock.Lock()
	current, exists := sm.streams[remoteID]
	sm.streamsLock.Unlock()
	require.True(t, exists, "replacement stream should be tracked after dispatch completes")
	require.Equal(t, newStream, current, "replacement stream should be installed after disconnect cleanup")
}

func TestStream_ConcurrentFailureDoesNotUnprotectWhileAnotherAttemptInFlight(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	localID := peer.ID("ZZZZ-high-peer")
	remoteID := peer.ID("AAAA-low-peer")
	conn := newMockConn(localID, remoteID, network.DirInbound)

	var successStream *mockStream
	var failStream *mockStream
	successStarted := make(chan struct{})
	releaseSuccess := make(chan struct{})
	handler := func(_ context.Context, _ peer.ID, s network.Stream, _ bool) error {
		switch s {
		case successStream:
			closeSignal(successStarted)
			<-releaseSuccess
			return nil
		case failStream:
			return errDispatchFailed
		default:
			return nil
		}
	}
	sm, h := newTestStreamManagerWithHandler(localID, true, handler)
	h.cm.Protect(remoteID, cnmgrTag)
	successStream = newMockStream(conn, testProto, network.DirInbound)
	failStream = newMockStream(conn, testProto, network.DirInbound)

	successDone := make(chan struct{})
	go func() {
		sm.streamHandler(successStream)
		close(successDone)
	}()

	select {
	case <-successStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("success dispatch did not start")
	}

	failDone := make(chan struct{})
	go func() {
		sm.streamHandler(failStream)
		close(failDone)
	}()
	select {
	case <-failDone:
	case <-time.After(2 * time.Second):
		t.Fatal("failed dispatch did not complete")
	}

	require.True(t, h.cm.IsProtected(remoteID, cnmgrTag), "failed attempt must not unprotect while another attempt is in flight")
	require.Equal(t, 0, h.cm.UnprotectCalls(remoteID), "no unprotect should happen before the in-flight attempt completes")

	closeSignal(releaseSuccess)
	select {
	case <-successDone:
	case <-time.After(2 * time.Second):
		t.Fatal("success dispatch did not complete")
	}

	sm.streamsLock.Lock()
	current, exists := sm.streams[remoteID]
	sm.streamsLock.Unlock()
	require.True(t, exists, "successful stream should be tracked")
	require.Equal(t, successStream, current, "successful stream should be in the map")
	require.True(t, h.cm.IsProtected(remoteID, cnmgrTag), "peer should remain protected after successful stream install")
	require.Equal(t, 0, h.cm.UnprotectCalls(remoteID), "successful stream install should not unprotect")
	require.True(t, failStream.wasReset(), "failed stream should be reset")
}

func TestStream_ConcurrentFailedAttemptsUnprotectOnce(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	localID := peer.ID("ZZZZ-high-peer")
	remoteID := peer.ID("AAAA-low-peer")
	conn := newMockConn(localID, remoteID, network.DirInbound)

	var streamA *mockStream
	var streamB *mockStream
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	handler := func(_ context.Context, _ peer.ID, s network.Stream, _ bool) error {
		switch s {
		case streamA, streamB:
			started <- struct{}{}
			<-release
			return errDispatchFailed
		default:
			return errDispatchFailed
		}
	}
	sm, h := newTestStreamManagerWithHandler(localID, true, handler)
	h.cm.Protect(remoteID, cnmgrTag)
	streamA = newMockStream(conn, testProto, network.DirInbound)
	streamB = newMockStream(conn, testProto, network.DirInbound)

	doneA := make(chan struct{})
	go func() {
		sm.streamHandler(streamA)
		close(doneA)
	}()
	doneB := make(chan struct{})
	go func() {
		sm.streamHandler(streamB)
		close(doneB)
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("expected both dispatch attempts to start")
		}
	}
	closeSignal(release)

	select {
	case <-doneA:
	case <-time.After(2 * time.Second):
		t.Fatal("first failed dispatch did not complete")
	}
	select {
	case <-doneB:
	case <-time.After(2 * time.Second):
		t.Fatal("second failed dispatch did not complete")
	}

	sm.streamsLock.Lock()
	_, exists := sm.streams[remoteID]
	sm.streamsLock.Unlock()
	require.False(t, exists, "no stream should remain after two failed attempts")
	require.False(t, h.cm.IsProtected(remoteID, cnmgrTag), "peer should be unprotected after all attempts failed")
	require.Equal(t, 1, h.cm.UnprotectCalls(remoteID), "peer should be unprotected exactly once")
	require.True(t, streamA.wasReset(), "first failed stream should be reset")
	require.True(t, streamB.wasReset(), "second failed stream should be reset")
}
