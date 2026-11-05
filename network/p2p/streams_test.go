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
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// syncBuffer is a thread-safe bytes.Buffer for use as a log output target.
type syncBuffer struct {
	mu  deadlock.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Write(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(p)
}

func (sb *syncBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.String()
}

func (sb *syncBuffer) Reset() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.buf.Reset()
}

func TestLogDispatchErrorDebugLevel(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	logBuffer := &syncBuffer{}
	logger := logging.NewLogger()
	logger.SetOutput(logBuffer)
	logger.SetLevel(logging.Debug)

	sm := &streamManager{log: logger}

	err := &StreamHandlerLoggedError{Err: fmt.Errorf("some debug error"), Level: logging.Debug}
	sm.logDispatchError(err)

	output := logBuffer.String()
	require.Contains(t, output, "some debug error")
	require.Contains(t, output, "level=debug")
	require.NotContains(t, output, "level=error")
	require.NotContains(t, output, "level=warning")
}

func TestLogDispatchErrorErrorLevel(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	logBuffer := &syncBuffer{}
	logger := logging.NewLogger()
	logger.SetOutput(logBuffer)
	logger.SetLevel(logging.Debug)

	sm := &streamManager{log: logger}

	// A plain error (not StreamHandlerLoggedError) should be logged at Error level.
	err := fmt.Errorf("some plain error")
	sm.logDispatchError(err)

	output := logBuffer.String()
	require.Contains(t, output, "some plain error")
	require.Contains(t, output, "level=error")
}

// TestConnectedLogsNonDialedOutgoingConnection tests that the Connected function
// exits early for non-dialed outgoing connections by checking the log output
func TestStreamNonDialedOutgoingConnection(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	logBuffer := &syncBuffer{}
	logger := logging.NewLogger()
	logger.SetOutput(logBuffer)
	logger.SetLevel(logging.Debug)

	cfg := config.GetDefaultLocal()
	cfg.NetAddress = ":1"
	cfg.EnableP2PHybridMode = true
	cfg.P2PHybridNetAddress = ":2"

	pstore1, err := peerstore.NewPeerStore(nil, "test1")
	require.NoError(t, err)
	pstore2, err := peerstore.NewPeerStore(nil, "test2")
	require.NoError(t, err)

	var dialerHost, listenerHost host.Host
	var dialerSM, listenerSM *streamManager

	host1, _, err := MakeHost(cfg, t.TempDir(), pstore1)
	require.NoError(t, err)
	defer host1.Close()

	host2, _, err := MakeHost(cfg, t.TempDir(), pstore2)
	require.NoError(t, err)
	defer host2.Close()

	if host1.ID() < host2.ID() {
		dialerHost = host1
		listenerHost = host2
	} else {
		dialerHost = host2
		listenerHost = host1
	}

	// Make listenerHost listen on a port so we can connect to it
	listenAddr, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	require.NoError(t, err)
	err = listenerHost.Network().Listen(listenAddr)
	require.NoError(t, err)

	ctx := context.Background()
	handlers := StreamHandlers{}
	dialerSM = makeStreamManager(ctx, logger, dialerHost, handlers, false)
	listenerSM = makeStreamManager(ctx, logger, listenerHost, handlers, false)

	// Setup Connected notification
	dialerHost.Network().Notify(dialerSM)
	listenerHost.Network().Notify(listenerSM)

	logBuffer.Reset()

	listenerAddrs := listenerHost.Network().ListenAddresses()
	require.NotEmpty(t, listenerAddrs, "listenerHost should have listening addresses")
	dialerHost.Peerstore().AddAddrs(listenerHost.ID(), listenerAddrs, 1)

	// Connect dialerHost to listenerHost directly, not through dialNode
	err = dialerHost.Connect(ctx, peer.AddrInfo{
		ID:    listenerHost.ID(),
		Addrs: listenerAddrs,
	})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return len(dialerHost.Network().ConnsToPeer(listenerHost.ID())) > 0
	}, 5*time.Second, 50*time.Millisecond)

	conns := dialerHost.Network().ConnsToPeer(listenerHost.ID())
	require.Len(t, conns, 1)
	require.Equal(t, network.DirOutbound, conns[0].Stat().Direction)

	const expectedMsg = "ignoring non-dialed outgoing peer ID"
	require.Eventually(t, func() bool {
		logOutput := logBuffer.String()
		return strings.Contains(logOutput, expectedMsg) && strings.Contains(logOutput, listenerHost.ID().String())
	}, 5*time.Second, 50*time.Millisecond)
}

// TestStream_CloseWaitsForHandlers verifies that streamManager.close waits for in-flight
// handler goroutines spawned by Connected, and that no new handlers start after close.
// Without this, handleConnected could outlive the service and log after shutdown, which
// panics under a testing logger once the test has completed.
func TestStream_CloseWaitsForHandlers(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	lowPeer := peer.ID("AAAA-low-peer")
	highPeer := peer.ID("ZZZZ-high-peer")
	require.True(t, lowPeer < highPeer)

	var handlerCalls atomic.Int32
	countingHandler := func(_ context.Context, _ peer.ID, _ network.Stream, _ bool) error {
		handlerCalls.Add(1)
		return nil
	}
	sm, h := newTestStreamManagerWithHandler(lowPeer, true, countingHandler)

	// localPeer < remotePeer and the peer is protected (as dialNode would do),
	// so Connected spawns handleConnected which calls host.NewStream.
	conn := newMockConn(lowPeer, highPeer, network.DirOutbound)
	h.cm.Protect(highPeer, cnmgrTag)

	newStreamStarted := make(chan struct{})
	newStreamRelease := make(chan struct{})
	var newStreamCalls atomic.Int32
	h.newStreamFn = func(context.Context, peer.ID, ...protocol.ID) (network.Stream, error) {
		if newStreamCalls.Add(1) == 1 {
			close(newStreamStarted)
			<-newStreamRelease
		}
		return nil, errors.New("test: failed to open stream")
	}

	sm.Connected(nil, conn)
	select {
	case <-newStreamStarted:
	case <-time.After(5 * time.Second):
		require.Fail(t, "handleConnected was not started by Connected")
	}

	// a direct tracked spawn (as done by DialPeersUntilTargetCount) is accepted before close.
	// its NewStream call is the second one and fails immediately, so the handler finishes
	// quickly, but close() below must still account for it.
	require.True(t, sm.goHandleConnected(conn))

	closeDone := make(chan struct{})
	go func() {
		sm.close()
		close(closeDone)
	}()

	// close must not return while handleConnected is blocked in NewStream
	select {
	case <-closeDone:
		require.Fail(t, "close returned while handleConnected was still in flight")
	case <-time.After(200 * time.Millisecond):
	}

	close(newStreamRelease)
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		require.Fail(t, "close did not return after handleConnected finished")
	}
	require.Equal(t, int32(2), newStreamCalls.Load())

	// after close, Connected must not spawn new handlers...
	sm.Connected(nil, conn)
	// ...nor may a direct tracked spawn be accepted...
	require.False(t, sm.goHandleConnected(conn))
	// ...and inbound streams must be rejected without dispatching to the handler.
	inConn := newMockConn(lowPeer, highPeer, network.DirInbound)
	stream := newMockStream(inConn, testProto, network.DirInbound)
	sm.streamHandler(stream)
	require.True(t, stream.wasReset())
	require.Equal(t, int32(0), handlerCalls.Load())

	// give a would-be handleConnected goroutine a chance to run: none must have started.
	// two NewStream calls are expected: one from Connected and one from the direct spawn.
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, int32(2), newStreamCalls.Load())
}

// TestStream_CloseTimeout verifies that streamManager.close gives up on a stuck handler
// after closeTimeout instead of hanging shutdown, and logs a warning naming the peer.
func TestStream_CloseTimeout(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	lowPeer := peer.ID("AAAA-low-peer")
	highPeer := peer.ID("ZZZZ-high-peer")
	require.True(t, lowPeer < highPeer)

	sm, h := newTestStreamManager(lowPeer, true)
	logBuffer := &syncBuffer{}
	logger := logging.NewLogger()
	logger.SetOutput(logBuffer)
	logger.SetLevel(logging.Debug)
	sm.log = logger
	sm.closeTimeout = 100 * time.Millisecond

	conn := newMockConn(lowPeer, highPeer, network.DirOutbound)
	h.cm.Protect(highPeer, cnmgrTag)

	newStreamStarted := make(chan struct{})
	newStreamRelease := make(chan struct{})
	h.newStreamFn = func(context.Context, peer.ID, ...protocol.ID) (network.Stream, error) {
		close(newStreamStarted)
		<-newStreamRelease
		return nil, errors.New("test: failed to open stream")
	}

	require.True(t, sm.goHandleConnected(conn))
	select {
	case <-newStreamStarted:
	case <-time.After(5 * time.Second):
		require.Fail(t, "handleConnected was not started")
	}

	// the handler is stuck: close must return after the timeout rather than block forever
	start := time.Now()
	closeDone := make(chan struct{})
	go func() {
		sm.close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		require.Fail(t, "close did not return after closeTimeout with a stuck handler")
	}
	require.GreaterOrEqual(t, time.Since(start), sm.closeTimeout)

	logOutput := logBuffer.String()
	require.Contains(t, logOutput, "timed out")
	require.Contains(t, logOutput, "waiting for stream handlers to finish")
	require.Contains(t, logOutput, highPeer.String())

	// release the stuck handler and make sure it drains so the test leaks nothing
	close(newStreamRelease)
	drained := make(chan struct{})
	go func() {
		sm.handlersWg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		require.Fail(t, "stuck handler did not finish after release")
	}
	require.Empty(t, sm.inflightPeers())
}
