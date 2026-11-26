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
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestStream_OneSetupPerPeer checks that handleConnected sets up one gossip stream at a time
// for a peer the node has two connections to, as two nodes that dial each other at the same
// moment have. A call that finds a setup under way for the peer opens no stream, and the peer
// is free for a new setup once that one has ended.
func TestStream_OneSetupPerPeer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	lowPeer := peer.ID("AAAA-low-peer")
	highPeer := peer.ID("ZZZZ-high-peer")

	for _, firstFails := range []bool{false, true} {
		name := "first setup completes"
		if firstFails {
			name = "first setup fails"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var handlerCalls atomic.Int32
			handler := func(context.Context, peer.ID, network.Stream, bool) error {
				if handlerCalls.Add(1) == 1 && firstFails {
					return errors.New("test: gossip setup failed")
				}
				return nil
			}
			sm, h := newTestStreamManagerWithHandler(lowPeer, true, handler)
			dialed := newMockConn(lowPeer, highPeer, network.DirOutbound)
			theirs := newMockConn(lowPeer, highPeer, network.DirInbound)
			h.cm.Protect(highPeer, cnmgrTag)

			started := make(chan struct{})
			release := make(chan struct{})
			var newStreamCalls atomic.Int32
			h.newStreamFn = func(context.Context, peer.ID, ...protocol.ID) (network.Stream, error) {
				if newStreamCalls.Add(1) == 1 {
					close(started)
					<-release
					return newMockStream(dialed, testProto, network.DirOutbound), nil
				}
				return newMockStream(theirs, testProto, network.DirOutbound), nil
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				sm.handleConnected(dialed)
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				require.FailNow(t, "the first setup did not open a stream")
			}

			// the first setup is under way: a call for the other connection opens nothing
			sm.handleConnected(theirs)
			require.Equal(t, int32(1), newStreamCalls.Load())
			close(release)
			<-done

			hasStream := func() bool {
				sm.streamsLock.Lock()
				defer sm.streamsLock.Unlock()
				require.Empty(t, sm.opening)
				_, ok := sm.streams[highPeer]
				return ok
			}
			require.Equal(t, !firstFails, hasStream())
			require.Empty(t, sm.inflightPeers())

			// a later call opens a stream only if the peer has none
			sm.handleConnected(theirs)
			wantCalls := int32(1)
			if firstFails {
				wantCalls = 2
			}
			require.Equal(t, wantCalls, newStreamCalls.Load())
			require.Equal(t, wantCalls, handlerCalls.Load())
			require.True(t, hasStream())
			require.Empty(t, sm.inflightPeers())
		})
	}
}
