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

package network

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/zstd"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/phonebook"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	sampleVote1 = map[string]any{
		"cred": map[string]any{"pf": crypto.VrfProof{1}},
		"r":    map[string]any{"rnd": uint64(2), "snd": [32]byte{3}},
		"sig": map[string]any{
			"p": [32]byte{4}, "p1s": [64]byte{5}, "p2": [32]byte{6},
			"p2s": [64]byte{7}, "ps": [64]byte{}, "s": [64]byte{9},
		},
	}
	sampleVote2 = map[string]any{
		"cred": map[string]any{"pf": crypto.VrfProof{2}},
		"r":    map[string]any{"rnd": uint64(3), "snd": [32]byte{4}},
		"sig": map[string]any{
			"p": [32]byte{5}, "p1s": [64]byte{6}, "p2": [32]byte{7},
			"p2s": [64]byte{8}, "ps": [64]byte{}, "s": [64]byte{10},
		},
	}
	sampleVote3 = map[string]any{
		"cred": map[string]any{"pf": crypto.VrfProof{3}},
		"r":    map[string]any{"rnd": uint64(4), "snd": [32]byte{5}},
		"sig": map[string]any{
			"p": [32]byte{6}, "p1s": [64]byte{7}, "p2": [32]byte{8},
			"p2s": [64]byte{9}, "ps": [64]byte{}, "s": [64]byte{11},
		},
	}
)

func TestZstdDecompress(t *testing.T) {
	partitiontest.PartitionTest(t)

	// happy case - small message
	msg := []byte(strings.Repeat("1", 2048))
	compressed, err := zstd.Compress(nil, msg)
	require.NoError(t, err)
	d := zstdProposalDecompressor{}
	decompressed, err := d.convert(compressed)
	require.NoError(t, err)
	require.Equal(t, msg, decompressed)

	// error case - large message
	msg = []byte(strings.Repeat("1", MaxDecompressedMessageSize+10))
	compressed, err = zstd.Compress(nil, msg)
	require.NoError(t, err)
	decompressed, err = d.convert(compressed)
	require.Error(t, err)
	require.Nil(t, decompressed)
}

func TestZstdCompressMsg(t *testing.T) {
	partitiontest.PartitionTest(t)

	ppt := len(protocol.ProposalPayloadTag)
	data := []byte("data")
	comp, msg := zstdCompressMsg([]byte(protocol.ProposalPayloadTag), data)
	require.Empty(t, msg)
	require.Equal(t, []byte(protocol.ProposalPayloadTag), comp[:ppt])
	require.Equal(t, zstdCompressionMagic[:], comp[ppt:ppt+len(zstdCompressionMagic)])
	d := zstdProposalDecompressor{}
	decompressed, err := d.convert(comp[ppt:])
	require.NoError(t, err)
	require.Equal(t, data, decompressed)
}

type converterTestLogger struct {
	logging.Logger
	WarnfCallback func(string, ...interface{})
	warnMsgCount  int
}

func (cl *converterTestLogger) Warnf(s string, args ...interface{}) {
	cl.warnMsgCount++
}

func TestWsPeerMsgDataConverterConvert(t *testing.T) {
	partitiontest.PartitionTest(t)

	c := wsPeerMsgCodec{}
	c.ppdec = zstdProposalDecompressor{}
	tag := protocol.AgreementVoteTag
	data := []byte("data")

	r, err := c.decompress(tag, data)
	require.NoError(t, err)
	require.Equal(t, data, r)

	tag = protocol.ProposalPayloadTag
	l := converterTestLogger{}
	c.log = &l
	c.ppdec = zstdProposalDecompressor{}
	r, err = c.decompress(tag, data)
	require.NoError(t, err)
	require.Equal(t, data, r)
	require.Equal(t, 1, l.warnMsgCount)

	l = converterTestLogger{}
	c.log = &l

	comp, err := zstd.Compress(nil, data)
	require.NoError(t, err)

	r, err = c.decompress(tag, comp)
	require.NoError(t, err)
	require.Equal(t, data, r)
	require.Equal(t, 0, l.warnMsgCount)
}

func TestMakeWsPeerMsgCodec_StatefulRequiresStateless(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Create a mock wsPeer with stateful compression features but WITHOUT stateless
	wp := &wsPeer{}
	wp.wsPeerCore.log = logging.TestingLog(t)
	wp.wsPeerCore.originAddress = "test-peer"
	wp.enableVoteCompression = true
	wp.voteCompressionTableSize = 512
	wp.features = pfCompressedVoteVpackStateful512 // stateful enabled but NOT pfCompressedVoteVpack

	codec := makeWsPeerMsgCodec(wp)

	// Stateless should not be enabled (no pfCompressedVoteVpack)
	assert.False(t, codec.avdec.enabled, "Stateless decompression should not be enabled when pfCompressedVoteVpack is not advertised")

	// Stateful should not be enabled even though stateful features are advertised
	// because stateful requires stateless to work (VP -> stateless -> raw)
	assert.False(t, codec.statefulVoteEnabled.Load(), "Stateful compression should not be enabled without stateless support")

	// Now test with both stateless AND stateful enabled
	wp.features = pfCompressedVoteVpack | pfCompressedVoteVpackStateful512

	codec = makeWsPeerMsgCodec(wp)

	// Both stateless and stateful should be enabled
	assert.True(t, codec.avdec.enabled, "Stateless decompression should be enabled when pfCompressedVoteVpack is advertised")
	assert.True(t, codec.statefulVoteEnabled.Load(), "Stateful compression should be enabled when both stateless and stateful features are supported")
}

type voteCompressionNetwork interface {
	Broadcast(ctx context.Context, tag protocol.Tag, data []byte, wait bool, except Peer) error
	RegisterHandlers(dispatch []TaggedMessageHandler)
	GetPeers(options ...PeerOption) []Peer
}

type voteTestNet struct {
	name    string
	network voteCompressionNetwork
	stop    func()
	peerFn  func() *wsPeer
}

type voteNetFactory func(t *testing.T, cfgA, cfgB config.Local) (*voteTestNet, *voteTestNet)

func waitForSinglePeer(t *testing.T, vn *voteTestNet) *wsPeer {
	require.NotNil(t, vn.peerFn, "%s: peer accessor not set", vn.name)
	var result *wsPeer
	require.Eventually(t, func() bool {
		result = vn.peerFn()
		return result != nil
	}, 5*time.Second, 50*time.Millisecond)
	return result
}

func makeWebsocketVoteNets(t *testing.T, cfgA, cfgB config.Local) (*voteTestNet, *voteTestNet) {
	netA := makeTestWebsocketNodeWithConfig(t, cfgA)
	netA.Start()

	netB := makeTestWebsocketNodeWithConfig(t, cfgB)

	addrA, postListen := netA.Address()
	require.True(t, postListen)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()

	readyTimeout := time.NewTimer(2 * time.Second)
	defer readyTimeout.Stop()
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	require.Eventually(t, func() bool {
		return len(netA.GetPeers(PeersConnectedIn)) == 1 && len(netB.GetPeers(PeersConnectedOut)) == 1
	}, 5*time.Second, 50*time.Millisecond)

	return &voteTestNet{
			name:    "websocket-A",
			network: netA,
			stop:    func() { netStop(t, netA, "A") },
			peerFn: func() *wsPeer {
				peers := netA.GetPeers(PeersConnectedIn)
				if len(peers) != 1 {
					return nil
				}
				return peers[0].(*wsPeer)
			},
		}, &voteTestNet{
			name:    "websocket-B",
			network: netB,
			stop:    func() { netStop(t, netB, "B") },
			peerFn: func() *wsPeer {
				peers := netB.GetPeers(PeersConnectedOut)
				if len(peers) != 1 {
					return nil
				}
				return peers[0].(*wsPeer)
			},
		}
}

func makeP2PVoteNets(t *testing.T, cfgA, cfgB config.Local) (*voteTestNet, *voteTestNet) {
	log := logging.TestingLog(t)
	genesisInfo := GenesisInfo{genesisID, config.Devtestnet}

	cfgA.DNSBootstrapID = ""
	cfgA.NetAddress = "127.0.0.1:0"
	cfgA.GossipFanout = 1
	netA, err := NewP2PNetwork(log.With("name", "netA"), cfgA, "", nil, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	require.NoError(t, netA.Start())

	peerInfoA := netA.service.AddrInfo()
	addrsA, err := peer.AddrInfoToP2pAddrs(&peerInfoA)
	require.NoError(t, err)
	require.NotEmpty(t, addrsA)

	cfgB.DNSBootstrapID = ""
	cfgB.NetAddress = ""
	cfgB.GossipFanout = 1
	phoneBookAddresses := []string{addrsA[0].String()}
	netB, err := NewP2PNetwork(log.With("name", "netB"), cfgB, "", phoneBookAddresses, genesisInfo, &nopeNodeInfo{}, nil, nil)
	require.NoError(t, err)
	require.NoError(t, netB.Start())

	require.Eventually(t, func() bool {
		return len(netA.service.Conns()) > 0 && len(netB.service.Conns()) > 0
	}, 5*time.Second, 50*time.Millisecond)

	require.Eventually(t, func() bool {
		return len(netA.GetPeers(PeersConnectedIn)) == 1 && len(netB.GetPeers(PeersConnectedOut)) == 1
	}, 5*time.Second, 50*time.Millisecond)

	return &voteTestNet{
			name:    "p2p-A",
			network: netA,
			stop:    func() { netA.Stop() },
			peerFn: func() *wsPeer {
				netA.wsPeersLock.RLock()
				defer netA.wsPeersLock.RUnlock()
				for _, peer := range netA.wsPeers {
					return peer
				}
				return nil
			},
		}, &voteTestNet{
			name:    "p2p-B",
			network: netB,
			stop:    func() { netB.Stop() },
			peerFn: func() *wsPeer {
				netB.wsPeersLock.RLock()
				defer netB.wsPeersLock.RUnlock()
				for _, peer := range netB.wsPeers {
					return peer
				}
				return nil
			},
		}
}

func TestVoteStatefulCompressionAbortMessage(t *testing.T) {
	partitiontest.PartitionTest(t)

	scenarios := []struct {
		name          string
		induce        func(t *testing.T, peerAtoB, peerBtoA *wsPeer)
		extraMessages [][]byte
	}{{
		name: "decoder_abort",
		induce: func(t *testing.T, peerAtoB, peerBtoA *wsPeer) {
			malformedVP := append([]byte(protocol.VotePackedTag), byte(0x00))
			require.True(t, peerBtoA.writeNonBlock(context.Background(), malformedVP, true, crypto.Digest{}, time.Now()),
				"failed to enqueue malformed VP message")
		},
	}, {
		name: "encoder_abort",
		induce: func(t *testing.T, peerAtoB, peerBtoA *wsPeer) {
			// pretend to VP abort w/out a message
			peerAtoB.msgCodec.switchOffStatefulVoteCompression()
			close, _ := peerAtoB.handleVPError(&voteCompressionError{err: errors.New("forced encoder failure")})
			require.False(t, close, "encoder abort should not close connection")
		},
	}, {
		name: "encoder_hello",
		induce: func(t *testing.T, peerAtoB, peerBtoA *wsPeer) {
			// send a bad AV message that triggers VP abort, but passes through anyway to the other side
			helloAV := append([]byte(protocol.AgreementVoteTag), "hello"...)
			require.True(t, peerAtoB.writeNonBlock(context.Background(), helloAV, true, crypto.Digest{}, time.Now()),
				"failed to enqueue malformed AV message")
		},
		extraMessages: [][]byte{[]byte("hello")},
	}}

	factories := []struct {
		name    string
		factory voteNetFactory
	}{
		{"Websocket", makeWebsocketVoteNets},
		{"P2P", makeP2PVoteNets},
	}

	for _, f := range factories {
		t.Run(f.name, func(t *testing.T) {
			for _, scenario := range scenarios {
				t.Run(scenario.name, func(t *testing.T) {
					testVoteStaticCompressionAbortMessage(t, f.factory, scenario.induce, scenario.extraMessages)
				})
			}
		})
	}
}

func testVoteStaticCompressionAbortMessage(t *testing.T, factory voteNetFactory, induce func(t *testing.T, peerAtoB, peerBtoA *wsPeer), extraMessages [][]byte) {
	cfgA := defaultConfig
	cfgA.GossipFanout = 1
	cfgA.EnableVoteCompression = true
	cfgA.StatefulVoteCompressionTableSize = 256

	cfgB := cfgA

	netA, netB := factory(t, cfgA, cfgB)
	defer netA.stop()
	defer netB.stop()

	peerAtoB := waitForSinglePeer(t, netA)
	peerBtoA := waitForSinglePeer(t, netB)

	voteData := protocol.EncodeReflect(sampleVote1)
	fallbackVotes := [][]byte{
		protocol.EncodeReflect(sampleVote2),
		protocol.EncodeReflect(sampleVote3),
	}
	// some subtests might expect extra messages to appear to test "pass through" error handling
	allVotes := append([][]byte{voteData}, extraMessages...)
	allVotes = append(allVotes, fallbackVotes...)
	matcher := newMessageMatcher(t, allVotes)
	allDone := matcher.done
	netB.network.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.AgreementVoteTag, MessageHandler: matcher}})

	// send first (valid) vote
	require.NoError(t, netA.network.Broadcast(context.Background(), protocol.AgreementVoteTag, voteData, true, nil))

	require.Eventually(t, func() bool {
		matcher.lock.Lock()
		defer matcher.lock.Unlock()
		return len(matcher.received) >= 1
	}, 2*time.Second, 50*time.Millisecond, "timeout waiting for initial vote")

	assert.True(t, peerAtoB.msgCodec.statefulVoteEnabled.Load(), "Stateful compression not established on A->B")
	assert.True(t, peerBtoA.msgCodec.statefulVoteEnabled.Load(), "Stateful compression not established on B->A")

	// induce some kind of error
	induce(t, peerAtoB, peerBtoA)

	// stateful should be disabled on both sides after abort, but connection should stay up
	require.Eventually(t, func() bool {
		return !peerAtoB.msgCodec.statefulVoteEnabled.Load()
	}, 2*time.Second, 50*time.Millisecond, "Stateful compression not disabled on A->B after abort trigger")

	require.Eventually(t, func() bool {
		return !peerBtoA.msgCodec.statefulVoteEnabled.Load()
	}, 2*time.Second, 50*time.Millisecond, "Stateful compression not disabled on B->A after abort trigger")
	assert.False(t, peerBtoA.msgCodec.statefulVoteEnabled.Load(), "Stateful compression should be disabled on B->A after abort")
	assert.False(t, peerAtoB.msgCodec.statefulVoteEnabled.Load(), "Stateful compression should be disabled on A->B after sending abort")

	require.Len(t, netA.network.GetPeers(PeersConnectedIn), 1, "connection should still be alive after abort")
	require.Len(t, netB.network.GetPeers(PeersConnectedOut), 1, "connection should still be alive after abort")

	// send through some more votes, just to show they still get through
	for _, msg := range fallbackVotes {
		require.NoError(t, netA.network.Broadcast(context.Background(), protocol.AgreementVoteTag, msg, true, nil))
	}

	// assert the whole sequence was received on the other side
	select {
	case <-allDone:
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for fallback votes after abort")
	}
	require.True(t, matcher.Match(), "received votes mismatch after abort")
}

func TestVoteStatefulVoteCompression(t *testing.T) {
	partitiontest.PartitionTest(t)

	scenarios := []struct {
		name                 string
		msgs                 [][]byte
		expectCompressionOff bool
	}{
		{"ValidVotes", [][]byte{protocol.EncodeReflect(sampleVote1), protocol.EncodeReflect(sampleVote2)}, false},
		{"InvalidVotes", [][]byte{[]byte("hello1"), []byte("hello2"), []byte("hello3")}, true},
	}

	factories := []struct {
		name    string
		factory voteNetFactory
	}{
		{"Websocket", makeWebsocketVoteNets},
		{"P2P", makeP2PVoteNets},
	}

	for _, f := range factories {
		t.Run(f.name, func(t *testing.T) {
			for _, scenario := range scenarios {
				t.Run(scenario.name, func(t *testing.T) {
					testStatefulVoteCompression(t, scenario.msgs, !scenario.expectCompressionOff, f.factory)
				})
			}
		})
	}
}

// test negotiation with different advertised settings on both ends, plus valid and invalid votes propagate correctly
func testStatefulVoteCompression(t *testing.T, msgs [][]byte, expectCompressionAfter bool, factory voteNetFactory) {
	type testCase struct {
		name          string
		netATableSize uint
		netBTableSize uint
		expectedSize  uint
		expectDynamic bool
	}

	testCases := []testCase{
		{"disabled_disabled", 0, 0, 0, false},
		{"disabled_16", 0, 16, 0, false},
		{"16_disabled", 16, 0, 0, false},
		{"disabled_1024", 0, 1024, 0, false},
		{"1024_disabled", 1024, 0, 0, false},
		{"disabled_2048", 0, 2048, 0, false},
		{"2048_disabled", 2048, 0, 0, false},
		{"16_16", 16, 16, 16, true},
		{"32_32", 32, 32, 32, true},
		{"64_64", 64, 64, 64, true},
		{"128_128", 128, 128, 128, true},
		{"256_256", 256, 256, 256, true},
		{"512_512", 512, 512, 512, true},
		{"1024_1024", 1024, 1024, 1024, true},
		{"2048_2048", 2048, 2048, 2048, true},
		{"16_32", 16, 32, 16, true},
		{"32_16", 32, 16, 16, true},
		{"16_1024", 16, 1024, 16, true},
		{"1024_16", 1024, 16, 16, true},
		{"16_2048", 16, 2048, 16, true},
		{"2048_16", 2048, 16, 16, true},
		{"64_256", 64, 256, 64, true},
		{"256_64", 256, 64, 64, true},
		{"128_512", 128, 512, 128, true},
		{"512_128", 512, 128, 128, true},
		{"256_1024", 256, 1024, 256, true},
		{"1024_256", 1024, 256, 256, true},
		{"256_2048", 256, 2048, 256, true},
		{"2048_256", 2048, 256, 256, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfgA := defaultConfig
			cfgA.GossipFanout = 1
			cfgA.EnableVoteCompression = true
			cfgA.StatefulVoteCompressionTableSize = tc.netATableSize

			cfgB := defaultConfig
			cfgB.GossipFanout = 1
			cfgB.EnableVoteCompression = true
			cfgB.StatefulVoteCompressionTableSize = tc.netBTableSize

			netA, netB := factory(t, cfgA, cfgB)
			defer netA.stop()
			defer netB.stop()

			peerAtoB := waitForSinglePeer(t, netA)
			peerBtoA := waitForSinglePeer(t, netB)

			if tc.expectDynamic {
				require.True(t, peerAtoB.msgCodec.statefulVoteEnabled.Load(), "A->B peer should have stateful compression enabled")
				require.True(t, peerBtoA.msgCodec.statefulVoteEnabled.Load(), "B->A peer should have stateful compression enabled")
				require.Equal(t, uint(tc.expectedSize), peerAtoB.getBestVpackTableSize(), "A->B peer should have expected table size")
				require.Equal(t, uint(tc.expectedSize), peerBtoA.getBestVpackTableSize(), "B->A peer should have expected table size")
			} else {
				require.False(t, peerAtoB.msgCodec.statefulVoteEnabled.Load(), "A->B peer should not have stateful compression enabled")
				require.False(t, peerBtoA.msgCodec.statefulVoteEnabled.Load(), "B->A peer should not have stateful compression enabled")
			}

			matcher := newMessageMatcher(t, msgs)
			counterDone := matcher.done
			netB.network.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.AgreementVoteTag, MessageHandler: matcher}})

			for _, msg := range msgs {
				require.NoError(t, netA.network.Broadcast(context.Background(), protocol.AgreementVoteTag, msg, true, nil))
			}

			select {
			case <-counterDone:
			case <-time.After(2 * time.Second):
				t.Errorf("timeout waiting for vote messages, count=%d, wanted %d", len(matcher.received), len(msgs))
			}

			require.True(t, matcher.Match(), "Received messages don't match sent messages")

			if tc.expectDynamic {
				if expectCompressionAfter {
					require.True(t, peerAtoB.msgCodec.statefulVoteEnabled.Load(), "Stateful compression should still be enabled after sending valid votes")
					require.True(t, peerBtoA.msgCodec.statefulVoteEnabled.Load(), "Stateful compression should still be enabled after receiving valid votes")
				} else {
					require.False(t, peerAtoB.msgCodec.statefulVoteEnabled.Load(), "Stateful compression should be disabled after sending invalid messages")
					require.False(t, peerBtoA.msgCodec.statefulVoteEnabled.Load(), "Stateful compression should be disabled after receiving abort from peer")
				}
			}
		})
	}
}
