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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand/internal/rapidgen"
	"github.com/algorand/go-algorand/network/phonebook"
	"pgregory.net/rapid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"
	"github.com/algorand/websocket"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/metrics"
)

const sendBufferLength = 1000

const genesisID = "go-test-network-genesis"

func TestMain(m *testing.M) {
	logging.Base().SetLevel(logging.Debug)
	os.Exit(m.Run())
}

func debugMetrics(t *testing.T) {
	if t.Failed() {
		var buf strings.Builder
		metrics.DefaultRegistry().WriteMetrics(&buf, "")
		t.Log(buf.String())
	}
}

type emptyPhonebook struct{}

func (e *emptyPhonebook) GetAddresses(n int) []string {
	return []string{}
}

func (e *emptyPhonebook) UpdateRetryAfter(addr string, retryAfter time.Time) {
}

var emptyPhonebookSingleton = &emptyPhonebook{}

type oneEntryPhonebook struct {
	addr       string
	retryAfter time.Time
}

func (e *oneEntryPhonebook) GetAddresses(n int) []string {
	return []string{e.addr}
}

func (e *oneEntryPhonebook) UpdateRetryAfter(addr string, retryAfter time.Time) {
	if e.addr == addr {
		e.retryAfter = retryAfter
	}
}

func (e *oneEntryPhonebook) GetConnectionWaitTime(addr string) (addrInPhonebook bool,
	waitTime time.Duration, provisionalTime time.Time) {
	var t time.Time
	return false, 0, t
}

func (e *oneEntryPhonebook) UpdateConnectionTime(addr string, t time.Time) bool {
	return false
}

var defaultConfig config.Local

func init() {
	defaultConfig = config.GetDefaultLocal()
	defaultConfig.Archival = false
	defaultConfig.GossipFanout = 4
	defaultConfig.NetAddress = "127.0.0.1:0"
	defaultConfig.BaseLoggerDebugLevel = uint32(logging.Debug)
	defaultConfig.DNSBootstrapID = ""
	defaultConfig.MaxConnectionsPerIP = 30
}

func makeTestWebsocketNodeWithConfig(t testing.TB, conf config.Local, opts ...testWebsocketOption) *WebsocketNetwork {
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	wn := &WebsocketNetwork{
		log:       log,
		config:    conf,
		phonebook: phonebook.MakePhonebook(1, 1*time.Millisecond),
		genesisInfo: GenesisInfo{
			GenesisID: genesisID,
			NetworkID: config.Devtestnet,
		},
		peerStater:      peerConnectionStater{log: log},
		identityTracker: NewIdentityTracker(),
	}
	// apply options to newly-created WebsocketNetwork, if provided
	for _, opt := range opts {
		opt.applyOpt(wn)
	}

	wn.setup()
	wn.eventualReadyDelay = time.Second
	return wn
}

// interface for providing extra options to makeTestWebsocketNode
type testWebsocketOption interface {
	applyOpt(wn *WebsocketNetwork)
}

// option to add KV to wn base logger
type testWebsocketLogNameOption struct{ logName string }

func (o testWebsocketLogNameOption) applyOpt(wn *WebsocketNetwork) {
	if o.logName != "" {
		wn.log = wn.log.With("name", o.logName)
	}
}

func makeTestWebsocketNode(t testing.TB, opts ...testWebsocketOption) *WebsocketNetwork {
	return makeTestWebsocketNodeWithConfig(t, defaultConfig, opts...)
}

type messageCounterHandler struct {
	target  int
	limit   int
	count   int
	lock    deadlock.Mutex
	done    chan struct{}
	t       testing.TB
	action  ForwardingPolicy
	verbose bool

	// For deterministically simulating slow handlers, block until test code says to go.
	release    sync.Cond
	shouldWait atomic.Int32
	waitcount  int
}

func (mch *messageCounterHandler) Handle(message IncomingMessage) OutgoingMessage {
	mch.lock.Lock()
	defer mch.lock.Unlock()
	if mch.verbose && len(message.Data) == 8 {
		now := time.Now().UnixNano()
		sent := int64(binary.LittleEndian.Uint64(message.Data))
		dnanos := now - sent
		mch.t.Logf("msg trans time %dns", dnanos)
	}
	if mch.shouldWait.Load() > 0 {
		mch.waitcount++
		mch.release.Wait()
		mch.waitcount--
	}
	mch.count++
	//mch.t.Logf("msg %d %#v", mch.count, message)
	if mch.target != 0 && mch.done != nil && mch.count >= mch.target {
		//mch.t.Log("mch target")
		close(mch.done)
		mch.done = nil
	}
	if mch.limit > 0 && mch.done != nil && mch.count > mch.limit {
		close(mch.done)
		mch.done = nil
	}
	return OutgoingMessage{Action: mch.action}
}

func (mch *messageCounterHandler) numWaiters() int {
	mch.lock.Lock()
	defer mch.lock.Unlock()
	return mch.waitcount
}
func (mch *messageCounterHandler) Count() int {
	mch.lock.Lock()
	defer mch.lock.Unlock()
	return mch.count
}
func (mch *messageCounterHandler) Signal() {
	mch.lock.Lock()
	defer mch.lock.Unlock()
	mch.release.Signal()
}
func (mch *messageCounterHandler) Broadcast() {
	mch.lock.Lock()
	defer mch.lock.Unlock()
	mch.release.Broadcast()
}

func newMessageCounter(t testing.TB, target int) *messageCounterHandler {
	return &messageCounterHandler{target: target, done: make(chan struct{}), t: t}
}

type messageMatcherHandler struct {
	lock deadlock.Mutex

	target   [][]byte
	received [][]byte
	done     chan struct{}
}

func (mmh *messageMatcherHandler) Handle(message IncomingMessage) OutgoingMessage {
	mmh.lock.Lock()
	defer mmh.lock.Unlock()

	mmh.received = append(mmh.received, message.Data)
	if len(mmh.target) > 0 && mmh.done != nil && len(mmh.received) >= len(mmh.target) {
		close(mmh.done)
		mmh.done = nil
	}

	return OutgoingMessage{Action: Ignore}
}

func (mmh *messageMatcherHandler) Match() bool {
	if len(mmh.target) != len(mmh.received) {
		return false
	}

	sort.Slice(mmh.target, func(i, j int) bool { return bytes.Compare(mmh.target[i], mmh.target[j]) == -1 })
	sort.Slice(mmh.received, func(i, j int) bool { return bytes.Compare(mmh.received[i], mmh.received[j]) == -1 })

	for i := 0; i < len(mmh.target); i++ {
		if !bytes.Equal(mmh.target[i], mmh.received[i]) {
			return false
		}
	}
	return true
}

func newMessageMatcher(t testing.TB, target [][]byte) *messageMatcherHandler {
	return &messageMatcherHandler{target: target, done: make(chan struct{})}
}

func TestWebsocketNetworkStartStop(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t)
	netA.Start()
	netA.Stop()
}

func waitReady(t testing.TB, wn *WebsocketNetwork, timeout <-chan time.Time) bool {
	select {
	case <-wn.Ready():
		return true
	case <-timeout:
		_, file, line, _ := runtime.Caller(1)
		t.Fatalf("%s:%d timeout waiting for ready", file, line)
		return false
	}
}

func netStop(t testing.TB, wn *WebsocketNetwork, name string) {
	t.Logf("stopping %s", name)
	wn.Stop()
	time.Sleep(time.Millisecond) // Stop is imperfect and some worker threads can log an error after Stop and that causes a testing error
	t.Logf("%s done", name)
}

func setupWebsocketNetworkAB(t *testing.T, countTarget int) (*WebsocketNetwork, *WebsocketNetwork, *messageCounterHandler, func()) {
	return setupWebsocketNetworkABwithLogger(t, countTarget, nil)
}
func setupWebsocketNetworkABwithLogger(t *testing.T, countTarget int, log logging.Logger) (*WebsocketNetwork, *WebsocketNetwork, *messageCounterHandler, func()) {
	success := false

	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	if log != nil {
		netA.log = log
	}
	netA.Start()
	defer func() {
		if !success {
			netStop(t, netA, "A")
		}
	}()
	netB := makeTestWebsocketNode(t)
	if log != nil {
		netB.log = log
	}
	netB.config.GossipFanout = 1
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer func() {
		if !success {
			netStop(t, netB, "B")
		}
	}()
	counter := newMessageCounter(t, countTarget)
	netB.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.TxnTag, MessageHandler: counter}})

	readyTimeout := time.NewTimer(5 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	t.Log("a ready")
	waitReady(t, netB, readyTimeout.C)
	t.Log("b ready")

	success = true
	closeFunc := func() {
		netStop(t, netB, "B")
		netStop(t, netB, "A")
	}
	return netA, netB, counter, closeFunc
}

// Set up two nodes, test that a.Broadcast is received by B
func TestWebsocketNetworkBasic(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA, _, counter, closeFunc := setupWebsocketNetworkAB(t, 2)
	defer closeFunc()
	counterDone := counter.done
	netA.Broadcast(context.Background(), protocol.TxnTag, []byte("foo"), false, nil)
	netA.Broadcast(context.Background(), protocol.TxnTag, []byte("bar"), false, nil)

	select {
	case <-counterDone:
	case <-time.After(2 * time.Second):
		t.Errorf("timeout, count=%d, wanted 2", counter.count)
	}
}

type mutexBuilder struct {
	logOutput strings.Builder
	mu        deadlock.Mutex
}

func (lw *mutexBuilder) Write(p []byte) (n int, err error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.logOutput.Write(p)
}
func (lw *mutexBuilder) String() string {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.logOutput.String()
}

// Set up two nodes, test that the connection between A and B is not established.
func TestWebsocketNetworkBasicInvalidTags(t *testing.T) { // nolint:paralleltest // changes global variable defaultSendMessageTags
	partitiontest.PartitionTest(t)
	defaultSendMessageTagsOriginal := defaultSendMessageTags
	defaultSendMessageTags = map[protocol.Tag]bool{"XX": true, "MI": true}
	defer func() {
		defaultSendMessageTags = defaultSendMessageTagsOriginal
	}()
	var logOutput mutexBuilder
	log := logging.TestingLog(t)
	log.SetOutput(&logOutput)
	log.SetLevel(logging.Level(logging.Debug))
	netA, netB, counter, closeFunc := setupWebsocketNetworkABwithLogger(t, 0, log)

	defer closeFunc()
	// register a handler that should never get called, because the message will never be delivered
	netB.RegisterHandlers([]TaggedMessageHandler{
		{Tag: "XX", MessageHandler: HandlerFunc(func(msg IncomingMessage) OutgoingMessage {
			require.Fail(t, "MessageHandler for out-of-protocol tag should not be called")
			return OutgoingMessage{}
		})}})
	// send a message with an invalid tag which is in defaultSendMessageTags.
	// it should not go through because the defaultSendMessageTags should not be accepted
	// and the connection should be dropped
	netA.Broadcast(context.Background(), "XX", []byte("foo"), false, nil)
	for p := 0; p < 100; p++ {
		if strings.Contains(logOutput.String(), "wsPeer handleMessageOfInterest: could not unmarshall message from") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Contains(t, logOutput.String(), "wsPeer handleMessageOfInterest: could not unmarshall message from")
	require.Equal(t, 0, counter.count)
}

// Set up two nodes, send proposal
func TestWebsocketProposalPayloadCompression(t *testing.T) {
	partitiontest.PartitionTest(t)

	type testDef struct {
		netASupProto []string
		netAProto    string
		netBSupProto []string
		netBProto    string
	}

	var tests []testDef = []testDef{
		// two new nodes with overwritten config
		{[]string{"2.2"}, "2.2", []string{"2.2"}, "2.2"},

		// old node + new node
		{[]string{"2.1"}, "2.1", []string{"2.2", "2.1"}, "2.2"},
		{[]string{"2.2", "2.1"}, "2.1", []string{"2.2"}, "2.2"},

		// combinations
		{[]string{"2.2", "2.1"}, "2.1", []string{"2.2", "2.1"}, "2.1"},
		{[]string{"2.2", "2.1"}, "2.2", []string{"2.2", "2.1"}, "2.1"},
		{[]string{"2.2", "2.1"}, "2.1", []string{"2.2", "2.1"}, "2.2"},
		{[]string{"2.2", "2.1"}, "2.2", []string{"2.2", "2.1"}, "2.2"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("A_%s(%s)+B_%s(%s)", test.netASupProto, test.netAProto, test.netBSupProto, test.netBProto), func(t *testing.T) {
			netA := makeTestWebsocketNode(t)
			netA.config.GossipFanout = 1
			netA.protocolVersion = test.netAProto
			netA.supportedProtocolVersions = test.netASupProto
			netA.Start()
			defer netStop(t, netA, "A")
			netB := makeTestWebsocketNode(t)
			netB.config.GossipFanout = 1
			netB.protocolVersion = test.netBProto
			netA.supportedProtocolVersions = test.netBSupProto
			addrA, postListen := netA.Address()
			require.True(t, postListen)
			t.Log(addrA)
			netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
			netB.Start()
			defer netStop(t, netB, "B")
			messages := [][]byte{
				[]byte("foo"),
				[]byte("bar"),
			}
			matcher := newMessageMatcher(t, messages)
			counterDone := matcher.done
			netB.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.ProposalPayloadTag, MessageHandler: matcher}})

			readyTimeout := time.NewTimer(2 * time.Second)
			waitReady(t, netA, readyTimeout.C)
			t.Log("a ready")
			waitReady(t, netB, readyTimeout.C)
			t.Log("b ready")

			for _, msg := range messages {
				netA.Broadcast(context.Background(), protocol.ProposalPayloadTag, msg, false, nil)
			}

			select {
			case <-counterDone:
			case <-time.After(2 * time.Second):
				t.Errorf("timeout, count=%d, wanted %d", len(matcher.received), len(messages))
			}

			require.True(t, matcher.Match())
		})
	}
}

// Set up two nodes, send vote to test vote compression feature
func TestWebsocketVoteCompression(t *testing.T) {
	partitiontest.PartitionTest(t)

	type testDef struct {
		netAEnableCompression, netBEnableCompression bool
	}

	var tests []testDef = []testDef{
		{true, true},   // both nodes with compression enabled
		{true, false},  // node A with compression, node B without
		{false, true},  // node A without compression, node B with compression
		{false, false}, // both nodes with compression disabled
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("A_compression_%v+B_compression_%v", test.netAEnableCompression, test.netBEnableCompression), func(t *testing.T) {
			cfgA := defaultConfig
			cfgA.GossipFanout = 1
			cfgA.EnableVoteCompression = test.netAEnableCompression
			cfgA.StatefulVoteCompressionTableSize = 0 // Disable stateful compression
			netA := makeTestWebsocketNodeWithConfig(t, cfgA)
			netA.Start()
			defer netStop(t, netA, "A")

			cfgB := defaultConfig
			cfgB.GossipFanout = 1
			cfgB.EnableVoteCompression = test.netBEnableCompression
			cfgB.StatefulVoteCompressionTableSize = 0 // Disable stateful compression
			netB := makeTestWebsocketNodeWithConfig(t, cfgB)

			addrA, postListen := netA.Address()
			require.True(t, postListen)
			t.Log(addrA)
			netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
			netB.Start()
			defer netStop(t, netB, "B")

			// ps is empty, so this is a valid vote
			vote1 := map[string]any{
				"cred": map[string]any{"pf": crypto.VrfProof{1}},
				"r":    map[string]any{"rnd": uint64(2), "snd": [32]byte{3}},
				"sig": map[string]any{
					"p": [32]byte{4}, "p1s": [64]byte{5}, "p2": [32]byte{6},
					"p2s": [64]byte{7}, "ps": [64]byte{}, "s": [64]byte{9},
				},
			}
			// ps is not empty: vpack compression will fail, but it will still be sent through
			vote2 := map[string]any{
				"cred": map[string]any{"pf": crypto.VrfProof{10}},
				"r":    map[string]any{"rnd": uint64(11), "snd": [32]byte{12}},
				"sig": map[string]any{
					"p": [32]byte{13}, "p1s": [64]byte{14}, "p2": [32]byte{15},
					"p2s": [64]byte{16}, "ps": [64]byte{17}, "s": [64]byte{18},
				},
			}
			// Send a totally invalid message to ensure that it goes through. Even though vpack compression
			// and decompression will fail, the message should still go through (as an intended fallback).
			vote3 := []byte("hello")
			messages := [][]byte{protocol.EncodeReflect(vote1), protocol.EncodeReflect(vote2), vote3}
			matcher := newMessageMatcher(t, messages)
			counterDone := matcher.done
			netB.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.AgreementVoteTag, MessageHandler: matcher}})

			readyTimeout := time.NewTimer(2 * time.Second)
			waitReady(t, netA, readyTimeout.C)
			t.Log("a ready")
			waitReady(t, netB, readyTimeout.C)
			t.Log("b ready")

			for _, msg := range messages {
				netA.Broadcast(context.Background(), protocol.AgreementVoteTag, msg, true, nil)
			}

			select {
			case <-counterDone:
			case <-time.After(2 * time.Second):
				t.Errorf("timeout, count=%d, wanted %d", len(matcher.received), len(messages))
			}

			require.True(t, matcher.Match())

			// Verify compression feature is correctly reflected in peer properties
			// Check peers have the correct compression capability
			peers := netA.GetPeers(PeersConnectedIn)
			require.Len(t, peers, 1)
			peer := peers[0].(*wsPeer)
			require.Equal(t, test.netBEnableCompression, peer.vpackVoteCompressionSupported())

			peers = netB.GetPeers(PeersConnectedOut)
			require.Len(t, peers, 1)
			peer = peers[0].(*wsPeer)
			require.Equal(t, test.netAEnableCompression, peer.vpackVoteCompressionSupported())

		})
	}
}

// Like a basic test, but really we just want to have SetPeerData()/GetPeerData()
func TestWebsocketPeerData(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA, _, _, closeFunc := setupWebsocketNetworkAB(t, 2)
	defer closeFunc()

	require.Equal(t, 1, len(netA.peers))
	require.Equal(t, 1, len(netA.GetPeers(PeersConnectedIn)))
	peerB := netA.peers[0]

	require.Equal(t, nil, netA.GetPeerData(peerB, "not there"))
	netA.SetPeerData(peerB, "foo", "bar")
	require.Equal(t, "bar", netA.GetPeerData(peerB, "foo"))
	netA.SetPeerData(peerB, "foo", "qux")
	require.Equal(t, "qux", netA.GetPeerData(peerB, "foo"))
	netA.SetPeerData(peerB, "foo", nil)
	require.Equal(t, nil, netA.GetPeerData(peerB, "foo"))
}

// Test cancelling message sends
func TestWebsocketNetworkCancel(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA, _, counter, closeFunc := setupWebsocketNetworkAB(t, 100)
	defer closeFunc()
	counterDone := counter.done

	tags := make([]protocol.Tag, 100)
	data := make([][]byte, 100)
	for i := range data {
		tags[i] = protocol.TxnTag
		data[i] = []byte(string(rune(i)))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// try calling broadcast
	for i := 0; i < 100; i++ {
		netA.broadcaster.broadcast(ctx, tags[i], data[i], true, nil)
	}

	select {
	case <-counterDone:
		t.Errorf("All messages were sent, send not cancelled")
	case <-time.After(1 * time.Second):
	}
	assert.Equal(t, 0, counter.Count())

	// try calling innerBroadcast
	peers, _ := netA.peerSnapshot([]*wsPeer{})
	for i := 0; i < 100; i++ {
		request := broadcastRequest{tag: tags[i], data: data[i], enqueueTime: time.Now(), ctx: ctx}
		netA.broadcaster.innerBroadcast(request, true, peers)
	}

	select {
	case <-counterDone:
		t.Errorf("All messages were sent, send not cancelled")
	case <-time.After(1 * time.Second):
	}
	assert.Equal(t, 0, counter.Count())

	// try calling writeLoopSend
	msgs := make([]sendMessage, 0, len(data))
	enqueueTime := time.Now()
	for i, msg := range data {
		tbytes := []byte(tags[i])
		mbytes := make([]byte, len(tbytes)+len(msg))
		copy(mbytes, tbytes)
		copy(mbytes[len(tbytes):], msg)
		msgs = append(msgs, sendMessage{data: mbytes, enqueued: time.Now(), peerEnqueued: enqueueTime, ctx: context.Background()})
	}

	// cancel msg 50
	msgs[50].ctx = ctx

	for _, peer := range peers {
		for _, msg := range msgs {
			peer.sendBufferHighPrio <- msg
		}
	}

	select {
	case <-counterDone:
		t.Errorf("All messages were sent, send not cancelled")
	case <-time.After(1 * time.Second):
	}
	// all but msg 50 should have been sent
	assert.Equal(t, 99, counter.Count())
}

// Set up two nodes, test that a.Broadcast is received by B, when B has no address.
func TestWebsocketNetworkNoAddress(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.Start()
	defer netStop(t, netA, "A")

	noAddressConfig := defaultConfig
	noAddressConfig.NetAddress = ""
	// enable services even though NetAddress is not set (to assert they don't override NetAddress)
	noAddressConfig.EnableGossipService = true
	noAddressConfig.EnableBlockService = true
	noAddressConfig.EnableLedgerService = true
	netB := makeTestWebsocketNodeWithConfig(t, noAddressConfig)
	netB.config.GossipFanout = 1
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")

	// assert addrB is not listening
	addrB, postListenB := netB.Address()
	require.False(t, postListenB)
	require.Empty(t, addrB)

	counter := newMessageCounter(t, 2)
	counterDone := counter.done
	netB.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.TxnTag, MessageHandler: counter}})

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	t.Log("a ready")
	waitReady(t, netB, readyTimeout.C)
	t.Log("b ready")

	netA.Broadcast(context.Background(), protocol.TxnTag, []byte("foo"), false, nil)
	netA.Broadcast(context.Background(), protocol.TxnTag, []byte("bar"), false, nil)

	select {
	case <-counterDone:
	case <-time.After(2 * time.Second):
		t.Errorf("timeout, count=%d, wanted 2", counter.count)
	}
}

func TestWebsocketNetworkNoGossipService(t *testing.T) {
	partitiontest.PartitionTest(t)

	config := defaultConfig
	config.EnableGossipService = false
	netA := makeTestWebsocketNodeWithConfig(t, config)
	netA.Start()
	defer netStop(t, netA, "A")

	// assert that the network was started and is listening
	addrA, postListen := netA.Address()
	require.True(t, postListen)

	// make HTTP request to gossip service and assert 404
	var resp *http.Response
	require.Eventually(t, func() bool {
		var err error
		resp, err = http.Get(fmt.Sprintf("%s/v1/%s/gossip", addrA, genesisID))
		return err == nil
	}, 2*time.Second, 100*time.Millisecond)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func lineNetwork(t *testing.T, numNodes int) (nodes []*WebsocketNetwork, counters []messageCounterHandler) {
	nodes = make([]*WebsocketNetwork, numNodes)
	counters = make([]messageCounterHandler, numNodes)
	for i := range nodes {
		nodes[i] = makeTestWebsocketNode(t)
		nodes[i].log = nodes[i].log.With("node", i)
		nodes[i].config.GossipFanout = 2
		if i == 0 || i == len(nodes)-1 {
			nodes[i].config.GossipFanout = 1
		}
		if i > 0 {
			addrPrev, postListen := nodes[i-1].Address()
			require.True(t, postListen)
			nodes[i].phonebook.ReplacePeerList([]string{addrPrev}, "default", phonebook.RelayRole)
			nodes[i].RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.TxnTag, MessageHandler: &counters[i]}})
		}
		nodes[i].Start()
		counters[i].t = t
		counters[i].action = Broadcast
	}
	return
}

func closeNodeWG(node *WebsocketNetwork, wg *sync.WaitGroup) {
	node.Stop()
	wg.Done()
}

func closeNodes(nodes []*WebsocketNetwork) {
	wg := sync.WaitGroup{}
	wg.Add(len(nodes))
	for _, node := range nodes {
		go closeNodeWG(node, &wg)
	}
	wg.Wait()
}

func waitNodesReady(t *testing.T, nodes []*WebsocketNetwork, timeout time.Duration) {
	tc := time.After(timeout)
	for i, node := range nodes {
		select {
		case <-node.Ready():
		case <-tc:
			t.Fatalf("node[%d] not ready at timeout", i)
		}
	}
}

const lineNetworkLength = 20
const lineNetworkNumMessages = 5

// Set up a network where each node connects to the previous; test that .Broadcast from one end gets to the other.
// Bonus! Measure how long that takes.
// TODO: also make a Benchmark version of this that reports per-node broadcast hop speed.
func TestLineNetwork(t *testing.T) {
	partitiontest.PartitionTest(t)

	nodes, counters := lineNetwork(t, lineNetworkLength)
	t.Logf("line network length: %d", lineNetworkLength)
	waitNodesReady(t, nodes, 2*time.Second)
	t.Log("ready")
	defer closeNodes(nodes)
	counter := &counters[len(counters)-1]
	counter.target = lineNetworkNumMessages
	counter.done = make(chan struct{})
	counterDone := counter.done
	counter.verbose = true
	for i := 0; i < lineNetworkNumMessages; i++ {
		sendTime := time.Now().UnixNano()
		var timeblob [8]byte
		binary.LittleEndian.PutUint64(timeblob[:], uint64(sendTime))
		nodes[0].Broadcast(context.Background(), protocol.TxnTag, timeblob[:], true, nil)
	}
	select {
	case <-counterDone:
	case <-time.After(20 * time.Second):
		t.Errorf("timeout, count=%d, wanted %d", counter.Count(), lineNetworkNumMessages)
		for ci := range counters {
			t.Errorf("count[%d]=%d", ci, counters[ci].Count())
		}
	}
	debugMetrics(t)
}

func addrtest(t *testing.T, wn *WebsocketNetwork, expected, src string) {
	actual, err := wn.addrToGossipAddr(src)
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestAddrToGossipAddr(t *testing.T) {
	partitiontest.PartitionTest(t)

	wn := &WebsocketNetwork{}
	wn.genesisInfo.GenesisID = "test genesisID"
	wn.log = logging.Base()
	addrtest(t, wn, "ws://r7.algodev.network.:4166/v1/test%20genesisID/gossip", "r7.algodev.network.:4166")
	addrtest(t, wn, "ws://r7.algodev.network.:4166/v1/test%20genesisID/gossip", "http://r7.algodev.network.:4166")
	addrtest(t, wn, "wss://r7.algodev.network.:4166/v1/test%20genesisID/gossip", "https://r7.algodev.network.:4166")
}

type nopConn struct{}

func (nc *nopConn) RemoteAddr() net.Addr                        { return nil }
func (nc *nopConn) RemoteAddrString() string                    { return "" }
func (nc *nopConn) NextReader() (int, io.Reader, error)         { return 0, nil, nil }
func (nc *nopConn) WriteMessage(int, []byte) error              { return nil }
func (nc *nopConn) WriteControl(int, []byte, time.Time) error   { return nil }
func (nc *nopConn) CloseWithMessage([]byte, time.Time) error    { return nil }
func (nc *nopConn) SetReadLimit(limit int64)                    {}
func (nc *nopConn) CloseWithoutFlush() error                    { return nil }
func (nc *nopConn) SetPingHandler(h func(appData string) error) {}
func (nc *nopConn) SetPongHandler(h func(appData string) error) {}
func (nc *nopConn) UnderlyingConn() net.Conn                    { return nil }

var nopConnSingleton = nopConn{}

// What happens when all the read message handler threads get busy?
func TestSlowHandlers(t *testing.T) {
	partitiontest.PartitionTest(t)

	slowTag := protocol.Tag("sl")
	fastTag := protocol.Tag("fa")
	slowCounter := messageCounterHandler{}
	slowCounter.shouldWait.Store(1)
	slowCounter.release.L = &slowCounter.lock
	fastCounter := messageCounterHandler{target: incomingThreads}
	fastCounter.done = make(chan struct{})
	fastCounterDone := fastCounter.done
	slowHandler := TaggedMessageHandler{Tag: slowTag, MessageHandler: &slowCounter}
	fastHandler := TaggedMessageHandler{Tag: fastTag, MessageHandler: &fastCounter}
	node := makeTestWebsocketNode(t)
	node.RegisterHandlers([]TaggedMessageHandler{slowHandler, fastHandler})
	node.Start()
	defer node.Stop()
	injectionPeers := make([]wsPeer, incomingThreads*2)
	for i := range injectionPeers {
		injectionPeers[i].closing = make(chan struct{})
		injectionPeers[i].net = node
		injectionPeers[i].conn = &nopConnSingleton
		node.addPeer(&injectionPeers[i])
	}
	ipi := 0
	// start slow handler calls that will block all handler threads
	for i := 0; i < incomingThreads; i++ {
		data := []byte{byte(i)}
		node.handler.readBuffer <- IncomingMessage{Sender: &injectionPeers[ipi], Tag: slowTag, Data: data, Net: node}
		ipi++
	}
	defer slowCounter.Broadcast()

	// start fast handler calls that won't get to run
	for i := 0; i < incomingThreads; i++ {
		data := []byte{byte(i)}
		node.handler.readBuffer <- IncomingMessage{Sender: &injectionPeers[ipi], Tag: fastTag, Data: data, Net: node}
		ipi++
	}
	ok := false
	lastnw := -1
	totalWait := 0
	for i := 0; i < 7; i++ {
		waitTime := int(1 << uint64(i))
		time.Sleep(time.Duration(waitTime) * time.Millisecond)
		totalWait += waitTime
		nw := slowCounter.numWaiters()
		if nw == incomingThreads {
			ok = true
			break
		}
		if lastnw != nw {
			t.Logf("%dms %d waiting", totalWait, nw)
			lastnw = nw
		}
	}
	if !ok {
		t.Errorf("timeout waiting for %d threads to block on slow handler, have %d", incomingThreads, lastnw)
	}
	require.Equal(t, 0, fastCounter.Count())

	// release one slow request, all the other requests should process on that one handler thread
	slowCounter.Signal()

	select {
	case <-fastCounterDone:
	case <-time.After(time.Second):
		t.Errorf("timeout waiting for %d blocked events to be handled, have %d", incomingThreads, fastCounter.Count())
	}
	// checks that above .Signal() did in fact release just one waiting slow handler
	require.Equal(t, 1, slowCounter.Count())

	// we don't care about counting how things finish
	debugMetrics(t)
}

// one peer sends waaaayy too much slow-to-handle traffic. everything else should run fine.
func TestFloodingPeer(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Skip("flaky test")
	slowTag := protocol.Tag("sl")
	fastTag := protocol.Tag("fa")
	slowCounter := messageCounterHandler{}
	slowCounter.shouldWait.Store(1)
	slowCounter.release.L = &slowCounter.lock
	fastCounter := messageCounterHandler{}
	slowHandler := TaggedMessageHandler{Tag: slowTag, MessageHandler: &slowCounter}
	fastHandler := TaggedMessageHandler{Tag: fastTag, MessageHandler: &fastCounter}
	node := makeTestWebsocketNode(t)
	node.RegisterHandlers([]TaggedMessageHandler{slowHandler, fastHandler})
	node.Start()
	defer node.Stop()
	injectionPeers := make([]wsPeer, incomingThreads*2)
	for i := range injectionPeers {
		injectionPeers[i].closing = make(chan struct{})
		injectionPeers[i].net = node
		injectionPeers[i].conn = &nopConnSingleton
		node.addPeer(&injectionPeers[i])
	}
	ipi := 0
	const numBadPeers = 1
	// start slow handler calls that will block some threads
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < numBadPeers; i++ {
		myI := i
		myIpi := ipi
		go func() {
			processed := make(chan struct{}, 1)
			processed <- struct{}{}

			for qi := 0; qi < incomingThreads*2; qi++ {
				data := []byte{byte(myI), byte(qi)}
				select {
				case <-processed:
				case <-ctx.Done():
					return
				}

				select {
				case node.handler.readBuffer <- IncomingMessage{Sender: &injectionPeers[myIpi], Tag: slowTag, Data: data, Net: node, processing: processed}:
				case <-ctx.Done():
					return
				}
			}
		}()
		ipi++
	}
	defer cancel()
	defer func() {
		t.Log("release slow handlers")
		slowCounter.shouldWait.Store(0)
		slowCounter.Broadcast()
	}()

	// start fast handler calls that will run on other reader threads
	numFast := 0
	fastCounter.target = len(injectionPeers) - ipi
	fastCounter.done = make(chan struct{})
	fastCounterDone := fastCounter.done
	for ipi < len(injectionPeers) {
		data := []byte{byte(ipi)}
		node.handler.readBuffer <- IncomingMessage{Sender: &injectionPeers[ipi], Tag: fastTag, Data: data, Net: node}
		numFast++
		ipi++
	}
	require.Equal(t, numFast, fastCounter.target)
	select {
	case <-fastCounterDone:
	case <-time.After(time.Second):
		t.Errorf("timeout waiting for %d fast handlers, got %d", fastCounter.target, fastCounter.Count())
	}

	// we don't care about counting how things finish
}

func peerIsClosed(peer *wsPeer) bool {
	return peer.didInnerClose.Load() != 0
}

func avgSendBufferHighPrioLength(wn *WebsocketNetwork) float64 {
	wn.peersLock.Lock()
	defer wn.peersLock.Unlock()
	sum := 0
	for _, peer := range wn.peers {
		sum += len(peer.sendBufferHighPrio)
	}
	return float64(sum) / float64(len(wn.peers))
}

// TestSlowOutboundPeer tests what happens when one outbound peer is slow and the rest are fine. Current logic is to disconnect the one slow peer when its outbound channel is full.
//
// This is a deeply invasive test that reaches into the guts of WebsocketNetwork and wsPeer. If the implementation chainges consider throwing away or totally reimplementing this test.
func TestSlowOutboundPeer(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Skip() // todo - update this test to reflect the new implementation.
	xtag := protocol.ProposalPayloadTag
	node := makeTestWebsocketNode(t)
	destPeers := make([]wsPeer, 5)
	for i := range destPeers {
		destPeers[i].closing = make(chan struct{})
		destPeers[i].net = node
		destPeers[i].sendBufferHighPrio = make(chan sendMessage, sendBufferLength)
		destPeers[i].sendBufferBulk = make(chan sendMessage, sendBufferLength)
		destPeers[i].conn = &nopConnSingleton
		destPeers[i].rootURL = fmt.Sprintf("fake %d", i)
		node.addPeer(&destPeers[i])
	}
	node.Start()
	tctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
	for i := 0; i < sendBufferLength; i++ {
		t.Logf("broadcast %d", i)
		sent := node.Broadcast(tctx, xtag, []byte{byte(i)}, true, nil)
		require.NoError(t, sent)
	}
	cf()
	ok := false
	for i := 0; i < 10; i++ {
		time.Sleep(time.Millisecond)
		aoql := avgSendBufferHighPrioLength(node)
		if aoql == sendBufferLength {
			ok = true
			break
		}
		t.Logf("node.avgOutboundQueueLength() %f", aoql)
	}
	require.True(t, ok)
	for p := range destPeers {
		if p == 0 {
			continue
		}
		for j := 0; j < sendBufferLength; j++ {
			// throw away a message as if sent
			<-destPeers[p].sendBufferHighPrio
		}
	}
	aoql := avgSendBufferHighPrioLength(node)
	if aoql > (sendBufferLength / 2) {
		t.Fatalf("avgOutboundQueueLength=%f wanted <%f", aoql, sendBufferLength/2.0)
		return
	}
	// it shouldn't have closed for just sitting on the limit of full
	require.False(t, peerIsClosed(&destPeers[0]))

	// function context just to contain defer cf()
	func() {
		timeout, cf := context.WithTimeout(context.Background(), time.Second)
		defer cf()
		sent := node.Broadcast(timeout, xtag, []byte{byte(42)}, true, nil)
		assert.NoError(t, sent)
	}()

	// and now with the rest of the peers well and this one slow, we closed the slow one
	require.True(t, peerIsClosed(&destPeers[0]))
}

func makeTestFilterWebsocketNode(t *testing.T, nodename string) *WebsocketNetwork {
	dc := defaultConfig
	dc.EnableIncomingMessageFilter = true
	dc.EnableOutgoingNetworkMessageFiltering = true
	dc.IncomingMessageFilterBucketCount = 5
	dc.IncomingMessageFilterBucketSize = 512
	dc.OutgoingMessageFilterBucketCount = 3
	dc.OutgoingMessageFilterBucketSize = 128
	wn := &WebsocketNetwork{
		log:       logging.TestingLog(t).With("node", nodename),
		config:    dc,
		phonebook: phonebook.MakePhonebook(1, 1*time.Millisecond),
		genesisInfo: GenesisInfo{
			GenesisID: genesisID,
			NetworkID: config.Devtestnet,
		},
		peerStater:      peerConnectionStater{log: logging.TestingLog(t).With("node", nodename)},
		identityTracker: noopIdentityTracker{},
	}
	require.True(t, wn.config.EnableIncomingMessageFilter)
	wn.setup()
	wn.eventualReadyDelay = time.Second
	require.True(t, wn.config.EnableIncomingMessageFilter)
	return wn
}

func TestDupFilter(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestFilterWebsocketNode(t, "a")
	netA.config.GossipFanout = 1
	netA.Start()
	defer netStop(t, netA, "A")
	netB := makeTestFilterWebsocketNode(t, "b")
	netB.config.GossipFanout = 2
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")
	counter := &messageCounterHandler{t: t, limit: 1, done: make(chan struct{})}
	netB.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.AgreementVoteTag, MessageHandler: counter}})
	debugTag2 := protocol.ProposalPayloadTag
	counter2 := &messageCounterHandler{t: t, limit: 1, done: make(chan struct{})}
	netB.RegisterHandlers([]TaggedMessageHandler{{Tag: debugTag2, MessageHandler: counter2}})

	addrB, postListen := netB.Address()
	require.True(t, postListen)
	netC := makeTestFilterWebsocketNode(t, "c")
	netC.config.GossipFanout = 1
	netC.phonebook.ReplacePeerList([]string{addrB}, "default", phonebook.RelayRole)
	netC.Start()
	defer netC.Stop()

	makeMsg := func(n int) []byte {
		// We cannot hardcode the msgSize to messageFilterSize + 1 because max allowed AV message is smaller  than that.
		// We also cannot use maxSize for PP since it's a compressible tag but trying to compress random data will expand it.
		if messageFilterSize+1 < n {
			n = messageFilterSize + 1
		}
		msg := make([]byte, n)
		rand.Read(msg)
		return msg
	}

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	t.Log("a ready")
	waitReady(t, netB, readyTimeout.C)
	t.Log("b ready")
	waitReady(t, netC, readyTimeout.C)
	t.Log("c ready")

	// TODO: this test has two halves that exercise inbound de-dup and outbound non-send due to received hash. But it doesn't properly _test_ them as it doesn't measure _why_ it receives each message exactly once. The second half below could actually be because of the same inbound de-dup as this first half. You can see the actions of either in metrics.
	// algod_network_duplicate_message_received_total{} 2
	// algod_outgoing_network_message_filtered_out_total{} 2
	// Maybe we should just .Set(0) those counters and use them in this test?

	// This exercise inbound dup detection.
	avMsg := makeMsg(int(protocol.AgreementVoteTag.MaxMessageSize()))
	netA.Broadcast(context.Background(), protocol.AgreementVoteTag, avMsg, true, nil)
	netA.Broadcast(context.Background(), protocol.AgreementVoteTag, avMsg, true, nil)
	netA.Broadcast(context.Background(), protocol.AgreementVoteTag, avMsg, true, nil)
	t.Log("A dup send done")

	select {
	case <-counter.done:
		// probably a failure, but let it fall through to the equal check
	case <-time.After(time.Second):
	}
	counter.lock.Lock()
	assert.Equal(t, 1, counter.count)
	counter.lock.Unlock()

	// new message
	debugTag2Msg := makeMsg(int(debugTag2.MaxMessageSize()))
	t.Logf("debugTag2Msg len %d", len(debugTag2Msg))
	t.Log("A send, C non-dup-send")
	netA.Broadcast(context.Background(), debugTag2, debugTag2Msg, true, nil)
	// B should broadcast its non-desire to receive the message again
	time.Sleep(500 * time.Millisecond)

	// C should now not send these
	netC.Broadcast(context.Background(), debugTag2, debugTag2Msg, true, nil)
	netC.Broadcast(context.Background(), debugTag2, debugTag2Msg, true, nil)

	select {
	case <-counter2.done:
		// probably a failure, but let it fall through to the equal check
	case <-time.After(time.Second):
	}
	assert.Equal(t, 1, counter2.count)

	debugMetrics(t)
}

func TestGetPeers(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.Start()
	defer netA.Stop()
	netB := makeTestWebsocketNode(t)
	netB.config.GossipFanout = 1
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	phbMulti := phonebook.MakePhonebook(1, 1*time.Millisecond)
	phbMulti.ReplacePeerList([]string{addrA}, "phba", phonebook.RelayRole)
	netB.phonebook = phbMulti
	netB.Start()
	defer netB.Stop()

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	t.Log("a ready")
	waitReady(t, netB, readyTimeout.C)
	t.Log("b ready")

	phbMulti.ReplacePeerList([]string{"a", "b", "c"}, "ph", phonebook.RelayRole)

	// A few for archival node roles
	phbMulti.ReplacePeerList([]string{"d", "e", "f"}, "ph", phonebook.ArchivalRole)

	//addrB, _ := netB.Address()

	// A has only an inbound connection from B
	aPeers := netA.GetPeers(PeersConnectedOut)
	assert.Equal(t, 0, len(aPeers))

	// B's connection to A is outgoing
	bPeers := netB.GetPeers(PeersConnectedOut)
	assert.Equal(t, 1, len(bPeers))
	assert.Equal(t, addrA, bPeers[0].(HTTPPeer).GetAddress())

	// B also knows about other peers not connected to
	bPeers = netB.GetPeers(PeersPhonebookRelays)
	assert.Equal(t, 4, len(bPeers))
	peerAddrs := make([]string, len(bPeers))
	for pi, peer := range bPeers {
		peerAddrs[pi] = peer.(HTTPPeer).GetAddress()
	}
	sort.Strings(peerAddrs)
	expectAddrs := []string{addrA, "a", "b", "c"}
	sort.Strings(expectAddrs)
	assert.Equal(t, expectAddrs, peerAddrs)

	bPeers2 := netB.GetPeers(PeersPhonebookArchivalNodes)
	peerAddrs2 := make([]string, len(bPeers2))
	for pi2, peer2 := range bPeers2 {
		peerAddrs2[pi2] = peer2.(HTTPPeer).GetAddress()
	}
	sort.Strings(peerAddrs2)
	assert.Equal(t, []string{"d", "e", "f"}, peerAddrs2)

}

// confirms that if the config PublicAddress is set to "testing",
// PublicAddress is loaded when possible with the value of Address()
func TestTestingPublicAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	netA := makeTestWebsocketNode(t)
	netA.config.PublicAddress = "testing"
	netA.config.GossipFanout = 1

	netA.Start()

	time.Sleep(100 * time.Millisecond)

	// check that "testing" has been overloaded
	addr, ok := netA.Address()
	addr = hostAndPort(addr)
	require.True(t, ok)
	require.NotEqual(t, "testing", netA.PublicAddress())
	require.Equal(t, addr, netA.PublicAddress())
}

// mock an identityTracker
type mockIdentityTracker struct {
	isOccupied  bool
	setCount    int
	insertCount int
	removeCount int
	lock        deadlock.Mutex
	realTracker identityTracker
}

func newMockIdentityTracker(realTracker identityTracker) *mockIdentityTracker {
	return &mockIdentityTracker{
		isOccupied:  false,
		setCount:    0,
		insertCount: 0,
		removeCount: 0,
		realTracker: realTracker,
	}
}

func (d *mockIdentityTracker) setIsOccupied(b bool) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.isOccupied = b
}
func (d *mockIdentityTracker) removeIdentity(p *wsPeer) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.removeCount++
	d.realTracker.removeIdentity(p)
}
func (d *mockIdentityTracker) getInsertCount() int {
	d.lock.Lock()
	defer d.lock.Unlock()
	return d.insertCount
}
func (d *mockIdentityTracker) getRemoveCount() int {
	d.lock.Lock()
	defer d.lock.Unlock()
	return d.removeCount
}
func (d *mockIdentityTracker) getSetCount() int {
	d.lock.Lock()
	defer d.lock.Unlock()
	return d.setCount
}
func (d *mockIdentityTracker) setIdentity(p *wsPeer) bool {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.setCount++
	// isOccupied is true, meaning we're overloading the "ok" return to false
	if d.isOccupied {
		return false
	}
	ret := d.realTracker.setIdentity(p)
	if ret {
		d.insertCount++
	}
	return ret
}

func hostAndPort(u string) string {
	url, err := url.Parse(u)
	if err == nil {
		return fmt.Sprintf("%s:%s", url.Hostname(), url.Port())
	}
	return ""
}

// TestPeeringWithIdentityChallenge tests the happy path of connecting with identity challenge:
// - both peers have correctly set PublicAddress
// - both should exchange identities and verify
// - both peers should be able to deduplicate connections
func TestPeeringWithIdentityChallenge(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
	netA.identityTracker = newMockIdentityTracker(netA.identityTracker)
	netA.config.PublicAddress = "testing"
	netA.config.GossipFanout = 1

	netB := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netB"})
	netB.identityTracker = newMockIdentityTracker(netB.identityTracker)
	netB.config.PublicAddress = "testing"
	netB.config.GossipFanout = 1

	netA.Start()
	defer netA.Stop()
	netB.Start()
	defer netB.Stop()

	addrA, ok := netA.Address()
	require.True(t, ok)

	addrB, ok := netB.Address()
	require.True(t, ok)
	gossipB, err := netB.addrToGossipAddr(addrB)
	require.NoError(t, err)

	// set addresses to just host:port to match phonebook/dns format
	addrA = hostAndPort(addrA)
	addrB = hostAndPort(addrB)

	// first connection should work just fine
	if _, ok := netA.tryConnectReserveAddr(addrB); ok {
		netA.wg.Add(1)
		netA.tryConnect(addrB, gossipB)
		// let the tryConnect go forward
		assert.Eventually(t, func() bool {
			return len(netA.GetPeers(PeersConnectedOut)) == 1
		}, time.Second, 50*time.Millisecond)
	}
	// just one A->B connection
	assert.Equal(t, 0, len(netA.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 0, len(netB.GetPeers(PeersConnectedOut)))

	// confirm identity map was added to for both hosts
	assert.Equal(t, 1, netA.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 1, netA.identityTracker.(*mockIdentityTracker).getInsertCount())

	// netB has to wait for a final verification message over WS Handler, so pause a moment
	assert.Eventually(t, func() bool {
		return netB.identityTracker.(*mockIdentityTracker).getSetCount() == 1
	}, time.Second, 50*time.Millisecond)

	assert.Equal(t, 1, netB.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 1, netB.identityTracker.(*mockIdentityTracker).getInsertCount())

	// bi-directional connection from B should not proceed
	_, ok = netB.tryConnectReserveAddr(addrA)
	assert.False(t, ok)

	// still just one A->B connection
	assert.Equal(t, 0, len(netA.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 0, len(netB.GetPeers(PeersConnectedOut)))
	// netA never attempts to set identity as it never sees a verified identity
	assert.Equal(t, 1, netA.identityTracker.(*mockIdentityTracker).getSetCount())
	// no connection => netB does attempt to add the identity to the tracker
	// and it would not end up being added
	assert.Equal(t, 1, netB.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 1, netB.identityTracker.(*mockIdentityTracker).getInsertCount())

	// Check deduplication again, this time from A
	// the "ok" from tryConnectReserveAddr is overloaded here because isConnectedTo
	// will prevent this connection from attempting in the first place
	// in the real world, that isConnectedTo doesn't always trigger, if the hosts are behind
	// a load balancer or other NAT
	_, ok = netA.tryConnectReserveAddr(addrB)
	assert.False(t, ok)
	netA.wg.Add(1)
	old := networkPeerIdentityDisconnect.GetUint64Value()
	netA.tryConnect(addrB, gossipB)
	// let the tryConnect go forward
	assert.Eventually(t, func() bool {
		new := networkPeerIdentityDisconnect.GetUint64Value()
		return new > old
	}, time.Second, 50*time.Millisecond)

	// netB never tries to add a new identity, since the connection gets abandoned before it is verified
	assert.Equal(t, 1, netB.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 1, netB.identityTracker.(*mockIdentityTracker).getInsertCount())
	// still just one A->B connection
	assert.Equal(t, 0, len(netA.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 0, len(netB.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 2, netA.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 1, netA.identityTracker.(*mockIdentityTracker).getInsertCount())
	// it is possible for NetB to be in the process of doing addPeer while
	// the underlying connection is being closed. In this case, the read loop
	// on the peer will detect and close the peer. Since this is asynchronous,
	// we wait and check regularly to allow the connection to settle
	assert.Eventually(t, func() bool {
		return len(netB.GetPeers(PeersConnectedIn)) == 1
	}, time.Second, 50*time.Millisecond)

	// Now have A connect to node C, which has the same PublicAddress as B (e.g., because it shares the
	// same public load balancer endpoint). C will have a different identity keypair and so will not be
	// considered a duplicate.
	netC := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netC"})
	netC.identityTracker = newMockIdentityTracker(netC.identityTracker)
	netC.config.PublicAddress = addrB
	netC.config.GossipFanout = 1

	netC.Start()
	defer netC.Stop()

	addrC, ok := netC.Address()
	require.True(t, ok)
	gossipC, err := netC.addrToGossipAddr(addrC)
	require.NoError(t, err)

	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedOut)))
	// A connects to C (but uses addrB here to simulate case where B & C have the same PublicAddress)
	netA.wg.Add(1)
	netA.tryConnect(addrB, gossipC)
	// let the tryConnect go forward
	assert.Eventually(t, func() bool {
		return len(netA.GetPeers(PeersConnectedOut)) == 2
	}, time.Second, 50*time.Millisecond)

	// A->B and A->C both open
	assert.Equal(t, 0, len(netA.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 2, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 0, len(netB.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 1, len(netC.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 0, len(netB.GetPeers(PeersConnectedOut)))

	// confirm identity map was added to for both hosts
	assert.Equal(t, 3, netA.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 2, netA.identityTracker.(*mockIdentityTracker).getInsertCount())

	// netC has to wait for a final verification message over WS Handler, so pause a moment
	assert.Eventually(t, func() bool {
		return netC.identityTracker.(*mockIdentityTracker).getSetCount() == 1
	}, time.Second, 50*time.Millisecond)

	assert.Equal(t, 1, netC.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 1, netC.identityTracker.(*mockIdentityTracker).getInsertCount())

}

// TestPeeringSenderIdentityChallengeOnly will confirm that if only the Sender
// Uses Identity, no identity exchange happens in the connection
func TestPeeringSenderIdentityChallengeOnly(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
	netA.identityTracker = newMockIdentityTracker(netA.identityTracker)
	netA.config.PublicAddress = "testing"
	netA.config.GossipFanout = 1

	netB := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netB"})
	netB.identityTracker = newMockIdentityTracker(netB.identityTracker)
	//netB.config.PublicAddress = "testing"
	netB.config.GossipFanout = 1

	netA.Start()
	defer netA.Stop()
	netB.Start()
	defer netB.Stop()

	addrA, ok := netA.Address()
	require.True(t, ok)

	addrB, ok := netB.Address()
	require.True(t, ok)
	gossipB, err := netB.addrToGossipAddr(addrB)
	require.NoError(t, err)

	// set addresses to just host:port to match phonebook/dns format
	addrA = hostAndPort(addrA)
	addrB = hostAndPort(addrB)

	assert.Equal(t, 0, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 0, len(netB.GetPeers(PeersConnectedIn)))

	// first connection should work just fine
	if _, ok := netA.tryConnectReserveAddr(addrB); ok {
		netA.wg.Add(1)
		netA.tryConnect(addrB, gossipB)
		assert.Eventually(t, func() bool {
			return len(netA.GetPeers(PeersConnectedOut)) == 1
		}, time.Second, 50*time.Millisecond)
	}
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedIn)))

	// confirm identity map was not added to for either host
	assert.Equal(t, 0, netA.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 0, netB.identityTracker.(*mockIdentityTracker).getSetCount())

	// bi-directional connection does not work because netA advertises its public address
	_, ok = netB.tryConnectReserveAddr(addrA)
	assert.False(t, ok)

	// no redundant connections
	assert.Equal(t, 0, len(netA.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 0, len(netB.GetPeers(PeersConnectedOut)))
	// confirm identity map was not added to for either host
	assert.Equal(t, 0, netA.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 0, netB.identityTracker.(*mockIdentityTracker).getSetCount())
}

// TestPeeringReceiverIdentityChallengeOnly will confirm that if only the Receiver
// Uses Identity, no identity exchange happens in the connection
func TestPeeringReceiverIdentityChallengeOnly(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
	netA.identityTracker = newMockIdentityTracker(netA.identityTracker)
	//netA.config.PublicAddress = "testing"
	netA.config.GossipFanout = 1

	netB := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netB"})
	netB.identityTracker = newMockIdentityTracker(netB.identityTracker)
	netB.config.PublicAddress = "testing"
	netB.config.GossipFanout = 1

	netA.Start()
	defer netA.Stop()
	netB.Start()
	defer netB.Stop()

	addrA, ok := netA.Address()
	require.True(t, ok)
	gossipA, err := netA.addrToGossipAddr(addrA)
	require.NoError(t, err)

	addrB, ok := netB.Address()
	require.True(t, ok)
	gossipB, err := netB.addrToGossipAddr(addrB)
	require.NoError(t, err)

	// set addresses to just host:port to match phonebook/dns format
	addrA = hostAndPort(addrA)
	addrB = hostAndPort(addrB)

	assert.Equal(t, 0, len(netA.GetPeers(PeersConnectedOut)))
	// first connection should work just fine
	if _, ok := netA.tryConnectReserveAddr(addrB); ok {
		netA.wg.Add(1)
		netA.tryConnect(addrB, gossipB)
		// let the tryConnect go forward
		assert.Eventually(t, func() bool {
			return len(netA.GetPeers(PeersConnectedOut)) == 1
		}, time.Second, 50*time.Millisecond)
	}
	// single A->B connection
	assert.Equal(t, 0, len(netA.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 0, len(netB.GetPeers(PeersConnectedOut)))

	// confirm identity map was not added to for either host
	assert.Equal(t, 0, netA.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 0, netB.identityTracker.(*mockIdentityTracker).getSetCount())

	// bi-directional connection should also work
	if _, ok := netB.tryConnectReserveAddr(addrA); ok {
		netB.wg.Add(1)
		netB.tryConnect(addrA, gossipA)
		// let the tryConnect go forward
		assert.Eventually(t, func() bool {
			return len(netB.GetPeers(PeersConnectedOut)) == 1
		}, time.Second, 50*time.Millisecond)
	}
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedOut)))
	// confirm identity map was not added to for either host
	assert.Equal(t, 0, netA.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 0, netB.identityTracker.(*mockIdentityTracker).getSetCount())
}

// TestPeeringIncorrectDeduplicationName confirm that if the receiver can't match
// the Address in the challenge to its PublicAddress, identities aren't exchanged, but peering continues
func TestPeeringIncorrectDeduplicationName(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
	netA.identityTracker = newMockIdentityTracker(netA.identityTracker)
	netA.config.PublicAddress = "testing"
	netA.config.GossipFanout = 1

	netB := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netB"})
	netB.identityTracker = newMockIdentityTracker(netB.identityTracker)
	netB.config.PublicAddress = "no:3333"
	netB.config.GossipFanout = 1

	netA.Start()
	defer netA.Stop()
	netB.Start()
	defer netB.Stop()

	addrA, ok := netA.Address()
	require.True(t, ok)
	gossipA, err := netA.addrToGossipAddr(addrA)
	require.NoError(t, err)

	addrB, ok := netB.Address()
	require.True(t, ok)
	gossipB, err := netB.addrToGossipAddr(addrB)
	require.NoError(t, err)

	// set addresses to just host:port to match phonebook/dns format
	addrA = hostAndPort(addrA)
	addrB = hostAndPort(addrB)

	assert.Equal(t, 0, len(netA.GetPeers(PeersConnectedOut)))
	// first connection should work just fine
	if _, ok := netA.tryConnectReserveAddr(addrB); ok {
		netA.wg.Add(1)
		netA.tryConnect(addrB, gossipB)
		// let the tryConnect go forward
		assert.Eventually(t, func() bool {
			return len(netA.GetPeers(PeersConnectedOut)) == 1
		}, time.Second, 50*time.Millisecond)
	}
	// single A->B connection
	assert.Equal(t, 0, len(netA.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 0, len(netB.GetPeers(PeersConnectedOut)))

	// confirm identity map was not added to for either host
	// nor was "set" called at all
	assert.Equal(t, 0, netA.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 0, netB.identityTracker.(*mockIdentityTracker).getSetCount())

	// bi-directional connection would now work since netB detects to be connected to netA in tryConnectReserveAddr,
	// so force it.
	// this second connection should set identities, because the receiver address matches now
	_, ok = netB.tryConnectReserveAddr(addrA)
	assert.False(t, ok)
	netB.wg.Add(1)
	netB.tryConnect(addrA, gossipA)
	// let the tryConnect go forward
	assert.Eventually(t, func() bool {
		return len(netB.GetPeers(PeersConnectedOut)) == 1
	}, time.Second, 50*time.Millisecond)

	// confirm that at this point the identityTracker was called once per network
	//	and inserted once per network
	assert.Equal(t, 1, netA.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 1, netB.identityTracker.(*mockIdentityTracker).getSetCount())
	assert.Equal(t, 1, netA.identityTracker.(*mockIdentityTracker).getInsertCount())
	assert.Equal(t, 1, netB.identityTracker.(*mockIdentityTracker).getInsertCount())
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 1, len(netA.GetPeers(PeersConnectedOut)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedIn)))
	assert.Equal(t, 1, len(netB.GetPeers(PeersConnectedOut)))
}

// make a mockIdentityScheme which can accept overloaded behavior
// use this over the next few tests to check that when one peer misbehaves, peering continues/halts as expected
type mockIdentityScheme struct {
	t                       *testing.T
	realScheme              *identityChallengePublicKeyScheme
	attachChallenge         func(attach http.Header, addr string) identityChallengeValue
	verifyAndAttachResponse func(attach http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error)
	verifyResponse          func(t *testing.T, h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error)
}

func newMockIdentityScheme(t *testing.T) *mockIdentityScheme {
	return &mockIdentityScheme{t: t, realScheme: NewIdentityChallengeScheme(NetIdentityDedupNames("any"))}
}
func (i mockIdentityScheme) AttachChallenge(attach http.Header, addr string) identityChallengeValue {
	if i.attachChallenge != nil {
		return i.attachChallenge(attach, addr)
	}
	return i.realScheme.AttachChallenge(attach, addr)
}
func (i mockIdentityScheme) VerifyRequestAndAttachResponse(attach http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error) {
	if i.verifyAndAttachResponse != nil {
		return i.verifyAndAttachResponse(attach, h)
	}
	return i.realScheme.VerifyRequestAndAttachResponse(attach, h)
}
func (i mockIdentityScheme) VerifyResponse(h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error) {
	if i.verifyResponse != nil {
		return i.verifyResponse(i.t, h, c)
	}
	return i.realScheme.VerifyResponse(h, c)
}

// when the identity challenge is misconstructed in various ways, peering should behave as expected
func TestPeeringWithBadIdentityChallenge(t *testing.T) {
	partitiontest.PartitionTest(t)

	type testCase struct {
		name            string
		attachChallenge func(attach http.Header, addr string) identityChallengeValue
		totalInA        int
		totalOutA       int
		totalInB        int
		totalOutB       int
	}

	testCases := []testCase{
		// when identityChallenge is not included, peering continues as normal
		{
			name:            "not included",
			attachChallenge: func(attach http.Header, addr string) identityChallengeValue { return identityChallengeValue{} },
			totalInA:        0,
			totalOutA:       1,
			totalInB:        1,
			totalOutB:       0,
		},
		// when the identityChallenge is malformed B64, peering halts
		{
			name: "malformed b64",
			attachChallenge: func(attach http.Header, addr string) identityChallengeValue {
				attach.Add(IdentityChallengeHeader, "this does not decode!")
				return newIdentityChallengeValue()
			},
			totalInA:  0,
			totalOutA: 0,
			totalInB:  0,
			totalOutB: 0,
		},
		// when the identityChallenge can't be unmarshalled, peering halts
		{
			name: "not msgp decodable",
			attachChallenge: func(attach http.Header, addr string) identityChallengeValue {
				attach.Add(IdentityChallengeHeader, base64.StdEncoding.EncodeToString([]byte("Bad!Data!")))
				return newIdentityChallengeValue()
			},
			totalInA:  0,
			totalOutA: 0,
			totalInB:  0,
			totalOutB: 0,
		},
		// when the incorrect address is used, peering continues
		{
			name: "incorrect address",
			attachChallenge: func(attach http.Header, addr string) identityChallengeValue {
				s := NewIdentityChallengeScheme(NetIdentityDedupNames("does not matter")) // make a scheme to use its keys
				c := identityChallenge{
					Key:           s.identityKeys.PublicKey(),
					Challenge:     newIdentityChallengeValue(),
					PublicAddress: []byte("incorrect address!"),
				}
				attach.Add(IdentityChallengeHeader, c.signAndEncodeB64(s.identityKeys))
				return c.Challenge
			},
			totalInA:  0,
			totalOutA: 1,
			totalInB:  1,
			totalOutB: 0,
		},
		// when the challenge is incorrectly signed, peering halts
		{
			name: "bad signature",
			attachChallenge: func(attach http.Header, addr string) identityChallengeValue {
				s := NewIdentityChallengeScheme(NetIdentityDedupNames("does not matter")) // make a scheme to use its keys
				c := identityChallenge{
					Key:           s.identityKeys.PublicKey(),
					Challenge:     newIdentityChallengeValue(),
					PublicAddress: []byte("incorrect address!"),
				}.Sign(s.identityKeys)
				c.Msg.Challenge = newIdentityChallengeValue() // change the challenge after signing the message, so the signature check fails
				enc := protocol.Encode(&c)
				b64enc := base64.StdEncoding.EncodeToString(enc)
				attach.Add(IdentityChallengeHeader, b64enc)
				return c.Msg.Challenge
			},
			totalInA:  0,
			totalOutA: 0,
			totalInB:  0,
			totalOutB: 0,
		},
	}

	for _, tc := range testCases {
		t.Logf("Running Peering with Identity Challenge Test: %s", tc.name)
		netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
		netA.identityTracker = newMockIdentityTracker(netA.identityTracker)
		netA.config.PublicAddress = "testing"
		netA.config.GossipFanout = 1

		scheme := newMockIdentityScheme(t)
		scheme.attachChallenge = tc.attachChallenge
		netA.identityScheme = scheme

		netB := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netB"})
		netB.identityTracker = newMockIdentityTracker(netB.identityTracker)
		netB.config.PublicAddress = "testing"
		netB.config.GossipFanout = 1

		netA.Start()
		defer netA.Stop()
		netB.Start()
		defer netB.Stop()

		addrB, ok := netB.Address()
		require.True(t, ok)
		gossipB, err := netB.addrToGossipAddr(addrB)
		require.NoError(t, err)

		// set addresses to just host:port to match phonebook/dns format
		addrB = hostAndPort(addrB)

		if _, ok := netA.tryConnectReserveAddr(addrB); ok {
			netA.wg.Add(1)
			netA.tryConnect(addrB, gossipB)
			// let the tryConnect go forward
			time.Sleep(250 * time.Millisecond)
		}
		assert.Equal(t, tc.totalInA, len(netA.GetPeers(PeersConnectedIn)))
		assert.Equal(t, tc.totalOutA, len(netA.GetPeers(PeersConnectedOut)))
		assert.Equal(t, tc.totalInB, len(netB.GetPeers(PeersConnectedIn)))
		assert.Equal(t, tc.totalOutB, len(netB.GetPeers(PeersConnectedOut)))
	}

}

// when the identity challenge response is misconstructed in various way, confirm peering behaves as expected
func TestPeeringWithBadIdentityChallengeResponse(t *testing.T) {
	partitiontest.PartitionTest(t)

	type testCase struct {
		name                    string
		verifyAndAttachResponse func(attach http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error)
		totalInA                int
		totalOutA               int
		totalInB                int
		totalOutB               int
	}

	testCases := []testCase{
		// when there is no response to the identity challenge, peering should continue without ID
		{
			name: "not included",
			verifyAndAttachResponse: func(attach http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error) {
				return identityChallengeValue{}, crypto.PublicKey{}, nil
			},
			totalInA:  0,
			totalOutA: 1,
			totalInB:  1,
			totalOutB: 0,
		},
		// when the response is malformed, do not peer
		{
			name: "malformed b64",
			verifyAndAttachResponse: func(attach http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error) {
				attach.Add(IdentityChallengeHeader, "this does not decode!")
				return identityChallengeValue{}, crypto.PublicKey{}, nil
			},
			totalInA:  0,
			totalOutA: 0,
			totalInB:  0,
			totalOutB: 0,
		},
		// when the response is malformed, do not peer
		{
			name: "not msgp decodable",
			verifyAndAttachResponse: func(attach http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error) {
				attach.Add(IdentityChallengeHeader, base64.StdEncoding.EncodeToString([]byte("Bad!Data!")))
				return identityChallengeValue{}, crypto.PublicKey{}, nil
			},
			totalInA:  0,
			totalOutA: 0,
			totalInB:  0,
			totalOutB: 0,
		},
		// when the original challenge isn't included, do not peer
		{
			name: "incorrect original challenge",
			verifyAndAttachResponse: func(attach http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error) {
				s := NewIdentityChallengeScheme(NetIdentityDedupNames("does not matter")) // make a scheme to use its keys
				// decode the header to an identityChallenge
				msg, _ := base64.StdEncoding.DecodeString(h.Get(IdentityChallengeHeader))
				idChal := identityChallenge{}
				protocol.Decode(msg, &idChal)
				// make the response object, with an incorrect challenge encode it and attach it to the header
				r := identityChallengeResponse{
					Key:               s.identityKeys.PublicKey(),
					Challenge:         newIdentityChallengeValue(),
					ResponseChallenge: newIdentityChallengeValue(),
				}
				attach.Add(IdentityChallengeHeader, r.signAndEncodeB64(s.identityKeys))
				return r.ResponseChallenge, idChal.Key, nil
			},
			totalInA:  0,
			totalOutA: 0,
			totalInB:  0,
			totalOutB: 0,
		},
		// when the message is incorrectly signed, do not peer
		{
			name: "bad signature",
			verifyAndAttachResponse: func(attach http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error) {
				s := NewIdentityChallengeScheme(NetIdentityDedupNames("does not matter")) // make a scheme to use its keys
				// decode the header to an identityChallenge
				msg, _ := base64.StdEncoding.DecodeString(h.Get(IdentityChallengeHeader))
				idChal := identityChallenge{}
				protocol.Decode(msg, &idChal)
				// make the response object, then change the signature and encode and attach
				r := identityChallengeResponse{
					Key:               s.identityKeys.PublicKey(),
					Challenge:         newIdentityChallengeValue(),
					ResponseChallenge: newIdentityChallengeValue(),
				}.Sign(s.identityKeys)
				r.Msg.ResponseChallenge = newIdentityChallengeValue() // change the challenge after signing the message
				enc := protocol.Encode(&r)
				b64enc := base64.StdEncoding.EncodeToString(enc)
				attach.Add(IdentityChallengeHeader, b64enc)
				return r.Msg.ResponseChallenge, idChal.Key, nil
			},
			totalInA:  0,
			totalOutA: 0,
			totalInB:  0,
			totalOutB: 0,
		},
	}

	for _, tc := range testCases {
		t.Logf("Running Peering with Identity Challenge Response Test: %s", tc.name)
		netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
		netA.identityTracker = newMockIdentityTracker(netA.identityTracker)
		netA.config.PublicAddress = "testing"
		netA.config.GossipFanout = 1

		netB := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netB"})
		netB.identityTracker = newMockIdentityTracker(netB.identityTracker)
		netB.config.PublicAddress = "testing"
		netB.config.GossipFanout = 1

		scheme := newMockIdentityScheme(t)
		scheme.verifyAndAttachResponse = tc.verifyAndAttachResponse
		netB.identityScheme = scheme

		netA.Start()
		defer netA.Stop()
		netB.Start()
		defer netB.Stop()

		addrB, ok := netB.Address()
		require.True(t, ok)
		gossipB, err := netB.addrToGossipAddr(addrB)
		require.NoError(t, err)

		// set addresses to just host:port to match phonebook/dns format
		addrB = hostAndPort(addrB)

		if _, ok := netA.tryConnectReserveAddr(addrB); ok {
			netA.wg.Add(1)
			netA.tryConnect(addrB, gossipB)
			// let the tryConnect go forward
			time.Sleep(250 * time.Millisecond)
		}
		assert.Equal(t, tc.totalInA, len(netA.GetPeers(PeersConnectedIn)))
		assert.Equal(t, tc.totalOutA, len(netA.GetPeers(PeersConnectedOut)))
		assert.Equal(t, tc.totalOutB, len(netB.GetPeers(PeersConnectedOut)))
		// it is possible for NetB to be in the process of doing addPeer while
		// the underlying connection is being closed. In this case, the read loop
		// on the peer will detect and close the peer. Since this is asynchronous,
		// we wait and check regularly to allow the connection to settle
		assert.Eventually(
			t,
			func() bool { return len(netB.GetPeers(PeersConnectedIn)) == tc.totalInB },
			5*time.Second,
			100*time.Millisecond)
	}

}

// when the identity challenge verification is misconstructed in various ways, peering should behave as expected
func TestPeeringWithBadIdentityVerification(t *testing.T) {
	partitiontest.PartitionTest(t)

	type testCase struct {
		name           string
		verifyResponse func(t *testing.T, h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error)
		totalInA       int
		totalOutA      int
		totalInB       int
		totalOutB      int
		occupied       bool
	}

	testCases := []testCase{
		// in a totally unmodified scenario, the two peers stay connected even after the verification timeout
		{
			name:      "happy path",
			totalInA:  0,
			totalOutA: 1,
			totalInB:  1,
			totalOutB: 0,
		},
		// if the peer does not send a final message, the peers stay connected
		{
			name: "not included",
			verifyResponse: func(t *testing.T, h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error) {
				return crypto.PublicKey{}, []byte{}, nil
			},
			totalInA:  0,
			totalOutA: 1,
			totalInB:  1,
			totalOutB: 0,
		},
		// when the identityVerification can't be unmarshalled, peer is disconnected
		{
			name: "not msgp decodable",
			verifyResponse: func(t *testing.T, h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error) {
				message := append([]byte(protocol.NetIDVerificationTag), []byte("Bad!Data!")[:]...)
				return crypto.PublicKey{}, message, nil
			},
			totalInA:  0,
			totalOutA: 0,
			totalInB:  0,
			totalOutB: 0,
		},
		{
			// when the verification signature doesn't match the peer's expectation (the previously exchanged identity), peer is disconnected
			name: "bad signature",
			verifyResponse: func(t *testing.T, h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error) {
				headerString := h.Get(IdentityChallengeHeader)
				require.NotEmpty(t, headerString)
				msg, err := base64.StdEncoding.DecodeString(headerString)
				require.NoError(t, err)
				resp := identityChallengeResponseSigned{}
				err = protocol.Decode(msg, &resp)
				require.NoError(t, err)
				s := NewIdentityChallengeScheme(NetIdentityDedupNames("does not matter")) // make a throwaway key
				ver := identityVerificationMessageSigned{
					// fill in correct ResponseChallenge field
					Msg:       identityVerificationMessage{ResponseChallenge: resp.Msg.ResponseChallenge},
					Signature: s.identityKeys.SignBytes([]byte("bad bytes for signing")),
				}
				message := append([]byte(protocol.NetIDVerificationTag), protocol.Encode(&ver)[:]...)
				return crypto.PublicKey{}, message, nil
			},
			totalInA:  0,
			totalOutA: 0,
			totalInB:  0,
			totalOutB: 0,
		},
		{
			// when the verification signature doesn't match the peer's expectation (the previously exchanged identity), peer is disconnected
			name: "bad signature",
			verifyResponse: func(t *testing.T, h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error) {
				s := NewIdentityChallengeScheme(NetIdentityDedupNames("does not matter")) // make a throwaway key
				ver := identityVerificationMessageSigned{
					// fill in wrong ResponseChallenge field
					Msg:       identityVerificationMessage{ResponseChallenge: newIdentityChallengeValue()},
					Signature: s.identityKeys.SignBytes([]byte("bad bytes for signing")),
				}
				message := append([]byte(protocol.NetIDVerificationTag), protocol.Encode(&ver)[:]...)
				return crypto.PublicKey{}, message, nil
			},
			totalInA:  0,
			totalOutA: 0,
			totalInB:  0,
			totalOutB: 0,
		},
		{
			// when the identity is already in use, peer is disconnected
			name:           "identity occupied",
			verifyResponse: nil,
			totalInA:       0,
			totalOutA:      0,
			totalInB:       0,
			totalOutB:      0,
			occupied:       true,
		},
	}

	for _, tc := range testCases {
		t.Logf("Running Peering with Identity Verification Test: %s", tc.name)
		netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
		netA.identityTracker = newMockIdentityTracker(netA.identityTracker)
		netA.config.PublicAddress = "testing"
		netA.config.GossipFanout = 1

		scheme := newMockIdentityScheme(t)
		scheme.verifyResponse = tc.verifyResponse
		netA.identityScheme = scheme

		netB := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netB"})
		netB.identityTracker = newMockIdentityTracker(netB.identityTracker)
		netB.config.PublicAddress = "testing"
		netB.config.GossipFanout = 1
		// if the key is occupied, make the tracker fail to insert the peer
		if tc.occupied {
			netB.identityTracker = newMockIdentityTracker(netB.identityTracker)
			netB.identityTracker.(*mockIdentityTracker).setIsOccupied(true)
		}

		netA.Start()
		defer netA.Stop()
		netB.Start()
		defer netB.Stop()

		addrB, ok := netB.Address()
		require.True(t, ok)
		gossipB, err := netB.addrToGossipAddr(addrB)
		require.NoError(t, err)

		// set addresses to just host:port to match phonebook/dns format
		addrB = hostAndPort(addrB)

		if _, ok := netA.tryConnectReserveAddr(addrB); ok {
			netA.wg.Add(1)
			netA.tryConnect(addrB, gossipB)
			// let the tryConnect go forward
			time.Sleep(250 * time.Millisecond)
		}

		assert.Equal(t, tc.totalInA, len(netA.GetPeers(PeersConnectedIn)))
		assert.Equal(t, tc.totalOutA, len(netA.GetPeers(PeersConnectedOut)))
		assert.Equal(t, tc.totalOutB, len(netB.GetPeers(PeersConnectedOut)))
		// it is possible for NetB to be in the process of doing addPeer while
		// the underlying connection is being closed. In this case, the read loop
		// on the peer will detect and close the peer. Since this is asynchronous,
		// we wait and check regularly to allow the connection to settle
		assert.Eventually(
			t,
			func() bool { return len(netB.GetPeers(PeersConnectedIn)) == tc.totalInB },
			5*time.Second,
			100*time.Millisecond)
	}
}

type benchmarkHandler struct {
	returns chan uint64
}

func (bh *benchmarkHandler) Handle(message IncomingMessage) OutgoingMessage {
	i := binary.LittleEndian.Uint64(message.Data)
	bh.returns <- i
	return OutgoingMessage{}
}

// Set up two nodes, test that a.Broadcast is received by B
func BenchmarkWebsocketNetworkBasic(t *testing.B) {
	deadlock.Opts.Disable = true
	const msgSize = 200
	const inflight = 90
	t.Logf("%s %d", t.Name(), t.N)
	t.StopTimer()
	t.ResetTimer()
	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.Start()
	defer netStop(t, netA, "A")
	netB := makeTestWebsocketNode(t)
	netB.config.GossipFanout = 1
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")
	returns := make(chan uint64, 100)
	bhandler := benchmarkHandler{returns}
	netB.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.TxnTag, MessageHandler: &bhandler}})

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	t.Log("a ready")
	waitReady(t, netB, readyTimeout.C)
	t.Log("b ready")
	var ireturned uint64

	t.StartTimer()
	timeoutd := (time.Duration(t.N) * 100 * time.Microsecond) + (2 * time.Second)
	timeout := time.After(timeoutd)
	for i := 0; i < t.N; i++ {
		for uint64(i) > ireturned+inflight {
			select {
			case ireturned = <-returns:
			case <-timeout:
				t.Errorf("timeout in send at %d", i)
				return
			}
		}
		msg := make([]byte, msgSize)
		binary.LittleEndian.PutUint64(msg, uint64(i))
		err := netA.Broadcast(context.Background(), protocol.TxnTag, msg, true, nil)
		if err != nil {
			t.Errorf("error on broadcast: %v", err)
			return
		}
	}
	netA.Broadcast(context.Background(), protocol.Tag("-1"), []byte("derp"), true, nil)
	t.Logf("sent %d", t.N)

	for ireturned < uint64(t.N-1) {
		select {
		case ireturned = <-returns:
		case <-timeout:
			t.Errorf("timeout, count=%d, wanted %d", ireturned, t.N)
			buf := strings.Builder{}
			networkMessageReceivedTotal.WriteMetric(&buf, "")
			networkMessageSentTotal.WriteMetric(&buf, "")
			networkBroadcasts.WriteMetric(&buf, "")
			duplicateNetworkMessageReceivedTotal.WriteMetric(&buf, "")
			outgoingNetworkMessageFilteredOutTotal.WriteMetric(&buf, "")
			networkBroadcastsDropped.WriteMetric(&buf, "")
			t.Errorf(
				"a out queue=%d, metric: %s",
				len(netA.broadcaster.broadcastQueueBulk),
				buf.String(),
			)
			return
		}
	}
	t.StopTimer()
	t.Logf("counter done")
}

// Check that priority is propagated from B to A
func TestWebsocketNetworkPrio(t *testing.T) {
	partitiontest.PartitionTest(t)

	prioA := netPrioStub{}
	netA := makeTestWebsocketNode(t)
	netA.SetPrioScheme(&prioA)
	netA.config.GossipFanout = 1
	netA.prioResponseChan = make(chan *wsPeer, 10)
	netA.Start()
	defer netStop(t, netA, "A")

	prioB := netPrioStub{}
	crypto.RandBytes(prioB.addr[:])
	prioB.prio = crypto.RandUint64()
	netB := makeTestWebsocketNode(t)
	netB.SetPrioScheme(&prioB)
	netB.config.GossipFanout = 1
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")

	// Wait for response message to propagate from B to A
	select {
	case <-netA.prioResponseChan:
	case <-time.After(time.Second):
		t.Errorf("timeout on netA.prioResponseChan")
	}
	waitReady(t, netA, time.After(time.Second))

	// Peek at A's peers
	netA.peersLock.RLock()
	defer netA.peersLock.RUnlock()
	require.Equal(t, len(netA.peers), 1)

	require.Equal(t, netA.peers[0].prioAddress, prioB.addr)
	require.Equal(t, netA.peers[0].prioWeight, prioB.prio)
}

// Check that priority is propagated from B to A
func TestWebsocketNetworkPrioLimit(t *testing.T) {
	partitiontest.PartitionTest(t)

	limitConf := defaultConfig
	limitConf.BroadcastConnectionsLimit = 1

	prioA := netPrioStub{}
	netA := makeTestWebsocketNodeWithConfig(t, limitConf)
	netA.SetPrioScheme(&prioA)
	netA.config.GossipFanout = 2
	netA.prioResponseChan = make(chan *wsPeer, 10)
	netA.Start()
	defer netStop(t, netA, "A")
	addrA, postListen := netA.Address()
	require.True(t, postListen)

	counterB := newMessageCounter(t, 1)
	counterBdone := counterB.done
	prioB := netPrioStub{}
	crypto.RandBytes(prioB.addr[:])
	prioB.prio = 100
	netB := makeTestWebsocketNode(t)
	netB.SetPrioScheme(&prioB)
	netB.config.GossipFanout = 1
	netB.config.NetAddress = ""
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.TxnTag, MessageHandler: counterB}})
	netB.Start()
	defer netStop(t, netB, "B")

	counterC := newMessageCounter(t, 1)
	counterCdone := counterC.done
	prioC := netPrioStub{}
	crypto.RandBytes(prioC.addr[:])
	prioC.prio = 10
	netC := makeTestWebsocketNode(t)
	netC.SetPrioScheme(&prioC)
	netC.config.GossipFanout = 1
	netC.config.NetAddress = ""
	netC.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netC.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.TxnTag, MessageHandler: counterC}})
	netC.Start()
	defer func() { t.Log("stopping C"); netC.Stop(); t.Log("C done") }()

	// Wait for response messages to propagate from B+C to A
	select {
	case peer := <-netA.prioResponseChan:
		netA.peersLock.RLock()
		require.Subset(t, []uint64{prioB.prio, prioC.prio}, []uint64{peer.prioWeight})
		netA.peersLock.RUnlock()
	case <-time.After(time.Second):
		t.Errorf("timeout on netA.prioResponseChan 1")
	}
	select {
	case peer := <-netA.prioResponseChan:
		netA.peersLock.RLock()
		require.Subset(t, []uint64{prioB.prio, prioC.prio}, []uint64{peer.prioWeight})
		netA.peersLock.RUnlock()
	case <-time.After(time.Second):
		t.Errorf("timeout on netA.prioResponseChan 2")
	}
	waitReady(t, netA, time.After(time.Second))

	firstPeer := netA.peers[0]
	netA.Broadcast(context.Background(), protocol.TxnTag, nil, true, nil)

	failed := false
	select {
	case <-counterBdone:
	case <-time.After(time.Second):
		t.Errorf("timeout, B did not receive message")
		failed = true
	}

	select {
	case <-counterCdone:
		t.Errorf("C received message")
		failed = true
	case <-time.After(time.Second):
	}

	if failed {
		t.Errorf("NetA had the following two peers priorities : [0]:%s=%d [1]:%s=%d", netA.peers[0].GetAddress(), netA.peers[0].prioWeight, netA.peers[1].GetAddress(), netA.peers[1].prioWeight)
		t.Errorf("first peer before broadcasting was %s", firstPeer.GetAddress())
	}
}

// Create many idle connections, to see if we have excessive CPU utilization.
func TestWebsocketNetworkManyIdle(t *testing.T) {
	partitiontest.PartitionTest(t)

	// This test is meant to be run manually, as:
	//
	//   IDLETEST=x go test -v . -run=ManyIdle -count=1
	//
	// and examining the reported CPU time use.

	if os.Getenv("IDLETEST") == "" {
		t.Skip("Skipping; IDLETEST not set")
	}

	deadlock.Opts.Disable = true

	numClients := 1000
	relayConf := defaultConfig
	relayConf.BaseLoggerDebugLevel = uint32(logging.Error)
	relayConf.MaxConnectionsPerIP = numClients

	relay := makeTestWebsocketNodeWithConfig(t, relayConf)
	relay.config.GossipFanout = numClients
	relay.Start()
	defer relay.Stop()
	relayAddr, postListen := relay.Address()
	require.True(t, postListen)

	clientConf := defaultConfig
	clientConf.BaseLoggerDebugLevel = uint32(logging.Error)
	clientConf.BroadcastConnectionsLimit = 0
	clientConf.NetAddress = ""

	var clients []*WebsocketNetwork
	for i := 0; i < numClients; i++ {
		client := makeTestWebsocketNodeWithConfig(t, clientConf)
		client.config.GossipFanout = 1
		client.phonebook.ReplacePeerList([]string{relayAddr}, "default", phonebook.RelayRole)
		client.Start()
		defer client.Stop()

		clients = append(clients, client)
	}

	readyTimeout := time.NewTimer(30 * time.Second)
	waitReady(t, relay, readyTimeout.C)

	for i := 0; i < numClients; i++ {
		waitReady(t, clients[i], readyTimeout.C)
	}

	var r0utime, r1utime int64
	var r0stime, r1stime int64

	r0utime, r0stime, _ = util.GetCurrentProcessTimes()
	time.Sleep(10 * time.Second)
	r1utime, r1stime, _ = util.GetCurrentProcessTimes()

	t.Logf("Background CPU use: user %v, system %v\n",
		time.Duration(r1utime-r0utime),
		time.Duration(r1stime-r0stime))
}

// TODO: test both sides of http-header setting and checking?
// TODO: test request-disconnect-reconnect?
// TODO: test server handling of various malformed clients?
// TODO? disconnect a node in the middle of a line and test that messages _don't_ get through?
// TODO: test self-connect rejection
// TODO: test funcion when some message handler is slow?

func TestWebsocketNetwork_getCommonHeaders(t *testing.T) {
	partitiontest.PartitionTest(t)

	header := http.Header{}
	expectedTelemetryGUID := "123"
	expectedInstanceName := "456"
	expectedPublicAddr := "789"
	header.Set(TelemetryIDHeader, expectedTelemetryGUID)
	header.Set(InstanceNameHeader, expectedInstanceName)
	header.Set(AddressHeader, expectedPublicAddr)
	otherTelemetryGUID, otherInstanceName, otherPublicAddr := getCommonHeaders(header)
	require.Equal(t, expectedTelemetryGUID, otherTelemetryGUID)
	require.Equal(t, expectedInstanceName, otherInstanceName)
	require.Equal(t, expectedPublicAddr, otherPublicAddr)
}

func TestWebsocketNetwork_checkServerResponseVariables(t *testing.T) {
	partitiontest.PartitionTest(t)

	wn := makeTestWebsocketNode(t)
	wn.genesisInfo.GenesisID = "genesis-id1"
	wn.randomID = "random-id1"
	header := http.Header{}
	header.Set(ProtocolVersionHeader, ProtocolVersion)
	header.Set(NodeRandomHeader, wn.randomID+"tag")
	header.Set(GenesisHeader, wn.genesisInfo.GenesisID)
	responseVariableOk, matchingVersion := wn.checkServerResponseVariables(header, "addressX")
	require.Equal(t, true, responseVariableOk)
	require.Equal(t, matchingVersion, ProtocolVersion)

	noVersionHeader := http.Header{}
	noVersionHeader.Set(NodeRandomHeader, wn.randomID+"tag")
	noVersionHeader.Set(GenesisHeader, wn.genesisInfo.GenesisID)
	responseVariableOk, _ = wn.checkServerResponseVariables(noVersionHeader, "addressX")
	require.Equal(t, false, responseVariableOk)

	noRandomHeader := http.Header{}
	noRandomHeader.Set(ProtocolVersionHeader, ProtocolVersion)
	noRandomHeader.Set(GenesisHeader, wn.genesisInfo.GenesisID)
	responseVariableOk, _ = wn.checkServerResponseVariables(noRandomHeader, "addressX")
	require.Equal(t, false, responseVariableOk)

	sameRandomHeader := http.Header{}
	sameRandomHeader.Set(ProtocolVersionHeader, ProtocolVersion)
	sameRandomHeader.Set(NodeRandomHeader, wn.randomID)
	sameRandomHeader.Set(GenesisHeader, wn.genesisInfo.GenesisID)
	responseVariableOk, _ = wn.checkServerResponseVariables(sameRandomHeader, "addressX")
	require.Equal(t, false, responseVariableOk)

	differentGenesisIDHeader := http.Header{}
	differentGenesisIDHeader.Set(ProtocolVersionHeader, ProtocolVersion)
	differentGenesisIDHeader.Set(NodeRandomHeader, wn.randomID+"tag")
	differentGenesisIDHeader.Set(GenesisHeader, wn.genesisInfo.GenesisID+"tag")
	responseVariableOk, _ = wn.checkServerResponseVariables(differentGenesisIDHeader, "addressX")
	require.Equal(t, false, responseVariableOk)
}

func (wn *WebsocketNetwork) broadcastWithTimestamp(tag protocol.Tag, data []byte, when time.Time) error {
	request := broadcastRequest{tag: tag, data: data, enqueueTime: when, ctx: context.Background()}

	broadcastQueue := wn.broadcaster.broadcastQueueBulk
	if highPriorityTag(tag) {
		broadcastQueue = wn.broadcaster.broadcastQueueHighPrio
	}
	// no wait
	select {
	case broadcastQueue <- request:
		return nil
	default:
		return errBcastQFull
	}
}

func TestDelayedMessageDrop(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.Start()
	defer netStop(t, netA, "A")

	noAddressConfig := defaultConfig
	noAddressConfig.NetAddress = ""
	netB := makeTestWebsocketNodeWithConfig(t, noAddressConfig)
	netB.config.GossipFanout = 1
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")
	counter := newMessageCounter(t, 5)
	counterDone := counter.done
	netB.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.TxnTag, MessageHandler: counter}})

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	currentTime := time.Now()
	for i := 0; i < 10; i++ {
		err := netA.broadcastWithTimestamp(protocol.TxnTag, []byte("foo"), currentTime.Add(time.Hour*time.Duration(i-5)))
		require.NoErrorf(t, err, "No error was expected")
	}

	select {
	case <-counterDone:
	case <-time.After(maxMessageQueueDuration):
		require.Equalf(t, 5, counter.count, "One or more messages failed to reach destination network")
	}
}

func TestSlowPeerDisconnection(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)
	log.SetLevel(logging.Info)
	wn := &WebsocketNetwork{
		log:       log,
		config:    defaultConfig,
		phonebook: phonebook.MakePhonebook(1, 1*time.Millisecond),
		genesisInfo: GenesisInfo{
			GenesisID: genesisID,
			NetworkID: config.Devtestnet,
		},
		peerStater:      peerConnectionStater{log: log},
		identityTracker: noopIdentityTracker{},
	}
	wn.setup()
	wn.broadcaster.slowWritingPeerMonitorInterval = time.Millisecond * 50
	wn.eventualReadyDelay = time.Second
	wn.messagesOfInterest = nil // clear this before starting the network so that we won't be sending a MOI upon connection.

	netA := wn
	netA.config.GossipFanout = 1
	netA.Start()
	defer netStop(t, netA, "A")

	noAddressConfig := defaultConfig
	noAddressConfig.NetAddress = ""
	netB := makeTestWebsocketNodeWithConfig(t, noAddressConfig)
	netB.config.GossipFanout = 1
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	var peers []*wsPeer
	peers, _ = netA.peerSnapshot(peers)
	require.Equalf(t, len(peers), 1, "Expected number of peers should be 1")
	peer := peers[0]
	// On connection may send a MOI message, wait for it to go out
	now := time.Now()
	expire := now.Add(5 * time.Second)
	for {
		time.Sleep(10 * time.Millisecond)
		if len(peer.sendBufferHighPrio)+len(peer.sendBufferBulk) == 0 {
			break
		}
		now = time.Now()
		if now.After(expire) {
			t.Errorf("wait for empty peer outbound queue expired")
		}
	}
	// modify the peer on netA and
	beforeLoopTime := time.Now()
	peer.intermittentOutgoingMessageEnqueueTime.Store(beforeLoopTime.Add(-maxMessageQueueDuration).Add(time.Second).UnixNano())
	// wait up to 10 seconds for the monitor to figure out it needs to disconnect.
	expire = beforeLoopTime.Add(2 * slowWritingPeerMonitorInterval)
	for {
		peers, _ = netA.peerSnapshot(peers)
		if len(peers) == 0 || peers[0] != peer {
			// make sure it took more than 1 second, and less than 5 seconds.
			waitTime := time.Since(beforeLoopTime)
			require.LessOrEqual(t, int64(time.Second), int64(waitTime))
			require.GreaterOrEqual(t, int64(5*time.Second), int64(waitTime))
			break
		}
		if time.Now().After(expire) {
			require.Fail(t, "Slow peer was not disconnected")
		}
		time.Sleep(time.Millisecond * 5)
	}
}

func TestForceMessageRelaying(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)
	log.SetLevel(logging.Level(defaultConfig.BaseLoggerDebugLevel))
	wn := &WebsocketNetwork{
		log:       log,
		config:    defaultConfig,
		phonebook: phonebook.MakePhonebook(1, 1*time.Millisecond),
		genesisInfo: GenesisInfo{
			GenesisID: genesisID,
			NetworkID: config.Devtestnet,
		},
		peerStater:      peerConnectionStater{log: log},
		identityTracker: noopIdentityTracker{},
	}
	wn.setup()
	wn.eventualReadyDelay = time.Second

	netA := wn
	netA.config.GossipFanout = 1

	defer netStop(t, netA, "A")

	counter := newMessageCounter(t, 5)
	counterDone := counter.done
	netA.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.TxnTag, MessageHandler: counter}})
	netA.Start()
	addrA, postListen := netA.Address()
	require.Truef(t, postListen, "Listening network failed to start")

	noAddressConfig := defaultConfig
	noAddressConfig.NetAddress = ""
	netB := makeTestWebsocketNodeWithConfig(t, noAddressConfig)
	netB.config.GossipFanout = 1
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")

	noAddressConfig.ForceRelayMessages = true
	netC := makeTestWebsocketNodeWithConfig(t, noAddressConfig)
	netC.config.GossipFanout = 1
	netC.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netC.Start()
	defer func() { t.Log("stopping C"); netC.Stop(); t.Log("C done") }()

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)
	waitReady(t, netC, readyTimeout.C)

	// send 5 messages from both netB and netC to netA
	for i := 0; i < 5; i++ {
		err := netB.Relay(context.Background(), protocol.TxnTag, []byte{1, 2, 3}, true, nil)
		require.NoError(t, err)
		err = netC.Relay(context.Background(), protocol.TxnTag, []byte{1, 2, 3}, true, nil)
		require.NoError(t, err)
	}

	select {
	case <-counterDone:
	case <-time.After(2 * time.Second):
		if counter.count < 5 {
			require.Failf(t, "One or more messages failed to reach destination network", "%d > %d", 5, counter.count)
		} else if counter.count > 5 {
			require.Failf(t, "One or more messages that were expected to be dropped, reached destination network", "%d < %d", 5, counter.count)
		}
	}
	netA.ClearHandlers()
	counter = newMessageCounter(t, 10)
	counterDone = counter.done
	netA.RegisterHandlers([]TaggedMessageHandler{{Tag: protocol.TxnTag, MessageHandler: counter}})

	// hack the relayMessages on the netB so that it would start sending messages.
	netB.relayMessages = true
	// send additional 10 messages from netB
	for i := 0; i < 10; i++ {
		err := netB.Relay(context.Background(), protocol.TxnTag, []byte{1, 2, 3}, true, nil)
		require.NoError(t, err)
	}

	select {
	case <-counterDone:
	case <-time.After(2 * time.Second):
		require.Failf(t, "One or more messages failed to reach destination network", "%d > %d", 10, counter.count)
	}

}

func TestSetUserAgentHeader(t *testing.T) {
	partitiontest.PartitionTest(t)

	headers := http.Header{}
	SetUserAgentHeader(headers)
	require.Equal(t, 1, len(headers))
	t.Log(headers)
}

func TestCheckProtocolVersionMatch(t *testing.T) {
	partitiontest.PartitionTest(t)

	log := logging.TestingLog(t)
	log.SetLevel(logging.Level(defaultConfig.BaseLoggerDebugLevel))
	wn := &WebsocketNetwork{
		log:       log,
		config:    defaultConfig,
		phonebook: phonebook.MakePhonebook(1, 1*time.Millisecond),
		genesisInfo: GenesisInfo{
			GenesisID: genesisID,
			NetworkID: config.Devtestnet,
		},
		peerStater:      peerConnectionStater{log: log},
		identityTracker: noopIdentityTracker{},
	}
	wn.setup()
	wn.supportedProtocolVersions = []string{"2", "1"}

	header1 := make(http.Header)
	header1.Add(ProtocolAcceptVersionHeader, "1")
	header1.Add(ProtocolVersionHeader, "3")
	matchingVersion, otherVersion := checkProtocolVersionMatch(header1, wn.supportedProtocolVersions)
	require.Equal(t, "1", matchingVersion)
	require.Equal(t, "", otherVersion)

	header2 := make(http.Header)
	header2.Add(ProtocolAcceptVersionHeader, "3")
	header2.Add(ProtocolAcceptVersionHeader, "4")
	header2.Add(ProtocolVersionHeader, "1")
	matchingVersion, otherVersion = checkProtocolVersionMatch(header2, wn.supportedProtocolVersions)
	require.Equal(t, "1", matchingVersion)
	require.Equal(t, "1", otherVersion)

	header3 := make(http.Header)
	header3.Add(ProtocolVersionHeader, "3")
	matchingVersion, otherVersion = checkProtocolVersionMatch(header3, wn.supportedProtocolVersions)
	require.Equal(t, "", matchingVersion)
	require.Equal(t, "3", otherVersion)

	header4 := make(http.Header)
	header4.Add(ProtocolVersionHeader, "5\n")
	matchingVersion, otherVersion = checkProtocolVersionMatch(header4, wn.supportedProtocolVersions)
	require.Equal(t, "", matchingVersion)
	require.Equal(t, "5"+unprintableCharacterGlyph, otherVersion)
}

func handleTopicRequest(msg IncomingMessage) (out OutgoingMessage) {

	topics, err := UnmarshallTopics(msg.Data)
	if err != nil {
		return
	}

	val1b, f := topics.GetValue("val1")
	if !f {
		return
	}
	val2b, f := topics.GetValue("val2")
	if !f {
		return
	}
	val1 := int(val1b[0])
	val2 := int(val2b[0])

	respTopics := Topics{
		Topic{
			key:  "value",
			data: []byte{byte(val1 + val2)},
		},
	}
	return OutgoingMessage{
		Action: Respond,
		Tag:    protocol.TopicMsgRespTag,
		Topics: respTopics,
	}
}

// Set up two nodes, test topics send/receive is working
func TestWebsocketNetworkTopicRoundtrip(t *testing.T) {
	partitiontest.PartitionTest(t)

	var topicMsgReqTag Tag = protocol.UniEnsBlockReqTag
	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.Start()
	defer netStop(t, netA, "A")
	netB := makeTestWebsocketNode(t)
	netB.config.GossipFanout = 1
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")

	netB.RegisterHandlers([]TaggedMessageHandler{
		{
			Tag:            topicMsgReqTag,
			MessageHandler: HandlerFunc(handleTopicRequest),
		},
	})

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	t.Log("a ready")
	waitReady(t, netB, readyTimeout.C)
	t.Log("b ready")

	peerA := netA.peers[0]

	topics := Topics{
		Topic{
			key:  "command",
			data: []byte("add"),
		},
		Topic{
			key:  "val1",
			data: []byte{1},
		},
		Topic{
			key:  "val2",
			data: []byte{4},
		},
	}

	resp, err := peerA.Request(context.Background(), topicMsgReqTag, topics)
	assert.NoError(t, err)

	sum, found := resp.Topics.GetValue("value")
	assert.Equal(t, true, found)
	assert.Equal(t, 5, int(sum[0]))
}

func waitPeerInternalChanQuiet(t *testing.T, netA *WebsocketNetwork) {
	// okay, but now we need to wait for asynchronous thread within netA to _apply_ the MOI to its peer for netB...
	timeout := time.Now().Add(100 * time.Millisecond)
	waiting := true
	for waiting {
		time.Sleep(1 * time.Millisecond)
		peers := netA.GetPeers(PeersConnectedIn)
		for _, pg := range peers {
			wp := pg.(*wsPeer)
			if len(wp.sendBufferHighPrio)+len(wp.sendBufferBulk) == 0 {
				waiting = false
				break
			}
		}
		if time.Now().After(timeout) {
			for _, pg := range peers {
				wp := pg.(*wsPeer)
				if len(wp.sendBufferHighPrio)+len(wp.sendBufferBulk) == 0 {
					t.Fatalf("netA peer buff empty timeout len(high)=%d, len(bulk)=%d", len(wp.sendBufferHighPrio), len(wp.sendBufferBulk))
				}
			}
		}
	}
}

func waitForMOIRefreshQuiet(netB *WebsocketNetwork) {
	for {
		// wait for async messagesOfInterestRefresh
		time.Sleep(time.Millisecond)
		if len(netB.messagesOfInterestRefresh) == 0 {
			break
		}
	}
}

// Set up two nodes, have one of them request a certain message tag mask, and verify the other follow that.
func TestWebsocketNetworkMessageOfInterest(t *testing.T) {
	partitiontest.PartitionTest(t)
	var (
		ft1 = protocol.Tag("AV")
		ft2 = protocol.Tag("UE")
		ft3 = protocol.Tag("NI")
		ft4 = protocol.Tag("TX")

		testTags = []protocol.Tag{ft1, ft2, ft3, ft4}
	)
	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.config.EnablePingHandler = false

	netA.Start()
	defer netStop(t, netA, "A")
	netB := makeTestWebsocketNode(t)
	netB.config.GossipFanout = 1
	netB.config.EnablePingHandler = false
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Logf("netA %s", addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)

	// have netB asking netA to send it ft2.
	// Max MOI size is calculated by encoding all of the valid tags, since we are using a custom tag here we must deregister one in the default set.
	netB.registerMessageInterest(ft2)

	netB.Start()
	defer netStop(t, netB, "B")
	addrB, _ := netB.Address()
	t.Logf("netB %s", addrB)

	incomingMsgSync := deadlock.Mutex{}
	msgCounters := make(map[protocol.Tag]int)
	expectedCounts := make(map[protocol.Tag]int)
	expectedCounts[ft2] = 5
	var failed atomic.Uint32
	messageArriveWg := sync.WaitGroup{}
	msgHandler := func(msg IncomingMessage) (out OutgoingMessage) {
		t.Logf("A->B %s", msg.Tag)
		incomingMsgSync.Lock()
		defer incomingMsgSync.Unlock()
		expected := expectedCounts[msg.Tag]
		if expected < 1 {
			failed.Store(1)
			t.Logf("UNEXPECTED A->B %s", msg.Tag)
			return
		}
		msgCounters[msg.Tag] = msgCounters[msg.Tag] + 1
		messageArriveWg.Done()
		return
	}
	messageFilterArriveWg := sync.WaitGroup{}
	messageFilterArriveWg.Add(1)
	waitMessageArriveHandler := func(msg IncomingMessage) (out OutgoingMessage) {
		messageFilterArriveWg.Done()
		return
	}

	// register all the handlers.
	taggedHandlers := []TaggedMessageHandler{}
	for _, tag := range testTags {
		taggedHandlers = append(taggedHandlers, TaggedMessageHandler{
			Tag:            tag,
			MessageHandler: HandlerFunc(msgHandler),
		})
	}
	netB.RegisterHandlers(taggedHandlers)
	netA.RegisterHandlers([]TaggedMessageHandler{
		{
			Tag:            protocol.VoteBundleTag,
			MessageHandler: HandlerFunc(waitMessageArriveHandler),
		}})

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	// have netB asking netA to send it only AgreementVoteTag and ProposalPayloadTag
	netB.registerMessageInterest(ft2)
	netB.DeregisterMessageInterest(ft1)
	netB.DeregisterMessageInterest(ft3)
	netB.DeregisterMessageInterest(ft4)

	// send another message which we can track, so that we'll know that the first message was delivered.
	netB.Broadcast(context.Background(), protocol.VoteBundleTag, []byte{0, 1, 2, 3, 4}, true, nil)
	messageFilterArriveWg.Wait()
	waitPeerInternalChanQuiet(t, netA)

	messageArriveWg.Add(5) // we're expecting exactly 5 messages.
	// send 5 messages of few types.
	for i := 0; i < 5; i++ {
		if failed.Load() != 0 {
			t.Errorf("failed")
			break
		}
		netA.Broadcast(context.Background(), ft1, []byte{0, 1, 2, 3, 4}, true, nil) // NOT in MOI
		netA.Broadcast(context.Background(), ft3, []byte{0, 1, 2, 3, 4}, true, nil) // NOT in MOI
		netA.Broadcast(context.Background(), ft2, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), ft4, []byte{0, 1, 2, 3, 4}, true, nil) // NOT in MOI
	}
	if failed.Load() != 0 {
		t.Errorf("failed")
	}
	// wait until all the expected messages arrive.
	messageArriveWg.Wait()
	incomingMsgSync.Lock()
	defer incomingMsgSync.Unlock()
	require.Equal(t, 1, len(msgCounters))
	for tag, count := range msgCounters {
		if failed.Load() != 0 {
			t.Errorf("failed")
			break
		}
		if tag == ft1 || tag == ft2 {
			require.Equal(t, 5, count)
		} else {
			require.Equal(t, 0, count)
		}
	}
}

// Set up two nodes, have one of them work through TX gossip message-of-interest logic
// test:
// * wn.config.ForceFetchTransactions
// * wn.config.ForceRelayMessages
// * NodeInfo.IsParticipating() + WebsocketNetwork.OnNetworkAdvance()
func TestWebsocketNetworkTXMessageOfInterestRelay(t *testing.T) {
	// Tests that A->B follows MOI
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.config.EnablePingHandler = false

	netA.Start()
	defer netStop(t, netA, "A")
	bConfig := defaultConfig
	bConfig.NetAddress = ""
	bConfig.ForceRelayMessages = true
	netB := makeTestWebsocketNodeWithConfig(t, bConfig)
	netB.config.GossipFanout = 1
	netB.config.EnablePingHandler = false
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")

	incomingMsgSync := deadlock.Mutex{}
	msgCounters := make(map[protocol.Tag]int)
	messageArriveWg := sync.WaitGroup{}
	msgHandler := func(msg IncomingMessage) (out OutgoingMessage) {
		t.Logf("A->B %s", msg.Tag)
		incomingMsgSync.Lock()
		defer incomingMsgSync.Unlock()
		msgCounters[msg.Tag] = msgCounters[msg.Tag] + 1
		messageArriveWg.Done()
		return
	}
	messageFilterArriveWg := sync.WaitGroup{}
	messageFilterArriveWg.Add(1)
	waitMessageArriveHandler := func(msg IncomingMessage) (out OutgoingMessage) {
		messageFilterArriveWg.Done()
		return
	}

	// register all the handlers.
	taggedHandlers := []TaggedMessageHandler{}
	for tag := range defaultSendMessageTags {
		taggedHandlers = append(taggedHandlers, TaggedMessageHandler{
			Tag:            tag,
			MessageHandler: HandlerFunc(msgHandler),
		})
	}
	netB.RegisterHandlers(taggedHandlers)
	netA.RegisterHandlers([]TaggedMessageHandler{
		{
			Tag:            protocol.AgreementVoteTag,
			MessageHandler: HandlerFunc(waitMessageArriveHandler),
		}})

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	netB.OnNetworkAdvance()
	waitForMOIRefreshQuiet(netB)
	// send another message which we can track, so that we'll know that the first message was delivered.
	netB.Broadcast(context.Background(), protocol.AgreementVoteTag, []byte{0, 1, 2, 3, 4}, true, nil)
	messageFilterArriveWg.Wait()

	messageArriveWg.Add(5 * 4) // we're expecting exactly 20 messages.
	// send 5 messages of few types.
	for i := 0; i < 5; i++ {
		netA.Broadcast(context.Background(), protocol.AgreementVoteTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.TxnTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.ProposalPayloadTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.VoteBundleTag, []byte{0, 1, 2, 3, 4}, true, nil)
	}
	// wait until all the expected messages arrive.
	messageArriveWg.Wait()
	incomingMsgSync.Lock()
	require.Equal(t, 4, len(msgCounters))
	for _, count := range msgCounters {
		require.Equal(t, 5, count)
	}
	incomingMsgSync.Unlock()
}

func TestWebsocketNetworkTXMessageOfInterestForceTx(t *testing.T) {
	// Tests that A->B follows MOI
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.config.EnablePingHandler = false

	netA.Start()
	defer netStop(t, netA, "A")
	bConfig := defaultConfig
	bConfig.NetAddress = ""
	bConfig.ForceFetchTransactions = true
	netB := makeTestWebsocketNodeWithConfig(t, bConfig)
	netB.config.GossipFanout = 1
	netB.config.EnablePingHandler = false
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")

	incomingMsgSync := deadlock.Mutex{}
	msgCounters := make(map[protocol.Tag]int)
	messageArriveWg := sync.WaitGroup{}
	msgHandler := func(msg IncomingMessage) (out OutgoingMessage) {
		t.Logf("A->B %s", msg.Tag)
		incomingMsgSync.Lock()
		defer incomingMsgSync.Unlock()
		msgCounters[msg.Tag] = msgCounters[msg.Tag] + 1
		messageArriveWg.Done()
		return
	}
	messageFilterArriveWg := sync.WaitGroup{}
	messageFilterArriveWg.Add(1)
	waitMessageArriveHandler := func(msg IncomingMessage) (out OutgoingMessage) {
		messageFilterArriveWg.Done()
		return
	}

	// register all the handlers.
	taggedHandlers := []TaggedMessageHandler{}
	for tag := range defaultSendMessageTags {
		taggedHandlers = append(taggedHandlers, TaggedMessageHandler{
			Tag:            tag,
			MessageHandler: HandlerFunc(msgHandler),
		})
	}
	netB.RegisterHandlers(taggedHandlers)
	netA.RegisterHandlers([]TaggedMessageHandler{
		{
			Tag:            protocol.AgreementVoteTag,
			MessageHandler: HandlerFunc(waitMessageArriveHandler),
		}})

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	netB.OnNetworkAdvance()
	waitForMOIRefreshQuiet(netB)
	// send another message which we can track, so that we'll know that the first message was delivered.
	netB.Broadcast(context.Background(), protocol.AgreementVoteTag, []byte{0, 1, 2, 3, 4}, true, nil)
	messageFilterArriveWg.Wait()

	messageArriveWg.Add(5 * 4) // we're expecting exactly 20 messages.
	// send 5 messages of few types.
	for i := 0; i < 5; i++ {
		netA.Broadcast(context.Background(), protocol.AgreementVoteTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.TxnTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.ProposalPayloadTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.VoteBundleTag, []byte{0, 1, 2, 3, 4}, true, nil)
	}
	// wait until all the expected messages arrive.
	messageArriveWg.Wait()
	incomingMsgSync.Lock()
	require.Equal(t, 4, len(msgCounters))
	for _, count := range msgCounters {
		require.Equal(t, 5, count)
	}
	incomingMsgSync.Unlock()
}
func TestWebsocketNetworkTXMessageOfInterestNPN(t *testing.T) {
	// Tests that A->B follows MOI
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.config.EnablePingHandler = false
	netA.Start()
	defer netStop(t, netA, "A")

	bConfig := defaultConfig
	bConfig.NetAddress = ""
	netB := makeTestWebsocketNodeWithConfig(t, bConfig)
	netB.config.GossipFanout = 1
	netB.config.EnablePingHandler = false
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")
	require.False(t, netB.relayMessages)
	require.Equal(t, uint32(wantTXGossipUnk), netB.wantTXGossip.Load())

	incomingMsgSync := deadlock.Mutex{}
	msgCounters := make(map[protocol.Tag]int)
	messageArriveWg := sync.WaitGroup{}
	msgHandler := func(msg IncomingMessage) (out OutgoingMessage) {
		t.Logf("A->B %s", msg.Tag)
		incomingMsgSync.Lock()
		defer incomingMsgSync.Unlock()
		msgCounters[msg.Tag] = msgCounters[msg.Tag] + 1
		messageArriveWg.Done()
		return
	}
	messageFilterArriveWg := sync.WaitGroup{}
	messageFilterArriveWg.Add(1)
	waitMessageArriveHandler := func(msg IncomingMessage) (out OutgoingMessage) {
		messageFilterArriveWg.Done()
		return
	}

	// register all the handlers.
	taggedHandlers := []TaggedMessageHandler{}
	for tag := range defaultSendMessageTags {
		taggedHandlers = append(taggedHandlers, TaggedMessageHandler{
			Tag:            tag,
			MessageHandler: HandlerFunc(msgHandler),
		})
	}
	netB.RegisterHandlers(taggedHandlers)
	netA.RegisterHandlers([]TaggedMessageHandler{
		{
			Tag:            protocol.AgreementVoteTag,
			MessageHandler: HandlerFunc(waitMessageArriveHandler),
		}})

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	netB.OnNetworkAdvance()
	waitForMOIRefreshQuiet(netB)
	for i := 0; i < 100; i++ {
		if netB.wantTXGossip.Load() == uint32(wantTXGossipNo) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.Equal(t, uint32(wantTXGossipNo), netB.wantTXGossip.Load())
	// send another message which we can track, so that we'll know that the first message was delivered.
	netB.Broadcast(context.Background(), protocol.AgreementVoteTag, []byte{0, 1, 2, 3, 4}, true, nil)
	messageFilterArriveWg.Wait()
	waitPeerInternalChanQuiet(t, netA)

	messageArriveWg.Add(5 * 3) // we're expecting exactly 15 messages.
	// send 5 messages of few types.
	for i := 0; i < 5; i++ {
		netA.Broadcast(context.Background(), protocol.AgreementVoteTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.TxnTag, []byte{0, 1, 2, 3, 4}, true, nil) // THESE WILL BE DROPPED
		netA.Broadcast(context.Background(), protocol.ProposalPayloadTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.VoteBundleTag, []byte{0, 1, 2, 3, 4}, true, nil)
	}
	// wait until all the expected messages arrive.
	messageArriveWg.Wait()
	incomingMsgSync.Lock()
	require.Equal(t, 3, len(msgCounters), msgCounters)
	for tag, count := range msgCounters {
		if tag == protocol.TxnTag {
			require.Equal(t, 0, count)
		} else {
			require.Equal(t, 5, count)
		}
	}
	incomingMsgSync.Unlock()
}

type participatingNodeInfo struct {
	nopeNodeInfo
}

func (nnni *participatingNodeInfo) IsParticipating() bool {
	return true
}

func TestWebsocketNetworkTXMessageOfInterestPN(t *testing.T) {
	// Tests that A->B follows MOI
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.config.EnablePingHandler = false
	netA.Start()
	defer netStop(t, netA, "A")

	bConfig := defaultConfig
	bConfig.NetAddress = ""
	netB := makeTestWebsocketNodeWithConfig(t, bConfig)
	netB.nodeInfo = &participatingNodeInfo{}
	netB.config.GossipFanout = 1
	netB.config.EnablePingHandler = false
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")
	require.False(t, netB.relayMessages)
	require.Equal(t, uint32(wantTXGossipUnk), netB.wantTXGossip.Load())

	incomingMsgSync := deadlock.Mutex{}
	msgCounters := make(map[protocol.Tag]int)
	messageArriveWg := sync.WaitGroup{}
	msgHandler := func(msg IncomingMessage) (out OutgoingMessage) {
		t.Logf("A->B %s", msg.Tag)
		incomingMsgSync.Lock()
		defer incomingMsgSync.Unlock()
		msgCounters[msg.Tag] = msgCounters[msg.Tag] + 1
		messageArriveWg.Done()
		return
	}
	messageFilterArriveWg := sync.WaitGroup{}
	messageFilterArriveWg.Add(1)
	waitMessageArriveHandler := func(msg IncomingMessage) (out OutgoingMessage) {
		messageFilterArriveWg.Done()
		return
	}

	// register all the handlers.
	taggedHandlers := []TaggedMessageHandler{}
	for tag := range defaultSendMessageTags {
		taggedHandlers = append(taggedHandlers, TaggedMessageHandler{
			Tag:            tag,
			MessageHandler: HandlerFunc(msgHandler),
		})
	}
	netB.RegisterHandlers(taggedHandlers)
	netA.RegisterHandlers([]TaggedMessageHandler{
		{
			Tag:            protocol.AgreementVoteTag,
			MessageHandler: HandlerFunc(waitMessageArriveHandler),
		}})

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	netB.OnNetworkAdvance()
	waitForMOIRefreshQuiet(netB)
	for i := 0; i < 100; i++ {
		if netB.wantTXGossip.Load() == uint32(wantTXGossipYes) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.Equal(t, uint32(wantTXGossipYes), netB.wantTXGossip.Load())
	// send another message which we can track, so that we'll know that the first message was delivered.
	netB.Broadcast(context.Background(), protocol.AgreementVoteTag, []byte{0, 1, 2, 3, 4}, true, nil)
	messageFilterArriveWg.Wait()

	messageArriveWg.Add(5 * 4) // we're expecting exactly 20 messages.
	// send 5 messages of few types.
	for i := 0; i < 5; i++ {
		netA.Broadcast(context.Background(), protocol.AgreementVoteTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.TxnTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.ProposalPayloadTag, []byte{0, 1, 2, 3, 4}, true, nil)
		netA.Broadcast(context.Background(), protocol.VoteBundleTag, []byte{0, 1, 2, 3, 4}, true, nil)
	}
	// wait until all the expected messages arrive.
	messageArriveWg.Wait()
	incomingMsgSync.Lock()
	require.Equal(t, 4, len(msgCounters))
	for tag, count := range msgCounters {
		if tag == protocol.TxnTag {
			require.Equal(t, 5, count)
		} else {
			require.Equal(t, 5, count)
		}
	}
	incomingMsgSync.Unlock()
}

// Set up two nodes, have one of them disconnect from the other, and monitor disconnection error on the side that did not issue the disconnection.
// Plan:
// Network A will be sending messages to network B.
// Network B will respond with another message for the first 4 messages. When it receive the 5th message, it would close the connection.
func TestWebsocketDisconnection(t *testing.T) {
	partitiontest.PartitionTest(t)

	// We want to get an event with disconnectRequestReceived from netA
	testWebsocketDisconnection(t, func(wn *WebsocketNetwork, _ *OutgoingMessage) {
		wn.DisconnectPeers()
	}, nil)

	// We want to get an event with the default reason from netB
	defaultReason := disconnectBadData
	testWebsocketDisconnection(t, func(_ *WebsocketNetwork, out *OutgoingMessage) {
		out.Action = Disconnect
	}, &defaultReason)

	// We want to get an event with the provided reason from netB
	customReason := disconnectReason("MyCustomDisconnectReason")
	testWebsocketDisconnection(t, func(_ *WebsocketNetwork, out *OutgoingMessage) {
		out.Action = Disconnect
		out.reason = customReason
	}, &customReason)
}

func testWebsocketDisconnection(t *testing.T, disconnectFunc func(wn *WebsocketNetwork, out *OutgoingMessage), expectedNetBReason *disconnectReason) {
	netA := makeTestWebsocketNode(t)
	netA.config.GossipFanout = 1
	netA.config.EnablePingHandler = false
	dlNetA := eventsDetailsLogger{Logger: logging.TestingLog(t), eventReceived: make(chan interface{}, 1), eventIdentifier: telemetryspec.DisconnectPeerEvent}
	netA.log = dlNetA

	netA.Start()
	defer netStop(t, netA, "A")
	netB := makeTestWebsocketNode(t)
	netB.config.GossipFanout = 1
	netB.config.EnablePingHandler = false
	dlNetB := eventsDetailsLogger{Logger: logging.TestingLog(t), eventReceived: make(chan interface{}, 1), eventIdentifier: telemetryspec.DisconnectPeerEvent}
	netB.log = dlNetB

	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer netStop(t, netB, "B")

	msgHandlerA := func(msg IncomingMessage) (out OutgoingMessage) {
		// if we received a message, send a message back.
		if msg.Data[0]%10 == 2 {
			netA.Broadcast(context.Background(), protocol.ProposalPayloadTag, []byte{msg.Data[0] + 8}, true, nil)
		}
		return
	}

	var msgCounterNetB atomic.Uint32
	msgHandlerB := func(msg IncomingMessage) (out OutgoingMessage) {
		if msgCounterNetB.Add(1) == 5 {
			// disconnect
			disconnectFunc(netB, &out)
		} else {
			// if we received a message, send a message back.
			netB.Broadcast(context.Background(), protocol.ProposalPayloadTag, []byte{msg.Data[0] + 1}, true, nil)
			netB.Broadcast(context.Background(), protocol.ProposalPayloadTag, []byte{msg.Data[0] + 2}, true, nil)
		}
		return
	}

	// register all the handlers.
	taggedHandlersA := []TaggedMessageHandler{
		{
			Tag:            protocol.ProposalPayloadTag,
			MessageHandler: HandlerFunc(msgHandlerA),
		},
	}
	netA.ClearHandlers()
	netA.RegisterHandlers(taggedHandlersA)

	taggedHandlersB := []TaggedMessageHandler{
		{
			Tag:            protocol.ProposalPayloadTag,
			MessageHandler: HandlerFunc(msgHandlerB),
		},
	}
	netB.ClearHandlers()
	netB.RegisterHandlers(taggedHandlersB)

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)
	netA.Broadcast(context.Background(), protocol.ProposalPayloadTag, []byte{0}, true, nil)
	// wait until the peers disconnect.
	for {
		peers := netA.GetPeers(PeersConnectedIn)
		if len(peers) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	select {
	case eventDetails := <-dlNetA.eventReceived:
		switch disconnectPeerEventDetails := eventDetails.(type) {
		case telemetryspec.DisconnectPeerEventDetails:
			require.Equal(t, string(disconnectRequestReceived), disconnectPeerEventDetails.Reason)
		default:
			require.FailNow(t, "Unexpected event was send : %v", eventDetails)
		}

	default:
		require.FailNow(t, "The NetA DisconnectPeerEvent was missing")
	}

	if expectedNetBReason != nil {
		select {
		case eventDetails := <-dlNetB.eventReceived:
			switch disconnectPeerEventDetails := eventDetails.(type) {
			case telemetryspec.DisconnectPeerEventDetails:
				require.Equal(t, string(*expectedNetBReason), disconnectPeerEventDetails.Reason)
			default:
				require.FailNow(t, "Unexpected event was send : %v", eventDetails)
			}

		default:
			require.FailNow(t, "The NetB DisconnectPeerEvent was missing")
		}
	}
}

// TestASCIIFiltering tests the behaviour of filterASCII by feeding it with few known inputs and verifying the expected outputs.
func TestASCIIFiltering(t *testing.T) {
	partitiontest.PartitionTest(t)

	testUnicodePrintableStrings := []struct {
		testString     string
		expectedString string
	}{
		{"abc", "abc"},
		{"", ""},
		{"אבג", unprintableCharacterGlyph + unprintableCharacterGlyph + unprintableCharacterGlyph},
		{"\u001b[31mABC\u001b[0m", unprintableCharacterGlyph + "[31mABC" + unprintableCharacterGlyph + "[0m"},
		{"ab\nc", "ab" + unprintableCharacterGlyph + "c"},
	}
	for _, testElement := range testUnicodePrintableStrings {
		outString := filterASCII(testElement.testString)
		require.Equalf(t, testElement.expectedString, outString, "test string:%s", testElement.testString)
	}
}

type callbackLogger struct {
	logging.Logger
	InfoCallback  func(...interface{})
	InfofCallback func(string, ...interface{})
	WarnCallback  func(...interface{})
	WarnfCallback func(string, ...interface{})
}

func (cl callbackLogger) Info(args ...interface{}) {
	cl.InfoCallback(args...)
}
func (cl callbackLogger) Infof(s string, args ...interface{}) {
	cl.InfofCallback(s, args...)
}

func (cl callbackLogger) Warn(args ...interface{}) {
	cl.WarnCallback(args...)
}
func (cl callbackLogger) Warnf(s string, args ...interface{}) {
	cl.WarnfCallback(s, args...)
}

// TestMaliciousCheckServerResponseVariables test the checkServerResponseVariables to ensure it doesn't print the a malicious input without being filtered to the log file.
func TestMaliciousCheckServerResponseVariables(t *testing.T) {
	partitiontest.PartitionTest(t)

	wn := makeTestWebsocketNode(t)
	wn.genesisInfo.GenesisID = "genesis-id1"
	wn.randomID = "random-id1"
	wn.log = callbackLogger{
		Logger: wn.log,
		InfoCallback: func(args ...interface{}) {
			s := fmt.Sprint(args...)
			require.NotContains(t, s, "א")
		},
		InfofCallback: func(s string, args ...interface{}) {
			s = fmt.Sprintf(s, args...)
			require.NotContains(t, s, "א")
		},
		WarnCallback: func(args ...interface{}) {
			s := fmt.Sprint(args...)
			require.NotContains(t, s, "א")
		},
		WarnfCallback: func(s string, args ...interface{}) {
			s = fmt.Sprintf(s, args...)
			require.NotContains(t, s, "א")
		},
	}

	header1 := http.Header{}
	header1.Set(ProtocolVersionHeader, ProtocolVersion+"א")
	header1.Set(NodeRandomHeader, wn.randomID+"tag")
	header1.Set(GenesisHeader, wn.genesisInfo.GenesisID)
	responseVariableOk, matchingVersion := wn.checkServerResponseVariables(header1, "addressX")
	require.Equal(t, false, responseVariableOk)
	require.Equal(t, "", matchingVersion)

	header2 := http.Header{}
	header2.Set(ProtocolVersionHeader, ProtocolVersion)
	header2.Set("א", "א")
	header2.Set(GenesisHeader, wn.genesisInfo.GenesisID)
	responseVariableOk, matchingVersion = wn.checkServerResponseVariables(header2, "addressX")
	require.Equal(t, false, responseVariableOk)
	require.Equal(t, "", matchingVersion)

	header3 := http.Header{}
	header3.Set(ProtocolVersionHeader, ProtocolVersion)
	header3.Set(NodeRandomHeader, wn.randomID+"tag")
	header3.Set(GenesisHeader, wn.genesisInfo.GenesisID+"א")
	responseVariableOk, matchingVersion = wn.checkServerResponseVariables(header3, "addressX")
	require.Equal(t, false, responseVariableOk)
	require.Equal(t, "", matchingVersion)
}

func BenchmarkVariableTransactionMessageBlockSizes(t *testing.B) {
	netA := makeTestWebsocketNode(t)
	netA.log.SetLevel(logging.Warn)
	netA.config.GossipFanout = 1
	netA.config.EnablePingHandler = false
	netA.Start()
	defer func() { netA.Stop() }()

	netB := makeTestWebsocketNode(t)
	netB.log.SetLevel(logging.Warn)
	netB.config.GossipFanout = 1
	netB.config.EnablePingHandler = false
	addrA, postListen := netA.Address()
	require.True(t, postListen)
	t.Log(addrA)
	netB.phonebook.ReplacePeerList([]string{addrA}, "default", phonebook.RelayRole)
	netB.Start()
	defer func() { netB.Stop() }()

	const txnSize = 250
	var msgProcessed chan struct{}

	msgHandlerA := func(msg IncomingMessage) (out OutgoingMessage) {
		// spend some time, linear to the size of the message -
		txnCount := len(msg.Data) / txnSize
		time.Sleep(time.Nanosecond * time.Duration(10000*txnCount))
		msgProcessed <- struct{}{}
		return
	}
	// register all the handlers.
	taggedHandlersA := []TaggedMessageHandler{
		{
			Tag:            protocol.TxnTag,
			MessageHandler: HandlerFunc(msgHandlerA),
		},
	}
	netA.ClearHandlers()
	netA.RegisterHandlers(taggedHandlersA)

	netB.ClearHandlers()

	readyTimeout := time.NewTimer(2 * time.Second)
	waitReady(t, netA, readyTimeout.C)
	waitReady(t, netB, readyTimeout.C)

	highestRate := float64(1)
	sinceHighestRate := 0
	rate := float64(0)
	for txnCount := 1; txnCount < 1024; {
		t.Run(fmt.Sprintf("%d-TxnPerMessage", txnCount), func(t *testing.B) {
			msgProcessed = make(chan struct{}, t.N/txnCount)
			dataBuffer := make([]byte, txnSize*txnCount)
			crypto.RandBytes(dataBuffer[:])
			t.ResetTimer()
			startTime := time.Now()
			for i := 0; i < t.N/txnCount; i++ {
				netB.Broadcast(context.Background(), protocol.TxnTag, dataBuffer, true, nil)
				<-msgProcessed
			}
			deltaTime := time.Since(startTime)
			rate = float64(t.N) * float64(time.Second) / float64(deltaTime)
			t.ReportMetric(rate, "txn/sec")
		})
		if rate > highestRate {
			highestRate = rate
			sinceHighestRate = 0
			txnCount += txnCount/10 + 1
			continue
		}
		sinceHighestRate++
		if sinceHighestRate > 4 {
			break
		}
		txnCount += txnCount/4 + 1
	}
}

func TestPreparePeerData(t *testing.T) {
	partitiontest.PartitionTest(t)

	vote := map[string]any{
		"cred": map[string]any{"pf": crypto.VrfProof{}},
		"r":    map[string]any{"rnd": uint64(1), "snd": [32]byte{}},
		"sig": map[string]any{
			"p": [32]byte{}, "p1s": [64]byte{}, "p2": [32]byte{},
			"p2s": [64]byte{}, "ps": [64]byte{}, "s": [64]byte{},
		},
	}
	reqs := []broadcastRequest{
		{tag: protocol.AgreementVoteTag, data: protocol.EncodeReflect(vote)},
		{tag: protocol.ProposalPayloadTag, data: []byte("data")},
		{tag: protocol.TxnTag, data: []byte("txn")},
		{tag: protocol.StateProofSigTag, data: []byte("stateproof")},
	}

	wn := WebsocketNetwork{}
	wn.broadcaster.log = logging.TestingLog(t)
	// Enable vote compression for the test
	wn.broadcaster.enableVoteCompression = true
	data := make([][]byte, len(reqs))
	compressedData := make([][]byte, len(reqs))
	digests := make([]crypto.Digest, len(reqs))

	// Test without compression (prio = false)
	for i, req := range reqs {
		data[i], compressedData[i], digests[i] = wn.broadcaster.preparePeerData(req, false)
		require.NotEmpty(t, data[i])
		require.Empty(t, digests[i]) // small messages have no digest
	}

	for i := range data {
		require.Equal(t, append([]byte(reqs[i].tag), reqs[i].data...), data[i])
		require.Empty(t, compressedData[i]) // No compression when prio = false
	}

	// Test with compression (prio = true)
	for i, req := range reqs {
		data[i], compressedData[i], digests[i] = wn.broadcaster.preparePeerData(req, true)
		require.NotEmpty(t, data[i])
		require.Empty(t, digests[i]) // small messages have no digest
	}

	for i := range data {
		if reqs[i].tag == protocol.AgreementVoteTag {
			// For votes with prio=true, the main data remains uncompressed, but compressedData is filled
			require.Equal(t, append([]byte(reqs[i].tag), reqs[i].data...), data[i])
			require.NotEmpty(t, compressedData[i], "Vote messages should have compressed data when prio=true")
		} else if reqs[i].tag == protocol.ProposalPayloadTag {
			// For proposals with prio=true, the main data is compressed with zstd
			require.Equal(t, append([]byte(reqs[i].tag), zstdCompressionMagic[:]...), data[i][:len(reqs[i].tag)+len(zstdCompressionMagic)])
			require.Empty(t, compressedData[i], "Proposal messages should not have separate compressed data")
		} else {
			require.Equal(t, append([]byte(reqs[i].tag), reqs[i].data...), data[i])
			require.Empty(t, compressedData[i])
		}
	}
}

func TestWebsocketNetworkTelemetryTCP(t *testing.T) {
	partitiontest.PartitionTest(t)

	if strings.ToUpper(os.Getenv("CIRCLECI")) == "TRUE" {
		t.Skip("Flaky on CIRCLECI")
	}

	// start two networks and send 2 messages from A to B
	closed := false
	netA, netB, counter, closeFunc := setupWebsocketNetworkAB(t, 2)
	defer func() {
		if !closed {
			closeFunc()
		}
	}()
	counterDone := counter.done
	netA.Broadcast(context.Background(), protocol.TxnTag, []byte("foo"), false, nil)
	netA.Broadcast(context.Background(), protocol.TxnTag, []byte("bar"), false, nil)

	select {
	case <-counterDone:
	case <-time.After(2 * time.Second):
		t.Errorf("timeout, count=%d, wanted 2", counter.count)
	}

	// get RTT from both ends and assert nonzero
	var peersA, peersB []*wsPeer
	peersA, _ = netA.peerSnapshot(peersA)
	detailsA := getPeerConnectionTelemetryDetails(time.Now(), peersA)
	peersB, _ = netB.peerSnapshot(peersB)
	detailsB := getPeerConnectionTelemetryDetails(time.Now(), peersB)
	require.Len(t, detailsA.IncomingPeers, 1)
	assert.NotZero(t, detailsA.IncomingPeers[0].TCP.RTT)
	require.Len(t, detailsB.OutgoingPeers, 1)
	assert.NotZero(t, detailsB.OutgoingPeers[0].TCP.RTT)

	pcdA, err := json.Marshal(detailsA)
	assert.NoError(t, err)
	pcdB, err := json.Marshal(detailsB)
	assert.NoError(t, err)
	t.Log("detailsA", string(pcdA))
	t.Log("detailsB", string(pcdB))

	// close connections
	closeFunc()
	closed = true
	// open more FDs by starting 2 more networks
	_, _, _, closeFunc2 := setupWebsocketNetworkAB(t, 2)
	defer closeFunc2()
	//  use stale peers snapshot from closed networks to get telemetry
	// *net.OpError "use of closed network connection" err results in 0 rtt values
	detailsA = getPeerConnectionTelemetryDetails(time.Now(), peersA)
	detailsB = getPeerConnectionTelemetryDetails(time.Now(), peersB)
	require.Len(t, detailsA.IncomingPeers, 1)
	assert.Zero(t, detailsA.IncomingPeers[0].TCP.RTT)
	require.Len(t, detailsB.OutgoingPeers, 1)
	assert.Zero(t, detailsB.OutgoingPeers[0].TCP.RTT)

	pcdA, err = json.Marshal(detailsA)
	assert.NoError(t, err)
	pcdB, err = json.Marshal(detailsB)
	assert.NoError(t, err)
	t.Log("closed detailsA", string(pcdA))
	t.Log("closed detailsB", string(pcdB))
}

type mockServer struct {
	*httptest.Server
	URL string

	waitForClientClose bool
}

type mockHandler struct {
	*testing.T
	s *mockServer
}

var mockUpgrader = websocket.Upgrader{
	ReadBufferSize:    1024,
	WriteBufferSize:   1024,
	EnableCompression: true,
	Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
		http.Error(w, reason.Error(), status)
	},
}

func buildWsResponseHeader() http.Header {
	h := http.Header{}
	h.Add(ProtocolVersionHeader, ProtocolVersion)
	h.Add(GenesisHeader, genesisID)
	h.Add(NodeRandomHeader, "randomHeader")
	return h
}

func (t mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set the required headers to successfully establish a connection
	ws, err := mockUpgrader.Upgrade(w, r, buildWsResponseHeader())
	if err != nil {
		t.Logf("Upgrade: %v", err)
		return
	}
	defer ws.Close()
	// Send a message of interest immediately after the connection is established
	wr, err := ws.NextWriter(websocket.BinaryMessage)
	if err != nil {
		t.Logf("NextWriter: %v", err)
		return
	}

	bytes := marshallMessageOfInterest([]protocol.Tag{protocol.AgreementVoteTag})
	msgBytes := append([]byte(protocol.MsgOfInterestTag), bytes...)
	_, err = wr.Write(msgBytes)
	if err != nil {
		t.Logf("Error writing MessageOfInterest: %v", err)
		return
	}
	wr.Close()

	for {
		// echo a message back to the client
		_, _, err := ws.NextReader()
		if err != nil {
			if _, ok := err.(*websocket.CloseError); ok && t.s.waitForClientClose {
				t.Log("got client close")
				return
			}
			return
		}
	}
}

func makeWsProto(s string) string {
	return "ws" + strings.TrimPrefix(s, "http")
}

func newServer(t *testing.T) *mockServer {
	var s mockServer
	s.Server = httptest.NewServer(mockHandler{t, &s})
	s.Server.URL += ""
	s.URL = makeWsProto(s.Server.URL)
	return &s
}

func TestMaxHeaderSize(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
	netA.config.GossipFanout = 1

	netB := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netB"})
	netB.config.GossipFanout = 1

	netA.Start()
	defer netA.Stop()
	netB.Start()
	defer netB.Stop()

	addrB, ok := netB.Address()
	require.True(t, ok)
	gossipB, err := netB.addrToGossipAddr(addrB)
	require.NoError(t, err)

	// First make sure that the regular connection with default max header size works
	netA.wsMaxHeaderBytes = wsMaxHeaderBytes
	netA.wg.Add(1)
	netA.tryConnect(addrB, gossipB)
	require.Eventually(t, func() bool { return netA.NumPeers() == 1 }, 500*time.Millisecond, 25*time.Millisecond)

	netA.removePeer(netA.peers[0], disconnectReasonNone)
	assert.Zero(t, len(netA.peers))

	// Now try to connect with a max header size that is too small
	logBuffer := bytes.NewBuffer(nil)
	netA.log.SetOutput(logBuffer)

	netA.wsMaxHeaderBytes = 128
	netA.wg.Add(1)
	netA.tryConnect(addrB, gossipB)
	lg := logBuffer.String()
	logBuffer.Reset()
	time.Sleep(250 * time.Millisecond)
	assert.Contains(t, lg, fmt.Sprintf("ws connect(%s) fail:", gossipB))
	assert.Zero(t, len(netA.peers))

	// Test that setting 0 disables the max header size check
	netA.wsMaxHeaderBytes = 0
	netA.wg.Add(1)
	netA.tryConnect(addrB, gossipB)
	require.Eventually(t, func() bool { return netA.NumPeers() == 1 }, 500*time.Millisecond, 25*time.Millisecond)
}

func TestTryConnectEarlyWrite(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
	netA.config.GossipFanout = 1

	s := newServer(t)
	s.waitForClientClose = true
	defer s.Close()

	netA.Start()
	defer netA.Stop()

	dialer := websocket.Dialer{}
	mconn, resp, _ := dialer.Dial(s.URL, nil)
	expectedHeader := buildWsResponseHeader()
	for k, v := range expectedHeader {
		assert.Equal(t, v[0], resp.Header.Get(k))
	}

	// Fixed overhead of the full status line "HTTP/1.1 101 Switching Protocols" (32) + 4 bytes for two instance of CRLF
	// one after the status line and one to separate headers from the body
	minValidHeaderSize := 36
	for k, v := range resp.Header {
		minValidHeaderSize += len(k) + len(v[0]) + 4 // + 4 is for the ": " and CRLF
	}
	mconn.Close()

	// Setting the max header size to 1 byte less than the minimum header size should fail
	netA.wsMaxHeaderBytes = int64(minValidHeaderSize) - 1
	netA.wg.Add(1)
	netA.tryConnect(s.URL, s.URL)
	time.Sleep(250 * time.Millisecond)
	assert.Len(t, netA.peers, 0)

	// Now set the max header size to the minimum header size and it should succeed
	netA.wsMaxHeaderBytes = int64(minValidHeaderSize)
	netA.wg.Add(1)
	netA.tryConnect(s.URL, s.URL)
	p := netA.peers[0]
	var messageCount uint64
	for x := 0; x < 1000; x++ {
		messageCount = p.miMessageCount.Load()
		if messageCount == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Confirm that we successfully received a message of interest
	assert.Len(t, netA.peers, 1)
	fmt.Printf("MI Message Count: %v\n", netA.peers[0].miMessageCount.Load())
	assert.Equal(t, uint64(1), netA.peers[0].miMessageCount.Load())
}

// Test functionality that allows a node to discard a block response that it did not request or that arrived too late.
// Both cases are tested here by having A send unexpected, late responses to nodes B and C respectively.
func TestDiscardUnrequestedBlockResponse(t *testing.T) {
	partitiontest.PartitionTest(t)

	netA := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netA"})
	netA.config.GossipFanout = 1

	netB := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netB"})
	netB.config.GossipFanout = 1

	netC := makeTestWebsocketNode(t, testWebsocketLogNameOption{"netC"})
	netC.config.GossipFanout = 1

	netA.Start()
	defer netA.Stop()
	netB.Start()
	defer netB.Stop()

	addrB, ok := netB.Address()
	require.True(t, ok)
	gossipB, err := netB.addrToGossipAddr(addrB)
	require.NoError(t, err)

	netA.wg.Add(1)
	netA.tryConnect(addrB, gossipB)
	require.Eventually(t, func() bool { return netA.NumPeers() == 1 }, 500*time.Millisecond, 25*time.Millisecond)

	// send an unrequested block response
	msg := sendMessage{
		data:         append([]byte(protocol.TopicMsgRespTag), []byte("foo")...),
		enqueued:     time.Now(),
		peerEnqueued: time.Now(),
		ctx:          context.Background(),
	}
	netA.peers[0].sendBufferBulk <- msg
	require.Eventually(t,
		func() bool {
			return networkConnectionsDroppedTotal.GetUint64ValueForLabels(map[string]string{"reason": "unrequestedTS"}) == 1
		},
		1*time.Second,
		50*time.Millisecond,
	)

	// Stop and confirm that we hit the case of disconnecting a peer for sending an unrequested block response
	require.Zero(t, netB.NumPeers())

	netC.Start()
	defer netC.Stop()

	addrC, ok := netC.Address()
	require.True(t, ok)
	gossipC, err := netC.addrToGossipAddr(addrC)
	require.NoError(t, err)

	netA.wg.Add(1)
	netA.tryConnect(addrC, gossipC)
	require.Eventually(t, func() bool { return netA.NumPeers() == 1 }, 500*time.Millisecond, 25*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	topics := Topics{
		MakeTopic("requestDataType",
			[]byte("a")),
		MakeTopic(
			"blockData",
			[]byte("b")),
	}
	// Send a request for a block and cancel it after the handler has been registered
	go func() {
		netC.peers[0].Request(ctx, protocol.UniEnsBlockReqTag, topics)
	}()
	require.Eventually(
		t,
		func() bool {
			netC.peersLock.RLock()
			defer netC.peersLock.RUnlock()
			require.NotEmpty(t, netC.peers)
			return netC.peers[0].lenResponseChannels() > 0
		},
		1*time.Second,
		50*time.Millisecond,
	)
	cancel()

	// confirm that the request was cancelled but that we have registered that we have sent a request
	require.Eventually(
		t,
		func() bool { return netC.peers[0].lenResponseChannels() == 0 },
		500*time.Millisecond,
		20*time.Millisecond,
	)
	require.Equal(t, netC.peers[0].outstandingTopicRequests.Load(), int64(1))

	// Create a buffer to monitor log output from netC
	logBuffer := bytes.NewBuffer(nil)
	netC.log.SetOutput(logBuffer)

	// send a late TS response from A -> C
	netA.peers[0].sendBufferBulk <- msg
	require.Eventually(
		t,
		func() bool { return netC.peers[0].outstandingTopicRequests.Load() == int64(0) },
		500*time.Millisecond,
		20*time.Millisecond,
	)

	// Stop and confirm that we hit the case of disconnecting a peer for sending a stale block response
	netC.Stop()
	lg := logBuffer.String()
	require.Contains(t, lg, "wsPeer readLoop: received a TS response for a stale request ")
}

func customNetworkIDGen(networkID protocol.NetworkID) *rapid.Generator[protocol.NetworkID] {
	return rapid.Custom(func(t *rapid.T) protocol.NetworkID {
		// Unused/satisfying rapid requirement
		rapid.String().Draw(t, "networkIDGen")
		return networkID
	})
}

// The hardcoded network IDs just make testing this function more difficult with no confidence gain (the custom logic
// is already exercised well in the dnsbootstrap parsing tests).
func nonHardcodedNetworkIDGen() *rapid.Generator[protocol.NetworkID] {
	return rapid.OneOf(customNetworkIDGen(config.Testnet), customNetworkIDGen(config.Mainnet),
		customNetworkIDGen(config.Devtestnet))
}

/*
Basic exercise of the refreshRelayArchivePhonebookAddresses function, uses base / expected cases, relying  on neighboring
unit tests to cover the merge and phonebook update logic.
*/
func TestRefreshRelayArchivePhonebookAddresses(t *testing.T) {
	partitiontest.PartitionTest(t)
	var netA *WebsocketNetwork
	var refreshRelayDNSBootstrapID = "<network>.algorand.network?backup=<network>.algorand.net&dedup=<name>.algorand-<network>.(network|net)"

	refreshTestConf := defaultConfig

	rapid.Check(t, func(t1 *rapid.T) {
		refreshTestConf.DNSBootstrapID = refreshRelayDNSBootstrapID
		netA = makeTestWebsocketNodeWithConfig(t, refreshTestConf)
		netA.genesisInfo.NetworkID = nonHardcodedNetworkIDGen().Draw(t1, "network")

		primarySRVBootstrap := strings.Replace("<network>.algorand.network", "<network>", string(netA.genesisInfo.NetworkID), -1)
		backupSRVBootstrap := strings.Replace("<network>.algorand.net", "<network>", string(netA.genesisInfo.NetworkID), -1)
		var primaryRelayResolvedRecords []string
		var secondaryRelayResolvedRecords []string
		var primaryArchiveResolvedRecords []string
		var secondaryArchiveResolvedRecords []string

		for _, record := range []string{"r1.algorand-<network>.network",
			"r2.algorand-<network>.network", "r3.algorand-<network>.network"} {
			var recordSub = strings.Replace(record, "<network>", string(netA.genesisInfo.NetworkID), -1)
			primaryRelayResolvedRecords = append(primaryRelayResolvedRecords, recordSub)
			secondaryRelayResolvedRecords = append(secondaryRelayResolvedRecords, strings.Replace(recordSub, "network", "net", -1))
		}

		for _, record := range []string{"r1archive.algorand-<network>.network",
			"r2archive.algorand-<network>.network", "r3archive.algorand-<network>.network"} {
			var recordSub = strings.Replace(record, "<network>", string(netA.genesisInfo.NetworkID), -1)
			primaryArchiveResolvedRecords = append(primaryArchiveResolvedRecords, recordSub)
			secondaryArchiveResolvedRecords = append(secondaryArchiveResolvedRecords, strings.Replace(recordSub, "network", "net", -1))
		}

		// Mock the SRV record lookup
		netA.resolveSRVRecords = func(ctx context.Context, service string, protocol string, name string, fallbackDNSResolverAddress string,
			secure bool) (addrs []string, err error) {
			if service == "algobootstrap" && protocol == "tcp" && name == primarySRVBootstrap {
				return primaryRelayResolvedRecords, nil
			} else if service == "algobootstrap" && protocol == "tcp" && name == backupSRVBootstrap {
				return secondaryRelayResolvedRecords, nil
			}

			if service == "archive" && protocol == "tcp" && name == primarySRVBootstrap {
				return primaryArchiveResolvedRecords, nil
			} else if service == "archive" && protocol == "tcp" && name == backupSRVBootstrap {
				return secondaryArchiveResolvedRecords, nil
			}

			return
		}

		relayPeers := netA.GetPeers(PeersPhonebookRelays)
		assert.Equal(t, 0, len(relayPeers))

		archivePeers := netA.GetPeers(PeersPhonebookArchivalNodes)
		assert.Equal(t, 0, len(archivePeers))

		netA.refreshRelayArchivePhonebookAddresses()

		relayPeers = netA.GetPeers(PeersPhonebookRelays)

		assert.Equal(t, 3, len(relayPeers))
		relayAddrs := make([]string, 0, len(relayPeers))
		for _, peer := range relayPeers {
			relayAddrs = append(relayAddrs, peer.(HTTPPeer).GetAddress())
		}

		assert.ElementsMatch(t, primaryRelayResolvedRecords, relayAddrs)

		archivePeers = netA.GetPeers(PeersPhonebookArchivalNodes)

		assert.Equal(t, 3, len(archivePeers))

		archiveAddrs := make([]string, 0, len(archivePeers))
		for _, peer := range archivePeers {
			archiveAddrs = append(archiveAddrs, peer.(HTTPPeer).GetAddress())
		}

		assert.ElementsMatch(t, primaryArchiveResolvedRecords, archiveAddrs)

	})
}

/*
Exercises the updatePhonebookAddresses function, notably with different variations of valid relay and
archival addresses.
*/
func TestUpdatePhonebookAddresses(t *testing.T) {
	partitiontest.PartitionTest(t)
	var netA *WebsocketNetwork

	rapid.Check(t, func(t1 *rapid.T) {
		netA = makeTestWebsocketNode(t)
		relayPeers := netA.GetPeers(PeersPhonebookRelays)
		assert.Equal(t, 0, len(relayPeers))

		archivePeers := netA.GetPeers(PeersPhonebookArchivalNodes)
		assert.Equal(t, 0, len(archivePeers))

		domainGen := rapidgen.Domain()

		// Generate between 0 and N examples - if no dups, should end up in phonebook
		relayDomainsGen := rapid.SliceOfN(domainGen, 0, 200)

		relayDomains := relayDomainsGen.Draw(t1, "relayDomains")

		// Dont overlap with relays, duplicates between them not stored in phonebook as of this writing
		archiveDomainsGen := rapid.SliceOfN(rapidgen.DomainOf(253, 63, "", relayDomains), 0, 200)
		archiveDomains := archiveDomainsGen.Draw(t1, "archiveDomains")
		netA.updatePhonebookAddresses(relayDomains, archiveDomains)

		// Check that entries are in fact in phonebook less any duplicates
		dedupedRelayDomains := removeDuplicateStr(relayDomains, false)
		dedupedArchiveDomains := removeDuplicateStr(archiveDomains, false)

		relayPeers = netA.GetPeers(PeersPhonebookRelays)
		assert.Equal(t, len(dedupedRelayDomains), len(relayPeers))

		relayAddrs := make([]string, 0, len(relayPeers))
		for _, peer := range relayPeers {
			relayAddrs = append(relayAddrs, peer.(HTTPPeer).GetAddress())
		}

		assert.ElementsMatch(t, dedupedRelayDomains, relayAddrs)

		archivePeers = netA.GetPeers(PeersPhonebookArchivalNodes)
		assert.Equal(t, len(dedupedArchiveDomains), len(archivePeers))

		archiveAddrs := make([]string, 0, len(archivePeers))
		for _, peer := range archivePeers {
			archiveAddrs = append(archiveAddrs, peer.(HTTPPeer).GetAddress())
		}

		assert.ElementsMatch(t, dedupedArchiveDomains, archiveAddrs)

		// Generate fresh set of addresses with a duplicate from original batch if warranted,
		// assert phonebook reflects fresh list / prior peers other than selected duplicate
		// are not present
		var priorRelayDomains = relayDomains

		// Dont overlap with archive nodes previously specified, duplicates between them not stored in phonebook as of this writing
		relayDomainsGen = rapid.SliceOfN(rapidgen.DomainOf(253, 63, "", archiveDomains), 0, 200)
		relayDomains = relayDomainsGen.Draw(t1, "relayDomains")

		// Randomly select a prior relay domain
		if len(priorRelayDomains) > 0 {
			priorIdx := rapid.IntRange(0, len(priorRelayDomains)-1).Draw(t1, "")
			relayDomains = append(relayDomains, priorRelayDomains[priorIdx])
		}

		netA.updatePhonebookAddresses(relayDomains, nil)

		// Check that entries are in fact in phonebook less any duplicates
		dedupedRelayDomains = removeDuplicateStr(relayDomains, false)

		relayPeers = netA.GetPeers(PeersPhonebookRelays)
		assert.Equal(t, len(dedupedRelayDomains), len(relayPeers))

		relayAddrs = nil
		for _, peer := range relayPeers {
			relayAddrs = append(relayAddrs, peer.(HTTPPeer).GetAddress())
		}

		assert.ElementsMatch(t, dedupedRelayDomains, relayAddrs)

		archivePeers = netA.GetPeers(PeersPhonebookArchivalNodes)
		assert.Equal(t, len(dedupedArchiveDomains), len(archivePeers))

		archiveAddrs = nil
		for _, peer := range archivePeers {
			archiveAddrs = append(archiveAddrs, peer.(HTTPPeer).GetAddress())
		}

		assert.ElementsMatch(t, dedupedArchiveDomains, archiveAddrs)
	})
}

func removeDuplicateStr(strSlice []string, lowerCase bool) []string {
	allKeys := make(map[string]bool)
	var dedupStrSlice = make([]string, 0)
	for _, item := range strSlice {
		if lowerCase {
			item = strings.ToLower(item)
		}
		if _, exists := allKeys[item]; !exists {
			allKeys[item] = true
			dedupStrSlice = append(dedupStrSlice, item)
		}
	}
	return dedupStrSlice
}

func replaceAllIn(strSlice []string, strToReplace string, newStr string) []string {
	var subbedStrSlice = make([]string, 0)
	for _, item := range strSlice {
		item = strings.ReplaceAll(item, strToReplace, newStr)
		subbedStrSlice = append(subbedStrSlice, item)
	}

	return subbedStrSlice
}

func supportedNetworkGen() *rapid.Generator[string] {
	return rapid.OneOf(rapid.StringMatching(string(config.Testnet)), rapid.StringMatching(string(config.Mainnet)),
		rapid.StringMatching(string(config.Devnet)), rapid.StringMatching(string(config.Betanet)),
		rapid.StringMatching(string(config.Alphanet)), rapid.StringMatching(string(config.Devtestnet)))
}

func TestMergePrimarySecondaryRelayAddressListsMinOverlap(t *testing.T) {
	partitiontest.PartitionTest(t)
	var netA *WebsocketNetwork

	rapid.Check(t, func(t1 *rapid.T) {
		netA = makeTestWebsocketNode(t)

		network := supportedNetworkGen().Draw(t1, "network")
		dedupExp := regexp.MustCompile(strings.Replace(
			`(algorand-<network>.(network|net))`, "<network>", network, -1))
		domainPortGen := rapidgen.DomainWithPort()

		// Generate between 0 and N examples - if no dups, should end up in phonebook
		domainsGen := rapid.SliceOfN(domainPortGen, 0, 200)

		primaryRelayAddresses := domainsGen.Draw(t1, "primaryRelayAddresses")
		secondaryRelayAddresses := domainsGen.Draw(t1, "secondaryRelayAddresses")

		mergedRelayAddresses := netA.mergePrimarySecondaryAddressSlices(
			primaryRelayAddresses, secondaryRelayAddresses, dedupExp)

		expectedRelayAddresses := removeDuplicateStr(append(primaryRelayAddresses, secondaryRelayAddresses...), true)

		assert.ElementsMatch(t, expectedRelayAddresses, mergedRelayAddresses)
	})
}

func alphaNumStr(n int) string {
	var chars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321")
	str := make([]rune, n)
	for i := range str {
		str[i] = chars[rand.Intn(len(chars))]
	}
	return string(str)
}

func TestMergePrimarySecondaryRelayAddressListsPartialOverlap(t *testing.T) {
	partitiontest.PartitionTest(t)

	networks := []protocol.NetworkID{config.Testnet, config.Mainnet, config.Devnet, config.Betanet,
		config.Alphanet, config.Devtestnet}
	var netA *WebsocketNetwork

	for _, network := range networks {
		dedupExp := regexp.MustCompile(strings.Replace(
			"(algorand-<network>.(network|net))", "<network>", string(network), -1))
		primaryRelayAddresses := make([]string, 0)
		secondaryRelayAddresses := make([]string, 0)
		extraSecondaryRelayAddresses := make([]string, 0)
		for i := 0; i < 100; i++ {
			relayID := alphaNumStr(2)
			primaryRelayAddresses = append(primaryRelayAddresses, fmt.Sprintf("r-%s.algorand-%s.network",
				relayID, network))
			secondaryRelayAddresses = append(secondaryRelayAddresses, fmt.Sprintf("r-%s.algorand-%s.net",
				relayID, network))
		}
		for i := 0; i < 20; i++ {
			relayID := alphaNumStr(2) + "-" + alphaNumStr(1)
			primaryRelayAddresses = append(primaryRelayAddresses, fmt.Sprintf("relay-%s.algorand-%s.network",
				relayID, network))
			secondaryRelayAddresses = append(secondaryRelayAddresses, fmt.Sprintf("relay-%s.algorand-%s.net",
				relayID, network))
		}
		// Add additional secondary ones that intentionally do not duplicate primary ones
		for i := 0; i < 10; i++ {
			relayID := alphaNumStr(2) + "-" + alphaNumStr(1)
			extraSecondaryRelayAddresses = append(extraSecondaryRelayAddresses, fmt.Sprintf("noduprelay-%s.algorand-%s.net",
				relayID, network))
		}
		secondaryRelayAddresses = append(secondaryRelayAddresses, extraSecondaryRelayAddresses...)

		mergedRelayAddresses := netA.mergePrimarySecondaryAddressSlices(
			primaryRelayAddresses, secondaryRelayAddresses, dedupExp)

		// We expect the primary addresses to take precedence over a "matching" secondary address, extra non-duplicate
		// secondary addresses should be present in the merged slice
		expectedRelayAddresses := removeDuplicateStr(append(primaryRelayAddresses, extraSecondaryRelayAddresses...), true)

		assert.ElementsMatch(t, expectedRelayAddresses, mergedRelayAddresses)
	}

}

// Case where a "backup" network is specified, but no dedup expression is provided. Technically possible,
// but there is little benefit vs specifying them as separate `;` separated addresses in DNSBootrstrapID.
func TestMergePrimarySecondaryRelayAddressListsNoDedupExp(t *testing.T) {
	partitiontest.PartitionTest(t)
	var netA *WebsocketNetwork

	rapid.Check(t, func(t1 *rapid.T) {
		netA = makeTestWebsocketNode(t)

		network := supportedNetworkGen().Draw(t1, "network")
		primaryDomainSuffix := strings.Replace(
			`algorand-<network>.net`, "<network>", network, -1)

		// Generate hosts for a primary network domain
		primaryNetworkDomainGen := rapidgen.DomainWithSuffixAndPort(primaryDomainSuffix, nil)
		primaryDomainsGen := rapid.SliceOfN(primaryNetworkDomainGen, 0, 200)

		primaryRelayAddresses := primaryDomainsGen.Draw(t1, "primaryRelayAddresses")

		secondaryDomainSuffix := strings.Replace(
			`algorand-<network>.network`, "<network>", network, -1)
		// Generate these addresses from primary ones, find/replace domain suffix appropriately
		secondaryRelayAddresses := replaceAllIn(primaryRelayAddresses, primaryDomainSuffix, secondaryDomainSuffix)
		// Add some generated addresses to secondary list - to simplify verification further down
		// (substituting suffixes, etc), we don't want the generated addresses to duplicate any of
		// the replaced secondary ones
		secondaryNetworkDomainGen := rapidgen.DomainWithSuffixAndPort(secondaryDomainSuffix, secondaryRelayAddresses)
		secondaryDomainsGen := rapid.SliceOfN(secondaryNetworkDomainGen, 0, 200)
		generatedSecondaryRelayAddresses := secondaryDomainsGen.Draw(t1, "secondaryRelayAddresses")
		secondaryRelayAddresses = append(secondaryRelayAddresses, generatedSecondaryRelayAddresses...)

		mergedRelayAddresses := netA.mergePrimarySecondaryAddressSlices(
			primaryRelayAddresses, secondaryRelayAddresses, nil)

		// We expect non deduplication, so all addresses _should_ be present (note that no lower casing happens either)
		expectedRelayAddresses := append(primaryRelayAddresses, secondaryRelayAddresses...)

		assert.ElementsMatch(t, expectedRelayAddresses, mergedRelayAddresses)
	})
}

// TestSendMessageCallbacks tests that the SendMessage callbacks are called correctly. These are currently used for
// decrementing the number of bytes considered currently in flight for blockservice memcaps.
func TestSendMessageCallbacks(t *testing.T) {
	partitiontest.PartitionTest(t)
	netA, netB, _, closeFunc := setupWebsocketNetworkAB(t, 2)
	defer closeFunc()

	var counter atomic.Uint64
	require.NotZero(t, netA.NumPeers())

	// peerB is netA's representation of netB and vice versa
	peerB := netA.peers[0]
	peerA := netB.peers[0]

	// Need to create a channel so that TS messages sent by netA don't get filtered out in the readLoop
	peerA.makeResponseChannel(1)

	// The for loop simulates netA receiving 100 UE block requests from netB
	// and goes through the actual response code path to generate and send TS responses to netB
	for i := 0; i < 100; i++ {
		randInt := crypto.RandUint64()%(128) + 1
		counter.Add(randInt)
		topic := MakeTopic("val", []byte("blah"))
		callback := func() {
			counter.Add(^uint64(randInt - 1))
		}
		msg := IncomingMessage{Sender: peerB, Tag: protocol.UniEnsBlockReqTag}
		peerB.Respond(context.Background(), msg, OutgoingMessage{OnRelease: callback, Topics: Topics{topic}})
	}
	// Confirm that netB's representation netA peerB has received some requests and decremented the counter
	// of outstanding TS requests below 0. This will be true because we never made any UE block requests, we only
	// simulated them by manually creating a IncomingMessage with the UE tag in the loop above
	require.Eventually(t,
		func() bool { return peerA.outstandingTopicRequests.Load() < 0 },
		500*time.Millisecond,
		25*time.Millisecond,
	)

	// confirm that the test counter decrements down to zero correctly through callbacks
	require.Eventually(t,
		func() bool { return counter.Load() == uint64(0) },
		500*time.Millisecond,
		25*time.Millisecond,
	)
}

func TestSendMessageCallbackDrain(t *testing.T) {
	partitiontest.PartitionTest(t)

	node := makeTestWebsocketNode(t)
	destPeer := wsPeer{
		closing:            make(chan struct{}),
		sendBufferHighPrio: make(chan sendMessage, sendBufferLength),
		sendBufferBulk:     make(chan sendMessage, sendBufferLength),
		conn:               &nopConnSingleton,
	}
	node.addPeer(&destPeer)
	node.Start()
	defer node.Stop()

	var target, counter uint64
	// send messages to the peer that won't read them so they will sit in the sendQueue
	for i := 0; i < 10; i++ {
		randInt := crypto.RandUint64()%(128) + 1
		target += randInt
		topic := MakeTopic("val", []byte("blah"))
		callback := func() {
			counter += randInt
		}
		msg := IncomingMessage{Sender: node.peers[0], Tag: protocol.UniEnsBlockReqTag}
		destPeer.Respond(context.Background(), msg, OutgoingMessage{OnRelease: callback, Topics: Topics{topic}})
	}
	require.Len(t, destPeer.sendBufferBulk, 10)
	require.Zero(t, counter)
	require.Positive(t, target)
	// close the peer to trigger draining of the queue callbacks
	destPeer.Close(time.Now().Add(time.Second))

	require.Eventually(t,
		func() bool { return target == counter },
		2*time.Second,
		50*time.Millisecond,
	)
}

// TestWsNetworkPhonebookMix ensures p2p addresses are not added into wsNetwork via phonebook
func TestWsNetworkPhonebookMix(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	net, err := NewWebsocketNetwork(
		logging.TestingLog(t),
		config.GetDefaultLocal(),
		[]string{"127.0.0.1:1234", "/ip4/127.0.0.1/tcp/1234", "/ip4/127.0.0.1/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"},
		GenesisInfo{
			"test",
			"net",
		},
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)
	addrs := net.phonebook.GetAddresses(10, phonebook.RelayRole)
	require.Len(t, addrs, 1)
}

type testRecordingTransport struct {
	resultURL string
}

func (rt *testRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.resultURL = req.URL.String()
	return &http.Response{StatusCode: 200}, nil
}

func TestHTTPPAddressBoundTransport(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// first ensure url.URL.String() on path-only URLs works as expected
	var url = &url.URL{}
	url.Path = "/test"
	require.Equal(t, "/test", url.String())

	// now test some combinations of address and path
	const path = "/test/path"
	const expErr = "ERR"
	tests := []struct {
		addr     string
		expected string
	}{
		{"", expErr},
		{":", expErr},
		{"host:1234/lbr", expErr},
		{"host:1234", "http://host:1234" + path},
		{"http://host:1234", "http://host:1234" + path},
		{"http://host:1234/lbr", "http://host:1234/lbr" + path},
	}

	for _, test := range tests {
		recorder := testRecordingTransport{}
		tr := HTTPPAddressBoundTransport{
			Addr:           test.addr,
			InnerTransport: &recorder,
		}
		req, err := http.NewRequest("GET", path, nil)
		require.NoError(t, err)
		resp, err := tr.RoundTrip(req)
		if test.expected == expErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, 200, resp.StatusCode)
			require.Equal(t, test.expected, recorder.resultURL)
		}
	}
}

// TestWebsocketNetworkHTTPClient checks ws net HTTP client can connect to another node
// with out unexpected errors
func TestWebsocketNetworkHTTPClient(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	netA := makeTestWebsocketNode(t)
	err := netA.Start()
	require.NoError(t, err)
	defer netStop(t, netA, "A")

	netB := makeTestWebsocketNodeWithConfig(t, defaultConfig)

	addr, ok := netA.Address()
	require.True(t, ok)

	c, err := netB.GetHTTPClient(addr)
	require.NoError(t, err)

	netA.RegisterHTTPHandlerFunc("/handled", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	resp, err := c.Do(&http.Request{URL: &url.URL{Path: "/handled"}})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = c.Do(&http.Request{URL: &url.URL{Path: "/test"}})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode) // no such handler

	resp, err = c.Do(&http.Request{URL: &url.URL{Path: "/v1/" + genesisID + "/gossip"}})
	require.NoError(t, err)
	require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode) // not enough ws peer headers

	_, err = netB.GetHTTPClient("invalid")
	require.Error(t, err)
}

// TestPeerComparisonInBroadcast tests that the peer comparison in the broadcast function works as expected
// when casting wsPeer to Peer (interface{}) type.
func TestPeerComparisonInBroadcast(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	log := logging.TestingLog(t)
	conf := config.GetDefaultLocal()
	wn := &WebsocketNetwork{
		log:    log,
		config: conf,
		ctx:    context.Background(),
	}
	wn.setup()

	testPeer := &wsPeer{
		wsPeerCore:     makePeerCore(wn.ctx, wn, log, nil, "test-addr", nil, ""),
		sendBufferBulk: make(chan sendMessage, sendBufferLength),
	}
	exceptPeer := &wsPeer{
		wsPeerCore:     makePeerCore(wn.ctx, wn, log, nil, "except-addr", nil, ""),
		sendBufferBulk: make(chan sendMessage, sendBufferLength),
	}

	request := broadcastRequest{
		tag:         protocol.Tag("test-tag"),
		data:        []byte("test-data"),
		enqueueTime: time.Now(),
		except:      exceptPeer,
	}

	wn.broadcaster.innerBroadcast(request, false, []*wsPeer{testPeer, exceptPeer})

	require.Equal(t, 1, len(testPeer.sendBufferBulk))
	require.Equal(t, 0, len(exceptPeer.sendBufferBulk))
}

func TestMaybeSendMessagesOfInterestLegacyPeer(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	makePeer := func(wn *WebsocketNetwork, features peerFeatureFlag) (*wsPeer, chan sendMessage) {
		ch := make(chan sendMessage, 1)
		return &wsPeer{
			wsPeerCore:         makePeerCore(wn.ctx, wn, wn.log, nil, "test-addr", nil, ""),
			features:           features,
			sendBufferHighPrio: ch,
			sendBufferBulk:     make(chan sendMessage, 1),
			closing:            make(chan struct{}),
			processed:          make(chan struct{}, 1),
		}, ch
	}

	newTestNetwork := func(tags map[protocol.Tag]bool) *WebsocketNetwork {
		wn := &WebsocketNetwork{
			log: logging.TestingLog(t),
		}
		wn.ctx = context.Background()
		cloned := maps.Clone(tags)
		wn.messagesOfInterest = cloned
		wn.messagesOfInterestEnc = marshallMessageOfInterestMap(cloned)
		wn.messagesOfInterestGeneration.Store(1)
		return wn
	}

	t.Run("filters VP for peers without stateful support", func(t *testing.T) {
		wn := newTestNetwork(map[protocol.Tag]bool{
			protocol.AgreementVoteTag: true,
			protocol.VotePackedTag:    true,
		})

		peer, ch := makePeer(wn, pfCompressedProposal|pfCompressedVoteVpack)
		wn.maybeSendMessagesOfInterest(peer, nil)

		select {
		case msg := <-ch:
			require.Equal(t, protocol.MsgOfInterestTag, protocol.Tag(msg.data[:2]))

			decoded, err := unmarshallMessageOfInterest(msg.data[2:])
			require.NoError(t, err)

			require.Contains(t, decoded, protocol.AgreementVoteTag)
			require.True(t, decoded[protocol.AgreementVoteTag])
			_, hasVP := decoded[protocol.VotePackedTag]
			require.False(t, hasVP, "VP tag should be filtered for legacy peers")
		default:
			t.Fatal("expected MOI message for legacy peer")
		}
	})

	t.Run("retains VP for peers with stateful support", func(t *testing.T) {
		wn := newTestNetwork(map[protocol.Tag]bool{
			protocol.AgreementVoteTag: true,
			protocol.VotePackedTag:    true,
		})

		peer, ch := makePeer(wn, pfCompressedProposal|pfCompressedVoteVpack|pfCompressedVoteVpackStateful256)

		wn.maybeSendMessagesOfInterest(peer, nil)

		select {
		case msg := <-ch:
			require.Equal(t, protocol.MsgOfInterestTag, protocol.Tag(msg.data[:2]))

			decoded, err := unmarshallMessageOfInterest(msg.data[2:])
			require.NoError(t, err)

			require.Contains(t, decoded, protocol.AgreementVoteTag)
			require.True(t, decoded[protocol.AgreementVoteTag])
			require.Contains(t, decoded, protocol.VotePackedTag)
			require.True(t, decoded[protocol.VotePackedTag], "expected VP tag for peer with stateful support")
		default:
			t.Fatal("expected MOI message for stateful peer")
		}
	})

	t.Run("gracefully handles configuration without VP tag", func(t *testing.T) {
		wn := newTestNetwork(map[protocol.Tag]bool{
			protocol.AgreementVoteTag: true,
		})

		peer, ch := makePeer(wn, pfCompressedProposal|pfCompressedVoteVpack)
		wn.maybeSendMessagesOfInterest(peer, nil)

		select {
		case msg := <-ch:
			require.Equal(t, protocol.MsgOfInterestTag, protocol.Tag(msg.data[:2]))

			decoded, err := unmarshallMessageOfInterest(msg.data[2:])
			require.NoError(t, err)

			require.Contains(t, decoded, protocol.AgreementVoteTag)
			require.True(t, decoded[protocol.AgreementVoteTag])
			_, hasVP := decoded[protocol.VotePackedTag]
			require.False(t, hasVP)
		default:
			t.Fatal("expected MOI message when VP is absent from configuration")
		}
	})

	t.Run("skips sending when peer generation matches", func(t *testing.T) {
		wn := newTestNetwork(map[protocol.Tag]bool{
			protocol.AgreementVoteTag: true,
			protocol.VotePackedTag:    true,
		})

		peer, ch := makePeer(wn, pfCompressedProposal|pfCompressedVoteVpack)
		peer.messagesOfInterestGeneration.Store(wn.messagesOfInterestGeneration.Load())

		wn.maybeSendMessagesOfInterest(peer, nil)

		select {
		case <-ch:
			t.Fatal("did not expect MOI message when generations already match")
		default:
		}
	})
}
