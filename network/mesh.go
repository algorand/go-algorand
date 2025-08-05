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
	"math/rand"
	"sync"
	"time"

	"github.com/algorand/go-algorand/network/p2p"
	"github.com/libp2p/go-libp2p/p2p/discovery/backoff"
)

const meshThreadInterval = time.Minute

type mesher interface {
	start()
	stop()
}

type baseMesher struct {
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
	meshConfig
}

type meshConfig struct {
	parentCtx          context.Context
	meshUpdateRequests chan meshRequest
	meshThreadInterval time.Duration
	backoff            backoff.BackoffStrategy
	netMeshFn          func() bool
	peerStatReporter   func()
	closer             func()

	// wsnet and p2pnet are used in hybrid relay mode
	wsnet  *WebsocketNetwork
	p2pnet *P2PNetwork
}

type meshOption func(*meshConfig)

func withMeshExpJitterBackoff() meshOption {
	return func(cfg *meshConfig) {
		// Add exponential backoff with jitter to the mesh thread to handle new networks startup
		// when no DNS or DHT peers are available.
		// The parameters produce approximate the following delays (although they are random but the sequence give the idea):
		// 2 2.4 4.6 9 20 19.5 28 24 14 14 35 60 60
		ebf := backoff.NewExponentialDecorrelatedJitter(2*time.Second, meshThreadInterval, 3.0, rand.NewSource(rand.Int63()))
		eb := ebf()
		cfg.backoff = eb
	}
}
func withMeshNetMeshFn(netMeshFn func() bool) meshOption {
	return func(cfg *meshConfig) {
		cfg.netMeshFn = netMeshFn
	}
}
func withMeshPeerStatReporter(peerStatReporter func()) meshOption {
	return func(cfg *meshConfig) {
		cfg.peerStatReporter = peerStatReporter
	}
}
func withMeshCloser(closer func()) meshOption {
	return func(cfg *meshConfig) {
		cfg.closer = closer
	}
}

func withMeshUpdateRequest(ch chan meshRequest) meshOption {
	return func(cfg *meshConfig) {
		cfg.meshUpdateRequests = ch
	}
}

func withMeshUpdateInterval(d time.Duration) meshOption {
	return func(cfg *meshConfig) {
		cfg.meshThreadInterval = d
	}
}

func withContext(ctx context.Context) meshOption {
	return func(cfg *meshConfig) {
		cfg.parentCtx = ctx
	}
}

func withWebsocketNetwork(wsnet *WebsocketNetwork) meshOption {
	return func(cfg *meshConfig) {
		cfg.wsnet = wsnet
	}
}

func withP2PNetwork(p2pnet *P2PNetwork) meshOption {
	return func(cfg *meshConfig) {
		cfg.p2pnet = p2pnet
	}
}

func newBaseMesher(opts ...meshOption) (*baseMesher, error) {
	var cfg meshConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.parentCtx == nil {
		return nil, errors.New("context is not set")
	}
	if cfg.netMeshFn == nil {
		return nil, errors.New("mesh function is not set")
	}
	if cfg.meshUpdateRequests == nil {
		return nil, errors.New("mesh update requests channel is not set")
	}
	if cfg.meshThreadInterval == 0 {
		cfg.meshThreadInterval = meshThreadInterval
	}

	ctx, cancel := context.WithCancel(cfg.parentCtx)
	return &baseMesher{
		ctx:        ctx,
		cancel:     cancel,
		meshConfig: cfg,
	}, nil
}

func (m *baseMesher) meshThread() {
	defer m.wg.Done()

	timer := time.NewTicker(m.meshThreadInterval)
	defer timer.Stop()
	for {
		var request meshRequest
		select {
		case <-timer.C:
			request.done = nil
		case request = <-m.meshUpdateRequests:
		case <-m.ctx.Done():
			return
		}

		hasPeers := m.netMeshFn()
		if m.backoff != nil {
			if hasPeers {
				// found something, reset timer to the configured value
				timer.Reset(m.meshThreadInterval)
				m.backoff.Reset()
			} else {
				// no peers found, backoff
				timer.Reset(m.backoff.Delay())
			}
		}
		if request.done != nil {
			close(request.done)
		}

		// send the currently connected peers information to the
		// telemetry server; that would allow the telemetry server
		// to construct a cross-node map of all the nodes interconnections.
		m.peerStatReporter()
	}
}

func (m *baseMesher) start() {
	m.wg.Add(1)
	go m.meshThread()
}

func (m *baseMesher) stop() {
	m.cancel()
	m.wg.Wait()
	if m.closer != nil {
		m.closer()
	}
}

type networkConfig struct {
	pubsubOpts []p2p.PubSubOption // at the moment only pubsub configuration options only
}

// MeshCreator is an interface for creating mesh strategies.
type MeshCreator interface {
	create(opts ...meshOption) (mesher, error)
	makeConfig(wsnet *WebsocketNetwork, p2pnet *P2PNetwork) networkConfig
}

// baseMeshCreator is a creator for the base mesh strategy used in our standard WS or P2P implementations:
// run a mesh thread that periodically checks for new peers.
type baseMeshCreator struct{}

func (c baseMeshCreator) create(opts ...meshOption) (mesher, error) {
	return newBaseMesher(opts...)
}

func (c baseMeshCreator) makeConfig(wsnet *WebsocketNetwork, p2pnet *P2PNetwork) networkConfig {
	return networkConfig{}
}

// hybridRelayMeshCreator is a creator for the hybrid relay mesh strategy used in hybrid relays:
// always use wsnet nodes
type hybridRelayMeshCreator struct{}

func (c hybridRelayMeshCreator) create(opts ...meshOption) (mesher, error) {
	var cfg meshConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.wsnet == nil || cfg.p2pnet == nil {
		return nil, errors.New("both websocket and p2p networks must be provided")
	}

	out := make(chan meshRequest, 5)
	var wg sync.WaitGroup

	ctx := cfg.wsnet.ctx
	mesh, err := newBaseMesher(
		withContext(ctx),
		withMeshNetMeshFn(cfg.wsnet.meshThreadInner),
		withMeshPeerStatReporter(func() {
			cfg.p2pnet.peerStater.sendPeerConnectionsTelemetryStatus(cfg.wsnet)
			cfg.p2pnet.peerStater.sendPeerConnectionsTelemetryStatus(cfg.p2pnet)
		}),
		withMeshCloser(func() {
			wg.Wait()
			close(out)
		}),
		withMeshUpdateRequest(out),
		withMeshUpdateInterval(meshThreadInterval),
	)
	if err != nil {
		return nil, err
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			return
		case req := <-cfg.wsnet.meshUpdateRequests:
			out <- req
		}
	}()

	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			return
		case req := <-cfg.p2pnet.meshUpdateRequests:
			out <- req
		}
	}()

	return mesh, nil
}

func (c hybridRelayMeshCreator) makeConfig(wsnet *WebsocketNetwork, p2pnet *P2PNetwork) networkConfig {
	return networkConfig{}
}

type noopMeshCreator struct{}

func (c noopMeshCreator) create(opts ...meshOption) (mesher, error) {
	return &noopMesh{}, nil
}
func (c noopMeshCreator) makeConfig(wsnet *WebsocketNetwork, p2pnet *P2PNetwork) networkConfig {
	return networkConfig{}
}

type noopMesh struct{}

func (m *noopMesh) start() {}
func (m *noopMesh) stop()  {}

type noopMeshPubSubFilteredCreator struct{}

func (c noopMeshPubSubFilteredCreator) create(opts ...meshOption) (mesher, error) {
	return &noopMesh{}, nil
}
func (c noopMeshPubSubFilteredCreator) makeConfig(wsnet *WebsocketNetwork, p2pnet *P2PNetwork) networkConfig {
	return networkConfig{
		pubsubOpts: []p2p.PubSubOption{
			p2p.DisablePubSubPeerExchange(),
			p2p.SetPubSubPeerFilter(p2pnet.p2pRelayPeerFilter, p2pnet.pstore),
		},
	}
}
