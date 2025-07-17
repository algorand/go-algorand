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

	"github.com/libp2p/go-libp2p/p2p/discovery/backoff"
)

const meshThreadInterval = time.Minute

type meshStrategy interface {
	meshThread()
	start()
	stop()
}

type baseMeshStrategy struct {
	wg sync.WaitGroup
	meshConfig
}

type meshConfig struct {
	ctx                context.Context
	meshUpdateRequests chan meshRequest
	meshThreadInterval time.Duration
	backoff            backoff.BackoffStrategy
	netMesh            func() bool
	peerStatReport     func()
	closer             func()

	// wsnet and p2pnet are used in hybrid relay mode
	wsnet  *WebsocketNetwork
	p2pnet *P2PNetwork
}

type meshStrategyOption func(*meshConfig)

func withMeshExpJitterBackoff() meshStrategyOption {
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
func withMeshNetMesh(netMesh func() bool) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.netMesh = netMesh
	}
}
func withMeshPeerStatReport(peerStatReport func()) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.peerStatReport = peerStatReport
	}
}
func withMeshCloser(closer func()) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.closer = closer
	}
}

func withMeshUpdateRequest(ch chan meshRequest) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.meshUpdateRequests = ch
	}
}

func withMeshUpdateInterval(d time.Duration) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.meshThreadInterval = d
	}
}

func withContext(ctx context.Context) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.ctx = ctx
	}
}

func withWebsocketNetwork(wsnet *WebsocketNetwork) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.wsnet = wsnet
	}
}

func withP2PNetwork(p2pnet *P2PNetwork) meshStrategyOption {
	return func(cfg *meshConfig) {
		cfg.p2pnet = p2pnet
	}
}

func newBaseMeshStrategy(opts ...meshStrategyOption) (*baseMeshStrategy, error) {
	var cfg meshConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.ctx == nil {
		return nil, errors.New("context is not set")
	}
	if cfg.netMesh == nil {
		return nil, errors.New("mesh function is not set")
	}
	if cfg.meshUpdateRequests == nil {
		return nil, errors.New("mesh update requests channel is not set")
	}
	if cfg.meshThreadInterval == 0 {
		cfg.meshThreadInterval = meshThreadInterval
	}

	return &baseMeshStrategy{
		meshConfig: cfg,
	}, nil
}

func (m *baseMeshStrategy) meshThread() {
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

		hasPeers := m.netMesh()
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
		m.peerStatReport()
	}
}

func (m *baseMeshStrategy) start() {
	m.wg.Add(1)
	go m.meshThread()
}

func (m *baseMeshStrategy) stop() {
	m.wg.Wait()
	if m.closer != nil {
		m.closer()
	}
}

// MeshStrategyCreator is an interface for creating mesh strategies.
type MeshStrategyCreator interface {
	create(opts ...meshStrategyOption) (meshStrategy, error)
}

// BaseMeshStrategyCreator is a creator for the base mesh strategy used in our standard WS or P2P implementations:
// run a mesh thread that periodically checks for new peers.
type BaseMeshStrategyCreator struct {
}

func (c *BaseMeshStrategyCreator) create(opts ...meshStrategyOption) (meshStrategy, error) {
	return newBaseMeshStrategy(opts...)
}

// HybridRelayMeshStrategyCreator is a creator for the hybrid relay mesh strategy used in hybrid relays:
// always use wsnet nodes
type HybridRelayMeshStrategyCreator struct{}

func (c *HybridRelayMeshStrategyCreator) create(opts ...meshStrategyOption) (meshStrategy, error) {
	var cfg meshConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.wsnet == nil || cfg.p2pnet == nil {
		return nil, errors.New("both websocket and p2p networks must be provided")
	}

	out := make(chan meshRequest, 5)
	var wg sync.WaitGroup

	creator := BaseMeshStrategyCreator{}
	ctx := cfg.wsnet.ctx
	strategy, err := creator.create(
		withContext(ctx),
		withMeshNetMesh(cfg.wsnet.meshThreadInner),
		withMeshPeerStatReport(func() {
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

	return strategy, nil
}

type noopMeshStrategyCreator struct{}

func (c *noopMeshStrategyCreator) create(opts ...meshStrategyOption) (meshStrategy, error) {
	return &noopMeshStrategy{}, nil
}

type noopMeshStrategy struct{}

func (m *noopMeshStrategy) meshThread() {
}
func (m *noopMeshStrategy) start() {
}
func (m *noopMeshStrategy) stop() {
}
